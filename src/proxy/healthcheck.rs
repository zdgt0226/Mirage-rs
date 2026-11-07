use crate::proxy::outbound::OutboundNode;
use std::sync::Weak;
use tokio::time::{sleep, Duration, Instant, timeout};
use tracing::{debug, info};

/// 探测成功后的记录结果 (供日志区分)。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    Normal,
    /// 补测轮, 相对基线确认变慢, 已设延迟下限。
    ConfirmedSlow { baseline: u64 },
    /// 补测轮, 未确认变慢 (真实变慢多半是目标慢)。
    NotConfirmed { baseline: u64 },
    /// 普通轮, 延迟恢复正常, 提前解除变慢下限。
    FloorCleared,
}

/// 探测成功拿到 rtt 后记录。补测轮取出 probe_baseline 比对, 确认变慢设下限;
/// 普通轮照常记样本, 并在恢复正常时解除下限。
pub(crate) fn record_probe_success(
    stats: &mut crate::proxy::pool::PoolStats,
    rtt: u64,
    is_probe_round: bool,
    now: Instant,
) -> ProbeOutcome {
    if is_probe_round {
        if let Some(baseline) = stats.probe_baseline.take() {
            if crate::proxy::pool::is_slow_ttfb(rtt, Some(baseline)) == Some(true) {
                stats.confirm_slow_at(rtt, baseline, now);
                return ProbeOutcome::ConfirmedSlow { baseline };
            }
            stats.record_latency(rtt);
            return ProbeOutcome::NotConfirmed { baseline };
        }
    }
    stats.record_latency(rtt);
    if stats.maybe_clear_slow_floor_at(rtt, now) {
        return ProbeOutcome::FloorCleared;
    }
    ProbeOutcome::Normal
}

/// 探测失败记录。补测轮结束清掉 probe_baseline。
pub(crate) fn record_probe_failure(
    stats: &mut crate::proxy::pool::PoolStats,
    is_probe_round: bool,
) {
    stats.record_failure();
    if is_probe_round {
        stats.probe_baseline = None;
    }
}

fn handle_probe_result(
    stats: &std::sync::Arc<std::sync::RwLock<crate::proxy::pool::PoolStats>>,
    tag: &str,
    result: Result<u64, &'static str>,
    is_probe_round: bool,
) {
    let mut stats = stats.write().unwrap_or_else(|e| e.into_inner());
    match result {
        Ok(rtt) => match record_probe_success(&mut stats, rtt, is_probe_round, Instant::now()) {
            ProbeOutcome::ConfirmedSlow { baseline } => info!(
                "Node {} re-probe confirmed slower ({}ms, was {}ms), urltest will route with this latency for {}s",
                tag,
                rtt,
                baseline,
                crate::proxy::pool::SLOW_FLOOR_DURATION.as_secs()
            ),
            ProbeOutcome::NotConfirmed { baseline } => debug!(
                "HealthCheck [{}] ok: {}ms (re-probe did not confirm slowdown, was {}ms, real slowdown likely at target)",
                tag, rtt, baseline
            ),
            ProbeOutcome::FloorCleared => info!("Node {} latency recovered to normal ({}ms), cleared slow mark", tag, rtt),
            ProbeOutcome::Normal => debug!("HealthCheck [{}] ok: {}ms", tag, rtt),
        },
        Err(reason) => {
            record_probe_failure(&mut stats, is_probe_round);
            if !reason.is_empty() {
                debug!("HealthCheck [{}] failed ({})", tag, reason);
            }
        }
    }
}

/// 恢复探测时的短间隔 (2s)
pub const RESUME_PROBE_INTERVAL: Duration = Duration::from_secs(2);
pub const MAX_RESUME_PROBE_ROUNDS: u32 = 3;

/// 计算下一次探测的等待时长与剩余快探轮数。
/// 当从暂停恢复 (remaining_rounds > 0) 且健康状态未"确定" (failures < DEAD_AFTER_FAILURES 且 successes < RECOVER_AFTER_SUCCESSES) 时，
/// 改用 2s 短间隔快探，消耗 1 轮；否则回到正常 interval 且剩余轮数清零。
pub fn next_probe_delay(
    failures: u32,
    successes: u32,
    remaining_rounds: u32,
    normal_interval: Duration,
) -> (Duration, u32) {
    if remaining_rounds > 0
        && failures < crate::proxy::pool::DEAD_AFTER_FAILURES
        && successes < crate::proxy::pool::RECOVER_AFTER_SUCCESSES
    {
        (RESUME_PROBE_INTERVAL, remaining_rounds - 1)
    } else {
        (normal_interval, 0)
    }
}

pub fn start_health_checker(node: Weak<OutboundNode>, url: String, interval: u64) {
    if interval == 0 {
        return;
    }

    tokio::spawn(async move {
        // Wait a bit before starting the first check to avoid thundering herd
        sleep(Duration::from_secs(2)).await;

        let mut is_probe_round = false;
        let mut paused = false;
        let mut resume_fast_rounds: u32 = 0;
        loop {
            let Some(node) = node.upgrade() else {
                break;
            };
            if let OutboundNode::Mirage { pool, tag, .. } = &*node {
                if pool.is_idle() {
                    if !paused {
                        debug!(
                            "HealthCheck [{}] group idle for {}s, pausing probes",
                            tag,
                            crate::proxy::pool::GROUP_IDLE_PAUSE.as_secs()
                        );
                        paused = true;
                    }
                    let notify = pool.probe_notify();
                    drop(node);
                    tokio::select! {
                        _ = sleep(Duration::from_secs(interval)) => {
                            is_probe_round = false;
                        }
                        _ = notify.notified() => {
                            is_probe_round = true;
                        }
                    }
                    continue;
                }

                if paused {
                    debug!("HealthCheck [{}] traffic detected, resuming probes", tag);
                    paused = false;
                    resume_fast_rounds = MAX_RESUME_PROBE_ROUNDS;
                }

                let start = Instant::now();
                
                // Parse target from url
                let target = if url.contains("cloudflare.com") {
                    "cp.cloudflare.com:80"
                } else if url.contains("firefox.com") {
                    "detectportal.firefox.com:80"
                } else {
                    "www.gstatic.com:80" // default
                };

                let path = if url.contains("cloudflare.com") || url.contains("gstatic.com") {
                    "/generate_204"
                } else {
                    "/success.txt"
                };

                #[cfg(feature = "quic")]
                if pool.is_quic() {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let quic_res = timeout(Duration::from_secs(5), async {
                        pool.open_quic_lean(target).await
                    }).await;

                    if let Ok(Ok(mut stream)) = quic_res {
                        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, target.split(':').next().unwrap_or(""));
                        if stream.write_all(req.as_bytes()).await.is_ok() {
                            let mut buf = [0u8; 1024];
                            if let Ok(Ok(n)) = timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                                let resp = String::from_utf8_lossy(&buf[..n]);
                                if resp.contains("HTTP/1.1 204") || resp.contains("HTTP/1.1 200") {
                                    let rtt = start.elapsed().as_millis() as u64;
                                    handle_probe_result(&pool.stats, tag, Ok(rtt), is_probe_round);
                                } else {
                                    handle_probe_result(&pool.stats, tag, Err("bad status"), is_probe_round);
                                }
                            } else {
                                handle_probe_result(&pool.stats, tag, Err("recv timeout/err"), is_probe_round);
                            }
                        } else {
                            handle_probe_result(&pool.stats, tag, Err(""), is_probe_round);
                        }
                    } else {
                        handle_probe_result(&pool.stats, tag, Err("quic stream open timeout/err"), is_probe_round);
                    }
                    let delay = {
                        let s = pool.stats.read().unwrap_or_else(|e| e.into_inner());
                        let (d, rem) = next_probe_delay(
                            s.consecutive_failures,
                            s.consecutive_successes,
                            resume_fast_rounds,
                            Duration::from_secs(interval),
                        );
                        resume_fast_rounds = rem;
                        d
                    };
                    let notify = pool.probe_notify();
                    drop(node);
                    tokio::select! {
                        _ = sleep(delay) => {
                            is_probe_round = false;
                        }
                        _ = notify.notified() => {
                            is_probe_round = true;
                        }
                    }
                    continue;
                }

                // Acquire a tunnel. pool.get 自身有 10s timeout, healthcheck 再加 5s
                // 上限避免单次 probe 阻塞太久. 双重 Result: 外层 timeout / 内层 pool 错.
                let tunnel_res = timeout(Duration::from_secs(5), async {
                    pool.get().await
                }).await;

                if let Ok(Ok(mut tunnel)) = tunnel_res {
                    // Send connection target header
                    let target_bytes = target.as_bytes();
                    let mut target_header = Vec::with_capacity(2 + target_bytes.len());
                    target_header.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
                    target_header.extend_from_slice(target_bytes);
                    
                    if tunnel.writer.send_data(&target_header).await.is_ok() {
                        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, target.split(':').next().unwrap_or(""));
                        if tunnel.writer.send_data(req.as_bytes()).await.is_ok() {
                            let _buf = [0u8; 1024];
                            if let Ok(Ok(data)) = timeout(Duration::from_secs(5), tunnel.reader.recv_data()).await {
                                let resp = String::from_utf8_lossy(&data);
                                if resp.contains("HTTP/1.1 204") || resp.contains("HTTP/1.1 200") {
                                    let rtt = start.elapsed().as_millis() as u64;
                                    handle_probe_result(&pool.stats, tag, Ok(rtt), is_probe_round);
                                } else {
                                    handle_probe_result(&pool.stats, tag, Err("bad status"), is_probe_round);
                                }
                                // 正常结束发 close_notify (rtt 已记), 否则服务端按截断 RST 上游。
                                let _ = tunnel.writer.send_close_notify().await;
                            } else {
                                handle_probe_result(&pool.stats, tag, Err("recv timeout/err"), is_probe_round);
                            }
                        } else {
                            handle_probe_result(&pool.stats, tag, Err(""), is_probe_round);
                        }
                    } else {
                        handle_probe_result(&pool.stats, tag, Err(""), is_probe_round);
                    }
                } else {
                    handle_probe_result(&pool.stats, tag, Err("pool get timeout/err"), is_probe_round);
                }
                let delay = {
                    let s = pool.stats.read().unwrap_or_else(|e| e.into_inner());
                    let (d, rem) = next_probe_delay(
                        s.consecutive_failures,
                        s.consecutive_successes,
                        resume_fast_rounds,
                        Duration::from_secs(interval),
                    );
                    resume_fast_rounds = rem;
                    d
                };
                let notify = pool.probe_notify();
                drop(node);
                tokio::select! {
                    _ = sleep(delay) => {
                        is_probe_round = false;
                    }
                    _ = notify.notified() => {
                        is_probe_round = true;
                    }
                }
                continue;
            }
            drop(node);
            sleep(Duration::from_secs(interval)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::pool::PoolStats;

    #[test]
    fn probe_round_confirms_slow_sets_floor() {
        let mut stats = PoolStats::new();
        stats.record_latency(100);
        stats.probe_baseline = Some(100);
        let now = Instant::now();
        assert_eq!(record_probe_success(&mut stats, 2000, true, now), ProbeOutcome::ConfirmedSlow { baseline: 100 });
        assert_eq!(stats.probe_baseline, None);
        // 之后暖池快样本拉不回选路延迟
        for _ in 0..9 {
            stats.record_latency(100);
        }
        assert_eq!(stats.latency_ms_at(now), Some(2000));
    }

    #[test]
    fn probe_round_not_confirmed_keeps_samples() {
        let mut stats = PoolStats::new();
        stats.record_latency(100);
        stats.probe_baseline = Some(100);
        let now = Instant::now();
        assert_eq!(record_probe_success(&mut stats, 150, true, now), ProbeOutcome::NotConfirmed { baseline: 100 });
        assert_eq!(stats.slow_floor, None);
        assert_eq!(stats.latency_samples.len(), 2);
        assert_eq!(stats.probe_baseline, None);
    }

    #[test]
    fn normal_round_ignores_baseline_and_clears_floor_on_recovery() {
        let mut stats = PoolStats::new();
        stats.record_latency(100);
        stats.probe_baseline = Some(100);
        let now = Instant::now();
        // 普通轮不消费 probe_baseline
        assert_eq!(record_probe_success(&mut stats, 2000, false, now), ProbeOutcome::Normal);
        assert_eq!(stats.probe_baseline, Some(100));

        stats.confirm_slow_at(2000, 100, now);
        // 普通轮仍慢: 下限保留
        assert_eq!(record_probe_success(&mut stats, 1800, false, now), ProbeOutcome::Normal);
        assert!(stats.slow_floor.is_some());
        // 普通轮恢复: 解除
        assert_eq!(record_probe_success(&mut stats, 120, false, now), ProbeOutcome::FloorCleared);
        assert_eq!(stats.slow_floor, None);
    }

    #[test]
    fn probe_failure_clears_baseline_in_probe_round() {
        let mut stats = PoolStats::new();
        stats.probe_baseline = Some(100);
        record_probe_failure(&mut stats, false);
        assert_eq!(stats.probe_baseline, Some(100));
        record_probe_failure(&mut stats, true);
        assert_eq!(stats.consecutive_failures, 2);
        assert_eq!(stats.probe_baseline, None);
    }

    #[test]
    fn test_next_probe_delay_from_resume() {
        let normal = Duration::from_secs(60);

        // 恢复后初始 rounds = 3，状态未确定 (failures=1, successes=0) -> 2s 快探，剩余 2 轮
        let (d, rem) = next_probe_delay(1, 0, 3, normal);
        assert_eq!(d, RESUME_PROBE_INTERVAL);
        assert_eq!(rem, 2);

        // 第 2 次仍未确定 (failures=2, successes=0) -> 2s 快探，剩余 1 轮
        let (d, rem) = next_probe_delay(2, 0, 2, normal);
        assert_eq!(d, RESUME_PROBE_INTERVAL);
        assert_eq!(rem, 1);

        // 连续失败达 DEAD_AFTER_FAILURES (3) -> 状态确定 (dead)，恢复正常 60s
        let (d, rem) = next_probe_delay(3, 0, 1, normal);
        assert_eq!(d, normal);
        assert_eq!(rem, 0);

        // 若成功达 RECOVER_AFTER_SUCCESSES (2) -> 状态确定 (healthy)，恢复正常 60s
        let (d, rem) = next_probe_delay(0, 2, 2, normal);
        assert_eq!(d, normal);
        assert_eq!(rem, 0);

        // 若达到最大轮数 (3轮用尽 rem=0) 但未达到确定阈值 -> 恢复正常 60s
        let (d, rem) = next_probe_delay(1, 1, 0, normal);
        assert_eq!(d, normal);
        assert_eq!(rem, 0);
    }
}
