//! 实机探测采集工具 —— 关闭时间 / 首字节时延分布。
//!
//! 服务 [`docs/real-machine-verification.md`] 的 **A1** (T2/T3 关闭时间对齐) 与 **A2**
//! (auth-succ vs auth-fail 首字节时延)。对每个 target 并发发起若干指定形态的探测, 逐条记录
//! 样本并输出 P50/P95/P99 —— 真机跑完直接比对, 无需手工掐表。
//!
//! 形态:
//! - `empty`    连上不发任何数据。真站按自身 idle 超时关闭; Mirage 应在静默窗口后转发真站。
//! - `partial`  只发真实 ClientHello 的前 N 字节就停 (半截)。
//! - `badauth`  发**完整** ClientHello 但 session_id 为随机 token (认证必失败 → 转发真站)。
//! - `authsucc` 发**完整合法** ClientHello (认证通过 → 模板回放)。与 badauth 走完全相同的
//!   首字节读取测量循环 (严格消除客户端协议栈多算的 Fake Tail/TIME_SYNC 往返)。
//!
//! 用法 (真机):
//! ```text
//! cargo run --release --example probe_close_timing -- \
//!   -t <真站>:443 -t <Mirage服务端>:443 --count 5 --sni www.example.com
//! ```

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const USAGE: &str = "\
用法: probe_close_timing -t <host:port> [-t <host:port> ...] [选项]
  -t, --target <host:port>  目标 (可多次)。约定: 第 1 个视作真站基线, 其余与其对比。
  -c, --count <N>           每个 target 每形态探测数 (默认 5)
      --modes <a,b,c>       形态子集, 默认 empty,partial,badauth (可选 authsucc)
      --password <pwd>      authsucc 认证密码 (默认空)
      --sni <host>          ClientHello 的 SNI (默认 www.apple.com; 对真站填它自己的域名更真实)
      --partial-len <N>     partial 形态发送的字节数 (默认 40)
      --gap-ms <N>          分段发送间隔毫秒 (默认 0; 用于弱网重传容错与 A3 临界间隙测试)
      --split-at <N>        分段切割字节数 (默认 40)
      --interleave          成对交替发起 (每轮 target 依次跑 badauth, authsucc 消除时段网络漂移)
      --first-byte-only     首字节到达后立即结束探测 (A2/分隙探测无需等待长达90s的真站空闲关闭)
      --cap <secs>          单个探测最长等待 (默认 90; 真站 idle 常 ~60s)
      --connect-timeout <s> TCP 建连超时 (默认 10)
  -h, --help";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Empty,
    Partial,
    BadAuth,
    AuthSucc,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Empty => "empty",
            Mode::Partial => "partial",
            Mode::BadAuth => "badauth",
            Mode::AuthSucc => "authsucc",
        }
    }
    fn parse(s: &str) -> Option<Mode> {
        match s.trim() {
            "empty" => Some(Mode::Empty),
            "partial" => Some(Mode::Partial),
            "badauth" | "bad-auth" => Some(Mode::BadAuth),
            "authsucc" | "auth-succ" | "succ" => Some(Mode::AuthSucc),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct Sample {
    /// TCP 建连耗时 (从发起连接到连接可写)。
    connect_ms: u64,
    /// 服务端首字节 (或 EOF) 距**发起连接**的耗时 (含建立段)。
    first_byte_ms: Option<u64>,
    close_ms: u64,
    closed_by_peer: bool,
    connect_ok: bool,
}

impl Sample {
    /// 首字节距**建连完成**的耗时 —— 纯首字节时延 (去掉 TCP 建连段)。
    fn first_byte_after_connect(&self) -> Option<u64> {
        self.first_byte_ms.map(|fb| fb.saturating_sub(self.connect_ms))
    }
}

/// 一次探测: 建连 → 按形态发送 → 读到 EOF/超时, 记录首字节与关闭时刻。
#[allow(clippy::too_many_arguments)] // 测试工具, 参数直白优于再包一层结构体
async fn probe_one(
    target: &str,
    mode: Mode,
    sni: &str,
    partial_len: usize,
    connect_timeout: Duration,
    cap: Duration,
    password: &str,
    gap_ms: u64,
    split_at: usize,
    first_byte_only: bool,
) -> Sample {
    let t0 = Instant::now();
    let mut s = match timeout(connect_timeout, TcpStream::connect(target)).await {
        Ok(Ok(s)) => s,
        _ => {
            let el = t0.elapsed().as_millis() as u64;
            return Sample {
                connect_ms: el,
                first_byte_ms: None,
                close_ms: el,
                closed_by_peer: false,
                connect_ok: false,
            };
        }
    };
    let connect_ms = t0.elapsed().as_millis() as u64;
    let _ = s.set_nodelay(true);

    match mode {
        Mode::Empty => {}
        Mode::Partial | Mode::BadAuth => {
            let mut sid = [0u8; 32];
            rand::fill(&mut sid);
            let (ch, _cr) = mirage_rs::crypto::tls_raw::build_client_hello(sni, &sid);
            let payload: &[u8] = if mode == Mode::Partial {
                &ch[..partial_len.min(ch.len())]
            } else {
                &ch
            };

            if gap_ms > 0 && payload.len() > split_at {
                if s.write_all(&payload[..split_at]).await.is_err() {
                    return Sample {
                        connect_ms,
                        first_byte_ms: None,
                        close_ms: t0.elapsed().as_millis() as u64,
                        closed_by_peer: false,
                        connect_ok: true,
                    };
                }
                tokio::time::sleep(Duration::from_millis(gap_ms)).await;
                if s.write_all(&payload[split_at..]).await.is_err() {
                    return Sample {
                        connect_ms,
                        first_byte_ms: None,
                        close_ms: t0.elapsed().as_millis() as u64,
                        closed_by_peer: false,
                        connect_ok: true,
                    };
                }
            } else if s.write_all(payload).await.is_err() {
                return Sample {
                    connect_ms,
                    first_byte_ms: None,
                    close_ms: t0.elapsed().as_millis() as u64,
                    closed_by_peer: false,
                    connect_ok: true,
                };
            }
        }
        Mode::AuthSucc => {
            let mut client_random = [0u8; 32];
            rand::fill(&mut client_random);
            let token = mirage_rs::crypto::hello_auth::make_session_token(password, &client_random);
            let hello = mirage_rs::crypto::tls_raw::build_client_hello_with_random(sni, &token, &client_random);

            if gap_ms > 0 && hello.len() > split_at {
                if s.write_all(&hello[..split_at]).await.is_err() {
                    return Sample {
                        connect_ms,
                        first_byte_ms: None,
                        close_ms: t0.elapsed().as_millis() as u64,
                        closed_by_peer: false,
                        connect_ok: true,
                    };
                }
                tokio::time::sleep(Duration::from_millis(gap_ms)).await;
                if s.write_all(&hello[split_at..]).await.is_err() {
                    return Sample {
                        connect_ms,
                        first_byte_ms: None,
                        close_ms: t0.elapsed().as_millis() as u64,
                        closed_by_peer: false,
                        connect_ok: true,
                    };
                }
            } else if s.write_all(&hello).await.is_err() {
                return Sample {
                    connect_ms,
                    first_byte_ms: None,
                    close_ms: t0.elapsed().as_millis() as u64,
                    closed_by_peer: false,
                    connect_ok: true,
                };
            }
        }
    }

    let mut first_byte_ms = None;
    let mut closed_by_peer = false;
    let mut buf = [0u8; 8192];
    loop {
        match timeout(cap, s.read(&mut buf)).await {
            Ok(Ok(0)) => {
                closed_by_peer = true; // 对端 FIN
                break;
            }
            Ok(Ok(_)) => {
                if first_byte_ms.is_none() {
                    first_byte_ms = Some(t0.elapsed().as_millis() as u64);
                }
                if first_byte_only {
                    break;
                }
            }
            Ok(Err(_)) => break, // RST / 错误
            Err(_) => break,     // cap 到 (本地放弃, 未收到 FIN)
        }
    }
    Sample {
        connect_ms,
        first_byte_ms,
        close_ms: t0.elapsed().as_millis() as u64,
        closed_by_peer,
        connect_ok: true,
    }
}

/// nearest-rank 百分位 (p ∈ 0..=100)。
fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

struct Args {
    targets: Vec<String>,
    modes: Vec<Mode>,
    count: usize,
    password: String,
    sni: String,
    partial_len: usize,
    gap_ms: u64,
    split_at: usize,
    interleave: bool,
    first_byte_only: bool,
    cap: Duration,
    connect_timeout: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        targets: Vec::new(),
        modes: vec![Mode::Empty, Mode::Partial, Mode::BadAuth],
        count: 5,
        password: std::env::var("MIRAGE_PROBE_PASSWORD").unwrap_or_default(),
        sni: "www.apple.com".to_string(),
        partial_len: 40,
        gap_ms: 0,
        split_at: 40,
        interleave: false,
        first_byte_only: false,
        cap: Duration::from_secs(90),
        connect_timeout: Duration::from_secs(10),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = |what: &str| it.next().ok_or_else(|| format!("{what} 缺参数值"));
        match arg.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "-t" | "--target" => a.targets.push(next("--target")?),
            "-c" | "--count" => {
                a.count = next("--count")?.parse().map_err(|_| "--count 需为正整数")?
            }
            "--modes" => {
                let v = next("--modes")?;
                let mut ms = Vec::new();
                for s in v.split(',') {
                    ms.push(Mode::parse(s).ok_or_else(|| format!("未知形态 `{s}` (empty/partial/badauth/authsucc)"))?);
                }
                if ms.is_empty() {
                    return Err("--modes 为空".into());
                }
                a.modes = ms;
            }
            "--password" => a.password = next("--password")?,
            "--sni" => a.sni = next("--sni")?,
            "--partial-len" => {
                a.partial_len = next("--partial-len")?.parse().map_err(|_| "--partial-len 需为正整数")?
            }
            "--gap-ms" => {
                a.gap_ms = next("--gap-ms")?.parse().map_err(|_| "--gap-ms 需为整数")?
            }
            "--split-at" => {
                a.split_at = next("--split-at")?.parse().map_err(|_| "--split-at 需为正整数")?
            }
            "--interleave" => a.interleave = true,
            "--first-byte-only" => a.first_byte_only = true,
            "--cap" => a.cap = Duration::from_secs(next("--cap")?.parse().map_err(|_| "--cap 需为秒数")?),
            "--connect-timeout" => {
                a.connect_timeout =
                    Duration::from_secs(next("--connect-timeout")?.parse().map_err(|_| "--connect-timeout 需为秒数")?)
            }
            other => return Err(format!("未知参数 `{other}`")),
        }
    }
    if a.targets.is_empty() {
        return Err("至少需要一个 -t/--target".into());
    }
    if a.count == 0 {
        return Err("--count 不能为 0".into());
    }
    Ok(a)
}

fn print_stats(label: &str, samples: &[u64]) {
    let mut v = samples.to_vec();
    v.sort_unstable();
    if v.is_empty() {
        println!("  {label}: n=0");
        return;
    }
    println!(
        "  {label}: n={} min={} p50={} p95={} p99={} max={}",
        v.len(),
        v[0],
        pct(&v, 50.0),
        pct(&v, 95.0),
        pct(&v, 99.0),
        v[v.len() - 1]
    );
    println!("    samples: {}", v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" "));
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("✗ {e}\n");
            }
            eprintln!("{USAGE}");
            std::process::exit(if e.is_empty() { 0 } else { 2 });
        }
    };

    // results[target_idx][mode_idx] = samples
    let mut results: Vec<Vec<Vec<Sample>>> = (0..args.targets.len())
        .map(|_| (0..args.modes.len()).map(|_| Vec::new()).collect())
        .collect();

    if args.interleave {
        // 成对交替发起: 按轮推进, 每轮对每个 target 依次发起各 mode, 消除长时程网络抖动漂移
        for _ in 0..args.count {
            for (ti, t) in args.targets.iter().enumerate() {
                for (mi, mode) in args.modes.iter().enumerate() {
                    let s = probe_one(
                        t,
                        *mode,
                        &args.sni,
                        args.partial_len,
                        args.connect_timeout,
                        args.cap,
                        &args.password,
                        args.gap_ms,
                        args.split_at,
                        args.first_byte_only,
                    )
                    .await;
                    results[ti][mi].push(s);
                }
            }
        }
    } else {
        // 模式并发推进
        for (mi, mode) in args.modes.iter().enumerate() {
            let mut set = tokio::task::JoinSet::new();
            let mut remaining: Vec<usize> = vec![args.count; args.targets.len()];
            loop {
                let mut launched = false;
                for (ti, t) in args.targets.iter().enumerate() {
                    if remaining[ti] > 0 {
                        remaining[ti] -= 1;
                        launched = true;
                        let (t, m, sni, pwd) = (t.clone(), *mode, args.sni.clone(), args.password.clone());
                        let (pl, cap, ct, gap, split, fb_only) = (
                            args.partial_len,
                            args.cap,
                            args.connect_timeout,
                            args.gap_ms,
                            args.split_at,
                            args.first_byte_only,
                        );
                        set.spawn(async move {
                            (ti, probe_one(&t, m, &sni, pl, ct, cap, &pwd, gap, split, fb_only).await)
                        });
                    }
                }
                if !launched {
                    break;
                }
            }
            while let Some(res) = set.join_next().await {
                if let Ok((ti, s)) = res {
                    results[ti][mi].push(s);
                }
            }
        }
    }

    // ── 逐 target × 形态 输出 ──
    for (ti, target) in args.targets.iter().enumerate() {
        for (mi, mode) in args.modes.iter().enumerate() {
            let ss = &results[ti][mi];
            let conn_ok = ss.iter().filter(|s| s.connect_ok).count();
            let closed = ss.iter().filter(|s| s.closed_by_peer).count();
            println!("=== target={target} mode={} ===", mode.label());
            println!("  connect_ok={conn_ok}/{}  closed_by_peer={closed}/{}", ss.len(), ss.len());
            let conn: Vec<u64> = ss.iter().map(|s| s.connect_ms).collect();
            print_stats("connect_ms", &conn);
            let fb: Vec<u64> = ss.iter().filter_map(|s| s.first_byte_after_connect()).collect();
            print_stats("first_byte_after_connect_ms", &fb);
            let cl: Vec<u64> = ss.iter().map(|s| s.close_ms).collect();
            print_stats("close_ms", &cl);
        }

        // ── 成对配对统计 (当同时包含 badauth 和 authsucc 时) ──
        let bad_idx = args.modes.iter().position(|m| *m == Mode::BadAuth);
        let succ_idx = args.modes.iter().position(|m| *m == Mode::AuthSucc);
        if let (Some(bi), Some(si)) = (bad_idx, succ_idx) {
            let bad_samples = &results[ti][bi];
            let succ_samples = &results[ti][si];
            let mut deltas: Vec<i64> = Vec::new();
            for (b, s) in bad_samples.iter().zip(succ_samples.iter()) {
                if let (Some(fb_b), Some(fb_s)) = (b.first_byte_after_connect(), s.first_byte_after_connect()) {
                    deltas.push(fb_s as i64 - fb_b as i64);
                }
            }
            if !deltas.is_empty() {
                let n = deltas.len() as f64;
                let mean = deltas.iter().sum::<i64>() as f64 / n;
                let var = if deltas.len() > 1 {
                    deltas.iter().map(|&d| (d as f64 - mean).powi(2)).sum::<f64>() / (n - 1.0)
                } else {
                    0.0
                };
                let stddev = var.sqrt();
                let sem = stddev / n.sqrt();
                let ci_low = mean - 1.96 * sem;
                let ci_high = mean + 1.96 * sem;
                println!("\n>>> target={target} 严格同口径首字节成对差 (authsucc - badauth) <<<");
                println!("  n={} 均值差={:.1}ms 标准差={:.1}ms 95%置信区间=[{:.1}ms, {:.1}ms]", deltas.len(), mean, stddev, ci_low, ci_high);
                println!("  配对样本: {}", deltas.iter().map(|d| format!("{d:+}")).collect::<Vec<_>>().join(" "));
            }
        }
    }

    // ── 对比 (target[0] 视作真站基线) ──
    if args.targets.len() >= 2 {
        println!("\n=== 对比 (第 2..n 个 target 相对第 1 个 `{}`, 单位 ms) ===", args.targets[0]);
        println!("判据 (A1): empty/partial 的 |Δp50| ≤ 1000~2000, 且 Δ 为**负**(提前)即为回归信号");
        for (mi, mode) in args.modes.iter().enumerate() {
            let base: Vec<u64> = results[0][mi].iter().map(|s| s.close_ms).collect();
            let mut base_s = base.clone();
            base_s.sort_unstable();
            let base_p50 = pct(&base_s, 50.0);
            for (target, res) in args.targets.iter().zip(results.iter()).skip(1) {
                let mut v: Vec<u64> = res[mi].iter().map(|s| s.close_ms).collect();
                v.sort_unstable();
                let p50 = pct(&v, 50.0);
                println!(
                    "  mode={:<8} {} p50={}  vs {} p50={}  Δ={:+}",
                    mode.label(),
                    args.targets[0],
                    base_p50,
                    target,
                    p50,
                    p50 as i64 - base_p50 as i64
                );
            }
        }
    }
}
