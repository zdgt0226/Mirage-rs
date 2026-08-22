//! 加密 channel 建立 + v0.4 协议 TIME_SYNC 帧下发 + first_chunk 接收 +
//! 根据 first_chunk 内容分发到 TCP 或 UDP relay.
//!
//! 调用方: `handshake::handle_connection` 在 ClientHello 鉴权 + 63B tail 消费
//! 通过后进入这里. 不再退回 handshake — 这之后所有流量都是加密的.

use tokio::net::TcpStream;
use tracing::info;

use super::tcp_relay;
use super::udp_relay;

pub(super) async fn dispatch_authenticated(
    stream: TcpStream,
    password: String,
    client_random: [u8; 32],
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    ecdh: Option<[u8; 32]>,
) {
    // 3. Setup Crypto Stream。PFS 开时 (ecdh=Some) 走混入 ecdh 的 master 派生。
    // 客户端来源 IP (供 WebUI 服务端连接登记 / 域名排行的 inbound 维度)。
    let client_ip = stream.peer_addr().ok().map(|a| a.ip());
    let (read_half, write_half) = stream.into_split();
    let (mut reader, mut writer) = match ecdh {
        Some(ecdh) => crate::crypto::aead::create_crypto_pair_pfs(
            read_half,
            write_half,
            &password,
            &client_random,
            &ecdh,
            false, // is_initiator = false (Server)
        ),
        None => crate::crypto::aead::create_crypto_pair(
            read_half,
            write_half,
            &password,
            &client_random,
            false, // is_initiator = false (Server)
        ),
    };

    // 3.5 v0.4 协议: 通过加密 channel 主动下发服务器时间, 让客户端无需 NTP/HTTP 探测.
    //     帧格式: [0x01 type=TIME_SYNC][0x01 proto_ver][8B u64 BE server unix sec] = 10 字节
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        // unwrap_or_default: 服务端时钟 < epoch (嵌入式无 RTC 未同步 NTP) 不 panic
        // 崩溃, 回落 0. 见 time_sync::now_sec 注释.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut frame = [0u8; 10];
        frame[0] = 0x01; // type = TIME_SYNC
        // proto_ver: 开了 cipher_agility 才广播 0x02 (老客户端严格只认 0x01, 见 config 注释)。
        frame[1] = if crate::crypto::cipher::server_cipher_agility() {
            crate::crypto::cipher::PROTO_VER_AGILITY
        } else {
            crate::crypto::cipher::PROTO_VER_LEGACY
        };
        frame[2..10].copy_from_slice(&now.to_be_bytes());
        if let Err(e) = writer.send_data(&frame).await {
            tracing::error!("Mirage Server: failed to send TIME_SYNC frame: {:?}", e);
            return;
        }
    }

    // 4. Read first data chunk to determine TCP or UDP.
    //
    // 60s 是这条连接握手完成到收到 target_header 的最大空闲时间. 设这么长
    // 是为了配合客户端 WarmPool 的"预热长连"语义 — 客户端会持有空闲 tunnel
    // 60s 内随时复用, 不能让服务端这边过早 (旧版 5s) 把它们 reap 掉, 否则
    // pool 里全是"客户端以为活着、服务端已经关闭"的死 tunnel, 用户能复现
    // "无响应 / 5 分钟后 handler timeout" 的诡异行为.
    //
    // 配合客户端 Tunnel::max_age_sec 上限 50s (见 src/proxy/tunnel.rs), 留
    // 10s 余量, 保证 pool.get() 拿出来的 tunnel 在服务端这边一定还存活.
    //
    // DOS 防御: 这条 path 只在握手 (token 验证 + Poly1305 tag) 通过后才进
    // 入, 攻击者拿不到 password 就过不了, 不构成 unauth 资源放大.
    let first_chunk = match tokio::time::timeout(std::time::Duration::from_secs(60), reader.recv_data()).await {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => {
            // close_notify 是客户端主动优雅关闭 (warmup expire 时 pool sweeper 触发),
            // 不算错误. 其他 (crypto 解密失败 / 意外 EOF / 协议违反) 才算真错误.
            let msg = e.to_string();
            if msg.contains("close_notify") {
                tracing::debug!("Mirage Server: warmup gracefully closed by client");
            } else {
                // token 认证已过却解不开首个加密帧 = 会话密钥失配。给一次完整排查提示 (密码/时钟/
                // 高级特征单边), 而非裸 error 让运维无从下手。池化补货会反复撞到, 故只详细提示一次。
                static HINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !HINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(
                        "Mirage Server: first_chunk 解密失败 ({:?})。{}",
                        e,
                        crate::crypto::hello_auth::session_decrypt_failure_hint()
                    );
                } else {
                    tracing::debug!("Mirage Server: recv_data failed: {:?}", e);
                }
            }
            return;
        }
        Err(_) => {
            // 60s idle 后客户端仍没发数据 → 预期清理路径 (理论上不会触发, 因为
            // 客户端 sweeper 30-50s 内就会主动 close. 若真触发说明客户端 sweeper
            // 没跑或者大幅延迟, DEBUG 即可, 别刷 ERROR).
            tracing::debug!("Mirage Server: idle warmup reaped after 60s (client sweeper missed)");
            return;
        }
    };

    // cipher agility: 开关开 + 客户端首帧是 CIPHER_NEGO → 协商 AEAD, 回 CIPHER_ACK, 两端 rekey,
    // 再读**真**首帧 (target)。非 NEGO (老客户端发的真 target) → 原样, 维持 ChaCha20。
    let first_chunk = if crate::crypto::cipher::server_cipher_agility() {
        if let Some(client_aes) = crate::crypto::cipher::parse_cipher_nego(&first_chunk) {
            let final_cipher = crate::crypto::cipher::negotiate(
                client_aes,
                crate::crypto::cipher::local_supports_aes(),
            );
            let ack = crate::crypto::cipher::build_cipher_ack(final_cipher);
            if let Err(e) = writer.send_data(&ack).await {
                tracing::error!("Mirage Server: send CIPHER_ACK failed: {:?}", e);
                return;
            }
            writer.rekey(final_cipher);
            reader.rekey(final_cipher);
            tracing::debug!("Mirage Server: cipher agility 协商为 {:?}", final_cipher);
            // 读 rekey 后的真首帧
            match tokio::time::timeout(std::time::Duration::from_secs(60), reader.recv_data()).await {
                Ok(Ok(d)) => d,
                _ => return,
            }
        } else {
            first_chunk
        }
    } else {
        first_chunk
    };

    // 客户端版本识别 (两端 client_info 同开时): agility 之后这一帧可能是 CLIENT_INFO。读到即记
    // 客户端 IP → 版本, 再读**真**首帧 (target)。默认关 → 不读, 老客户端不发, 零兼容影响。
    let first_chunk = if crate::client_info::enabled() {
        if let Some(ver) = crate::client_info::parse_frame(&first_chunk) {
            if let Some(ip) = client_ip {
                crate::client_info::record_version(ip.to_string(), ver);
            }
            match tokio::time::timeout(std::time::Duration::from_secs(60), reader.recv_data()).await {
                Ok(Ok(d)) => d,
                _ => return,
            }
        } else {
            first_chunk
        }
    } else {
        first_chunk
    };

    info!("Mirage Server: Received first_chunk of len {}", first_chunk.len());

    if first_chunk.len() == 1 && first_chunk[0] == 0x00 {
        // UDP Mode.
        // 策略为 block 时直接拒绝, 让客户端立刻知道 UDP 不可用, 而不是静默走错出口。
        //
        // SS 上游默认如此: SS 的 UDP 未实现, 放行会让 UDP 从本机 IP 出去而 TCP 从上游出去 ——
        // 出口 IP 不一致, 对落地解锁是功能性错误 (QUIC 会"成功"但用错 IP, 不像被封那样回落 TCP)。
        // WG 上游**默认不走这里**: 隧道能承载 UDP, 出口与 TCP 一致, 默认策略是 tunnel。
        if upstream.as_ref().is_some_and(|u| u.block_udp()) {
            let up = upstream.as_ref().unwrap();
            tracing::warn!(
                "拒绝 UDP 中继: 上游 {} 的 udp 策略为 block。{}",
                up.describe(),
                match &**up {
                    crate::proxy::upstream::UpstreamOutlet::Shadowsocks(_) =>
                        "SS 的 UDP 未实现; 放行会让 UDP 从本机 IP 出去而与 TCP 出口不一致。\
                         确需旧行为请设 \"udp\": \"direct\"。",
                    crate::proxy::upstream::UpstreamOutlet::Wireguard(_) =>
                        "注意 WG 隧道本可承载 UDP (默认即 \"tunnel\", 与 TCP 同出口), \
                         这里是你显式设了 block。",
                }
            );
            let _ = writer.send_close_notify().await;
            return;
        }
        udp_relay::handle_udp_relay(reader, writer, upstream, client_ip).await;
    } else if first_chunk.len() == 1 && first_chunk[0] == crate::proxy::udp_mux::MUX_SENTINEL {
        // UDP MUX Mode: 一条隧道复用多条 UDP 流 (session-id)。block_udp 同样拒绝。
        if upstream.as_ref().is_some_and(|u| u.block_udp()) {
            tracing::warn!("拒绝 UDP mux 中继: 上游 udp 策略为 block");
            let _ = writer.send_close_notify().await;
            return;
        }
        udp_relay::handle_udp_mux_relay(reader, writer, upstream, client_ip).await;
    } else if first_chunk.len() >= 2 {
        // TCP Mode
        let target_len = u16::from_be_bytes([first_chunk[0], first_chunk[1]]) as usize;
        info!("Mirage Server: Parsed target_len = {}", target_len);

        if first_chunk.len() >= 2 + target_len {
            let target = match String::from_utf8(first_chunk[2..2+target_len].to_vec()) {
                Ok(t) => t,
                Err(_) => {
                    tracing::error!("Mirage Server: Target UTF-8 parsing failed!");
                    return;
                }
            };

            info!("Mirage Server: Target resolved to {}", target);

            // Check if there's any piggybacked payload after the target string
            let payload = if first_chunk.len() > 2 + target_len {
                Some(first_chunk[2+target_len..].to_vec())
            } else {
                None
            };

            tcp_relay::handle_tcp_relay(target, payload, reader, writer, upstream, client_ip).await;
        } else {
            tracing::error!("Mirage Server: first_chunk too short for target_len!");
        }
    } else {
        tracing::error!("Mirage Server: first_chunk too short to be valid!");
    }
}
