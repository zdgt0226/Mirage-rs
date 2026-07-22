//! 阶段4: 对着**真实 WireGuard 服务端**验证互通。
//!
//! 这是唯一能消掉"没证明能真连上"这个边界的测试 —— 此前所有单测只覆盖到握手包格式、
//! pump 机制、socket 生命周期与配置契约, 全部是**我方自洽**, 无法证明能和真实 WG 服务器
//! 通信 (与 SS2022 那条边界同性质)。
//!
//! 分三层, 逐层递进, 失败时一眼看出断在哪:
//!
//!   L1 WG 握手      —— 裸 boringtun + UDP。证明 Noise IK 握手、密钥派生、报文格式与真实
//!                      服务端互通。**这一层过了, 协议实现就是对的。**
//!   L2 TCP 经隧道   —— smoltcp + WgTcpStream。证明用户态 IP 栈产出的包能被服务端路由、
//!                      回包能被解密并交回 smoltcp。
//!   L3 UDP 经隧道   —— WgUdpSocket。
//!
//! L2/L3 都打同一个目标 (阿里公共 DNS 223.5.5.5:53) —— 它同时支持 DNS over TCP 与 UDP,
//! 且在国内可达, 一个目标验两条路。
//!
//! 用法 (私钥从文件读, 不写进源码也不进命令行历史):
//!   WG_PRIVATE_KEY_FILE=/path/to/key \
//!   WG_PEER_PUBLIC_KEY=... WG_ENDPOINT=host:port WG_ADDRESS=10.10.0.254 \
//!   cargo run --example verify_wg_real_peer
//!
//! 退出码: 0 = 全过; 非零 = 某层失败 (stderr 说明是哪层)。

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 目标: 阿里公共 DNS。TCP(53) 与 UDP(53) 都支持, 国内可达。
fn tcp_target() -> String {
    std::env::var("WG_TCP_TARGET").unwrap_or_else(|_| "223.5.5.5:53".into())
}
fn udp_target() -> String {
    std::env::var("WG_UDP_TARGET").unwrap_or_else(|_| "223.5.5.5:53".into())
}

/// 构造一个最小 DNS A 查询 (查 example.com)。
fn dns_query(id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes()); // ID
    q.extend_from_slice(&[0x01, 0x00]); // 标准查询, 期望递归
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    q
}

/// 一个像样的 DNS 响应: ID 对得上、QR 位是响应、且带至少一条回答。
fn dns_response_ok(resp: &[u8], id: u16) -> bool {
    resp.len() >= 12
        && resp[0..2] == id.to_be_bytes()
        && (resp[2] & 0x80) != 0
        && u16::from_be_bytes([resp[6], resp[7]]) > 0
}

fn env(k: &str) -> Result<String> {
    std::env::var(k).with_context(|| format!("缺少环境变量 {k}"))
}

fn load_config() -> Result<mirage_rs::proxy::wg::WgConfig> {
    use mirage_rs::proxy::wg::decode_wg_key;
    let key_file = env("WG_PRIVATE_KEY_FILE")?;
    let priv_b64 = std::fs::read_to_string(&key_file)
        .with_context(|| format!("读私钥文件 {key_file} 失败"))?;
    Ok(mirage_rs::proxy::wg::WgConfig {
        private_key: decode_wg_key(priv_b64.trim(), "private_key")?,
        peer_public_key: decode_wg_key(&env("WG_PEER_PUBLIC_KEY")?, "peer_public_key")?,
        preshared_key: match std::env::var("WG_PRESHARED_KEY") {
            Ok(k) if !k.trim().is_empty() => Some(decode_wg_key(&k, "preshared_key")?),
            _ => None,
        },
        endpoint: env("WG_ENDPOINT")?,
        address: env("WG_ADDRESS")?.parse().context("WG_ADDRESS 不是合法 IP")?,
        mtu: std::env::var("WG_MTU").ok().and_then(|s| s.parse().ok()).unwrap_or(1420),
        persistent_keepalive: Some(25),
    })
}

/// L1: 裸 boringtun + UDP, 只验 Noise 握手能不能和真实服务端走完。
///
/// 判据不是"收到了什么包", 而是**握手后 encapsulate 是否产出 DATA 包 (type=4)**:
/// 未建立会话时 boringtun 会再吐一个 handshake init (type=1), 两者一眼可分。
async fn layer1_handshake(cfg: &mirage_rs::proxy::wg::WgConfig) -> Result<()> {
    use boringtun::noise::TunnResult;

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(&cfg.endpoint)
        .await
        .with_context(|| format!("连不上 endpoint {}", cfg.endpoint))?;

    let mut tunn = mirage_rs::proxy::wg::build_tunn(cfg, 1);
    let mut out = vec![0u8; 2048];

    // 发握手 initiation
    let init = match tunn.encapsulate(&[], &mut out) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => bail!("未能产出握手包: {:?}", std::mem::discriminant(&other)),
    };
    if init.first() != Some(&1) {
        bail!("首包不是 handshake initiation (type=1)");
    }
    sock.send(&init).await?;
    eprintln!("  → 已发出 handshake initiation ({} 字节)", init.len());

    // 等 handshake response
    let mut rbuf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut rbuf))
        .await
        .context("10s 内没收到 handshake response —— 服务端没回。\
                  常见原因: 公钥没在服务端登记 / endpoint 或端口不对 / UDP 被拦")??;
    eprintln!("  ← 收到回包 {} 字节 (type={})", n, rbuf[0]);
    if rbuf[0] != 2 {
        bail!("回包不是 handshake response (期望 type=2, 实际 {})", rbuf[0]);
    }

    let mut dbuf = vec![0u8; 2048];
    match tunn.decapsulate(None, &rbuf[..n], &mut dbuf) {
        TunnResult::Err(e) => bail!("解握手应答失败: {e:?} —— 密钥不匹配的典型表现"),
        _ => {}
    }

    // 决定性判据: 会话建立后 encapsulate 应产出 DATA 包 (type=4), 而非又一个 init。
    let mut ebuf = vec![0u8; 2048];
    match tunn.encapsulate(b"probe", &mut ebuf) {
        TunnResult::WriteToNetwork(p) if p.first() == Some(&4) => {
            eprintln!("  ✓ 会话已建立 (encapsulate 产出 DATA 包 type=4)");
            Ok(())
        }
        TunnResult::WriteToNetwork(p) => {
            bail!("会话未建立: encapsulate 仍产出 type={} (应为 4)", p[0])
        }
        other => bail!("会话未建立: {:?}", std::mem::discriminant(&other)),
    }
}

/// 计算 16 位反码校验和 (IPv4 头 / UDP 伪头通用)。
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 手工拼一个 IPv4/UDP 包 (src → dst, 载荷 payload)。
fn build_udp_ip_packet(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut ip = vec![
        0x45, 0x00,
        (total_len >> 8) as u8, total_len as u8,
        0x00, 0x01,
        0x40, 0x00, // DF
        64,         // TTL
        17,         // UDP
        0x00, 0x00, // checksum 占位
    ];
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ck = checksum(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());

    let mut udp = Vec::new();
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum 占位
    udp.extend_from_slice(payload);

    // UDP 校验和: 伪头 + UDP 头 + 载荷
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let uck = checksum(&pseudo);
    udp[6..8].copy_from_slice(&if uck == 0 { 0xFFFFu16 } else { uck }.to_be_bytes());

    ip.extend_from_slice(&udp);
    ip
}

/// 拼一个 ICMP echo request 的 IPv4 包。
fn build_icmp_ping(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, id: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0]; // type=8 echo request, code=0, checksum 占位
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&1u16.to_be_bytes()); // seq
    icmp.extend_from_slice(b"mirage-wg-probe");
    let ck = checksum(&icmp);
    icmp[2..4].copy_from_slice(&ck.to_be_bytes());

    let total_len = 20 + icmp.len();
    let mut ip = vec![
        0x45, 0x00,
        (total_len >> 8) as u8, total_len as u8,
        0x00, 0x02, 0x40, 0x00, 64, 1, 0x00, 0x00,
    ];
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ck = checksum(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// L1.6: ping 服务端自己的隧道地址。把两种失败区分开:
///   有回应 → 服务端**收下并处理**了我的包 (AllowedIPs 没问题), 只是不给出网。
///   无回应 → 服务端大概率因 AllowedIPs 不含本端地址而直接丢弃。
async fn layer1_6_ping_gateway(
    cfg: &mirage_rs::proxy::wg::WgConfig,
    gw: std::net::Ipv4Addr,
) -> Result<()> {
    use boringtun::noise::TunnResult;

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(&cfg.endpoint).await?;
    let mut tunn = mirage_rs::proxy::wg::build_tunn(cfg, 3);
    let mut out = vec![0u8; 2048];
    if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&[], &mut out) {
        sock.send(&p.to_vec()).await?;
    }
    let mut rbuf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut rbuf))
        .await
        .context("等握手应答超时")??;
    let mut dbuf = vec![0u8; 2048];
    if let TunnResult::WriteToNetwork(p) = tunn.decapsulate(None, &rbuf[..n], &mut dbuf) {
        let v = p.to_vec();
        sock.send(&v).await?;
    }

    let src = match cfg.address {
        std::net::IpAddr::V4(v4) => v4,
        _ => bail!("只处理 IPv4"),
    };
    let pkt = build_icmp_ping(src, gw, 0x4242);
    eprintln!("  → ICMP echo {src} → {gw}");
    let mut ebuf = vec![0u8; 2048];
    if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&pkt, &mut ebuf) {
        sock.send(&p.to_vec()).await?;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            bail!("10s 内网关 {gw} 无 ICMP 回应");
        }
        let n = match tokio::time::timeout(left, sock.recv(&mut rbuf)).await {
            Ok(r) => r?,
            Err(_) => continue,
        };
        let mut d = vec![0u8; 2048];
        match tunn.decapsulate(None, &rbuf[..n], &mut d) {
            TunnResult::WriteToTunnelV4(ip, _) => {
                let ip = ip.to_vec();
                if ip.len() > 24 && ip[9] == 1 && ip[20] == 0 {
                    eprintln!("  ✓ 收到 ICMP echo reply —— 服务端收下并处理了我的包");
                    return Ok(());
                }
                eprintln!("  · 隧道内 IP 包 proto={} ({}B)", ip[9], ip.len());
            }
            TunnResult::WriteToNetwork(p) => {
                let v = p.to_vec();
                let _ = sock.send(&v).await;
            }
            _ => {}
        }
    }
}

/// L1.5: 握手后直接灌一个**手工拼的 IPv4/UDP 包**进隧道, 绕开 smoltcp。
///
/// 这一层是决定性的分诊断点:
///   - 通了 → 服务端确实为我们转发/NAT, 问题在我方 smoltcp/pump 层。
///   - 不通 → 服务端没给这个 peer 做出网转发 (AllowedIPs / NAT / ip_forward), 与我方代码无关。
async fn layer1_5_raw_ip(cfg: &mirage_rs::proxy::wg::WgConfig) -> Result<()> {
    use boringtun::noise::TunnResult;

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(&cfg.endpoint).await?;
    let mut tunn = mirage_rs::proxy::wg::build_tunn(cfg, 2);
    let mut out = vec![0u8; 2048];

    // 握手
    if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&[], &mut out) {
        sock.send(&p.to_vec()).await?;
    }
    let mut rbuf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut rbuf))
        .await
        .context("等 handshake response 超时")??;
    let mut dbuf = vec![0u8; 2048];
    // 握手应答可能带出待发包, 一并发出
    if let TunnResult::WriteToNetwork(p) = tunn.decapsulate(None, &rbuf[..n], &mut dbuf) {
        let v = p.to_vec();
        sock.send(&v).await?;
    }

    // 拼 IPv4/UDP: 隧道内本端地址 → 223.5.5.5:53, 载荷是 DNS 查询
    let src = match cfg.address {
        std::net::IpAddr::V4(v4) => v4,
        _ => bail!("本测试只处理 IPv4 隧道地址"),
    };
    let id = 0x9abcu16;
    let pkt = build_udp_ip_packet(src, "223.5.5.5".parse()?, 40000, 53, &dns_query(id));
    eprintln!("  → 灌入手工 IPv4/UDP 包 ({} 字节) {} → 223.5.5.5:53", pkt.len(), src);

    let mut ebuf = vec![0u8; 2048];
    match tunn.encapsulate(&pkt, &mut ebuf) {
        TunnResult::WriteToNetwork(p) => {
            sock.send(&p.to_vec()).await?;
        }
        other => bail!("加密数据包失败: {:?}", std::mem::discriminant(&other)),
    }

    // 等回包 (可能先来 keepalive, 循环直到拿到隧道内的 IP 包或超时)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            bail!(
                "12s 内没有任何隧道内回包 —— 服务端很可能没为本 peer 做出网转发 \
                 (检查服务端该 peer 的 AllowedIPs 是否含 {src}/32, 以及是否开了 \
                 ip_forward + MASQUERADE)"
            );
        }
        let n = match tokio::time::timeout(left, sock.recv(&mut rbuf)).await {
            Ok(r) => r?,
            Err(_) => continue,
        };
        let mut d = vec![0u8; 2048];
        match tunn.decapsulate(None, &rbuf[..n], &mut d) {
            TunnResult::WriteToTunnelV4(ip, _) => {
                let ip = ip.to_vec();
                // IPv4 头 20 字节 + UDP 头 8 字节后是 DNS 响应
                if ip.len() > 28 && ip[9] == 17 && dns_response_ok(&ip[28..], id) {
                    eprintln!("  ✓ 收到隧道内 DNS 响应 —— 服务端确实为本 peer 转发出网");
                    return Ok(());
                }
                eprintln!("  · 收到隧道内 IP 包 {} 字节 (proto={}), 继续等", ip.len(), ip[9]);
            }
            TunnResult::WriteToNetwork(p) => {
                let v = p.to_vec();
                let _ = sock.send(&v).await;
            }
            TunnResult::Err(e) => eprintln!("  · decapsulate: {e:?}"),
            _ => {}
        }
    }
}

/// L2: 经隧道建一条真 TCP 连接, 做一次 DNS over TCP 查询。
async fn layer2_tcp(tunnel: Arc<mirage_rs::proxy::wg::tunnel::WgTunnel>) -> Result<()> {
    let t = tcp_target();
    let addr: std::net::SocketAddr = t.parse()?;
    let mut s = tokio::time::timeout(
        Duration::from_secs(15),
        mirage_rs::proxy::wg::socket::WgTcpStream::connect(tunnel, addr),
    )
    .await
    .context("15s 内没能经隧道建立 TCP 连接")??;
    eprintln!("  ✓ TCP 已连通 {t}");

    // banner 模式: 只验"连上并能收到对端主动发来的字节", 用于目标不说 DNS 的场景
    // (如 SSH)。这足以证明 smoltcp 产出的包被真实 WG 服务端路由、回包也被正确解密送回。
    if std::env::var("WG_TCP_BANNER").is_ok() {
        let mut b = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(15), s.read(&mut b))
            .await
            .context("15s 内没读到 banner")??;
        if n == 0 {
            bail!("连上了但对端直接关闭, 没有数据");
        }
        eprintln!(
            "  ✓ 经隧道收到 {} 字节: {:?}",
            n,
            String::from_utf8_lossy(&b[..n.min(48)]).trim_end()
        );
        return Ok(());
    }

    // DNS over TCP: 2 字节长度前缀 + 报文
    let id = 0x1234u16;
    let q = dns_query(id);
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    s.write_all(&framed).await.context("写查询失败")?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(15), s.read_exact(&mut len_buf))
        .await
        .context("15s 内没读到响应长度")??;
    let rlen = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; rlen];
    tokio::time::timeout(Duration::from_secs(15), s.read_exact(&mut resp))
        .await
        .context("15s 内没读满响应体")??;

    if !dns_response_ok(&resp, id) {
        bail!("DNS over TCP 响应不合法 ({} 字节)", resp.len());
    }
    eprintln!("  ✓ DNS over TCP 往返成功 (响应 {} 字节, 含回答记录)", resp.len());
    Ok(())
}

/// L3: 经隧道发 UDP 数据报, 做一次 DNS 查询。
async fn layer3_udp(tunnel: Arc<mirage_rs::proxy::wg::tunnel::WgTunnel>) -> Result<()> {
    let t = udp_target();
    let addr: std::net::SocketAddr = t.parse()?;
    let sock = mirage_rs::proxy::wg::socket::WgUdpSocket::bind(tunnel)?;
    let id = 0x5678u16;
    sock.send_to(&dns_query(id), addr)?;

    let mut buf = vec![0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(15), sock.recv_from(&mut buf))
        .await
        .context("15s 内没收到 UDP 响应")??;
    if !dns_response_ok(&buf[..n], id) {
        bail!("DNS over UDP 响应不合法 ({n} 字节)");
    }
    eprintln!("  ✓ DNS over UDP 往返成功 (来自 {from}, {n} 字节, 含回答记录)");
    Ok(())
}

#[tokio::main]
async fn main() {
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("配置错误: {e:#}");
            std::process::exit(2);
        }
    };
    eprintln!(
        "目标 WG peer: {} | 隧道内本端地址: {} | MTU {}",
        cfg.endpoint, cfg.address, cfg.mtu
    );
    eprintln!(
        "本端公钥 (服务端 peer 列表里应有这一条): {}",
        {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(cfg.public_key())
        }
    );

    let mut failed = false;

    eprintln!("\n[L1] WireGuard 握手 (裸 boringtun + UDP)");
    if let Err(e) = layer1_handshake(&cfg).await {
        eprintln!("  ✗ L1 失败: {e:#}");
        eprintln!("\n结论: 协议层就没通, L2/L3 不必再试。");
        std::process::exit(1);
    }

    eprintln!("\n[L1.5] 裸 IP 包经隧道 (绕开 smoltcp, 分诊断服务端是否转发)");
    let server_forwards = match layer1_5_raw_ip(&cfg).await {
        Ok(()) => true,
        Err(e) => {
            eprintln!("  ✗ L1.5 失败: {e:#}");
            false
        }
    };

    if !server_forwards {
        // 分诊断: 服务端到底收没收下我的包
        let gw: std::net::Ipv4Addr = std::env::var("WG_GATEWAY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "10.10.0.1".parse().unwrap());
        eprintln!("\n[L1.6] ping 服务端隧道地址 {gw} (区分'没收下' vs '收下但不给出网')");
        match layer1_6_ping_gateway(&cfg, gw).await {
            Ok(()) => eprintln!(
                "  ⇒ 服务端收下了我的包 —— AllowedIPs 没问题, 缺的是**出网转发** \
                 (ip_forward / MASQUERADE)"
            ),
            Err(e) => eprintln!(
                "  ✗ {e:#}\n  ⇒ 服务端连隧道内的包都不回 —— 优先查该 peer 的 AllowedIPs \
                 是否含 {}/32", cfg.address
            ),
        }
    }

    // L1 用的是独立的 Tunn/socket; L2/L3 起一条真正的隧道。
    let tunnel = match mirage_rs::proxy::wg::tunnel::WgTunnel::connect(&cfg).await {
        Ok(t) => Arc::new(t),
        Err(e) => {
            eprintln!("建立隧道失败: {e:#}");
            std::process::exit(1);
        }
    };

    eprintln!("\n[L2] TCP 经隧道 (smoltcp + WgTcpStream) → {}", tcp_target());
    if let Err(e) = layer2_tcp(tunnel.clone()).await {
        eprintln!("  ✗ L2 失败: {e:#}");
        failed = true;
    }

    eprintln!("\n[L3] UDP 经隧道 (WgUdpSocket) → {}", udp_target());
    if let Err(e) = layer3_udp(tunnel.clone()).await {
        eprintln!("  ✗ L3 失败: {e:#}");
        failed = true;
    }

    eprintln!();
    if failed && !server_forwards {
        eprintln!(
            "✗ L2/L3 失败, 但 L1.5 (裸 IP 包) 同样不通 —— 病灶在**服务端不为本 peer 转发出网**, \
             不是本项目的 smoltcp/pump 层。协议实现 (L1 握手) 已证实与真实 WG 服务端互通。"
        );
        std::process::exit(1);
    }
    if failed {
        eprintln!("✗ 与真实 WG 服务端的互通验证**未全部通过** (见上面失败层)");
        std::process::exit(1);
    }
    eprintln!("✓ 与真实 WireGuard 服务端互通验证全部通过 (握手 + TCP + UDP)");
}
