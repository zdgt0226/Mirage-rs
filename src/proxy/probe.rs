//! 节点可用性探测: 对一个 mirage 出站做一次**完整握手 + 认证验证**, 报 RTT。
//!
//! 为什么不是裸 TCP connect: mirage 的伪装前置是真站点, `:443` 本来就通, 连上 ≠ 节点
//! 能用。真正的可用 = 完成 TLS 伪装握手后, 用密码派生的会话密钥**成功解开**服务端下发的
//! 首帧 (TIME_SYNC)。认证没过时服务端会把连接转发给伪装站, 我们用会话密钥去解伪装站的
//! 真 TLS 流量必然失败 —— 这正是"密码不符 / 非 Mirage 服务端"的确定信号。
//!
//! 复用客户端握手原语 (pool::connect_upstream 的同一套), 但判定更严: 必须解密成功。

use std::time::{Duration, Instant};

use anyhow::anyhow;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 探测结果。RTT 单位毫秒。
pub enum ProbeOutcome {
    /// 握手 + 认证均通过。tcp_ms = TCP 建连往返; handshake_ms = 建连后到认证确认的往返。
    Ok { tcp_ms: u64, handshake_ms: u64 },
    /// TCP + TLS 伪装握手可达, 但没收到可解密的首帧确认认证 (旧服务端不下发 TIME_SYNC?)。
    /// 可达但认证未确认 —— 不算失败, 也不能保证密码正确。
    Unconfirmed { tcp_ms: u64, note: String },
    /// 不可用。原因: 连接失败/超时、握手失败、认证解密失败等。
    Fail(String),
}

/// 对一个 mirage 节点做一次探测。永不返回 Err —— 所有错误折叠进 `ProbeOutcome::Fail`,
/// 便于调用方 (CLI / import --test) 直接按结果分支。
pub async fn probe_mirage(
    server: &str,
    port: u16,
    password: &str,
    camouflage_host: &str,
    timeout_secs: u64,
) -> ProbeOutcome {
    match probe_inner(server, port, password, camouflage_host, timeout_secs).await {
        Ok(o) => o,
        Err(e) => ProbeOutcome::Fail(e.to_string()),
    }
}

async fn probe_inner(
    server: &str,
    port: u16,
    password: &str,
    camouflage_host: &str,
    timeout_secs: u64,
) -> anyhow::Result<ProbeOutcome> {
    let dl = Duration::from_secs(timeout_secs);
    let addr = format!("{server}:{port}");

    // 1. TCP 建连 (计 RTT)。黑洞路由下会挂到内核 syn_retries, 故必须带超时。
    let t0 = Instant::now();
    let stream = timeout(dl, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("TCP 连接 {addr} 超时 ({timeout_secs}s, 黑洞路由/端口不通?)"))?
        .map_err(|e| anyhow!("TCP 连接 {addr} 失败: {e}"))?;
    let tcp_ms = t0.elapsed().as_millis() as u64;
    let _ = stream.set_nodelay(true);
    let (mut read_half, mut write_half) = stream.into_split();

    let t1 = Instant::now();

    // 2. 发带 token 的伪装 ClientHello, 读服务端握手 flight, 回假 Finished tail —— 与
    //    pool::connect_upstream 完全同一套原语。整段包一个总超时。
    let hs = async {
        let token = crate::crypto::hello_auth::make_session_token(password);
        let (hello, client_random) =
            crate::crypto::tls_raw::build_client_hello(camouflage_host, &token);
        write_half.write_all(&hello).await?;
        write_half.flush().await?;
        crate::proxy::pool::read_server_handshake(&mut read_half).await?;
        let tail = crate::crypto::tls_raw::build_fake_client_tail();
        write_half.write_all(&tail).await?;
        write_half.flush().await?;
        Ok::<_, anyhow::Error>(client_random)
    };
    let client_random = timeout(dl, hs)
        .await
        .map_err(|_| anyhow!("TLS 伪装握手超时 ({timeout_secs}s)"))?
        .map_err(|e| anyhow!("TLS 伪装握手失败: {e}"))?;

    // 3. 派生会话密钥, 尝试解服务端首帧。解密成功 = 密钥正确 = 密码对且是真 Mirage 服务端。
    let (mut reader, _writer) = crate::crypto::aead::create_crypto_pair(
        read_half,
        write_half,
        password,
        &client_random,
        true, // is_initiator
    );
    // 认证确认单独一个较短超时 (对齐 connect_upstream 的 3s TIME_SYNC 等待, 不超过总超时)。
    let auth_wait = dl.min(Duration::from_secs(3));
    match timeout(auth_wait, reader.recv_data()).await {
        // 解密成功 (任意帧): 会话密钥正确 → 认证通过。
        Ok(Ok(_data)) => Ok(ProbeOutcome::Ok {
            tcp_ms,
            handshake_ms: t1.elapsed().as_millis() as u64,
        }),
        // 解密失败: 服务端很可能拒了认证、把连接转给伪装站, 我们解不开它的真 TLS。
        Ok(Err(e)) => Ok(ProbeOutcome::Fail(format!(
            "认证失败: 会话数据解密错 (密码不符 / 非 Mirage 服务端 / 时钟偏差超服务端容差): {e}"
        ))),
        // 超时未收到首帧: TLS 握手过了但没确认认证 (旧服务端不下发 TIME_SYNC?)。
        Err(_) => Ok(ProbeOutcome::Unconfirmed {
            tcp_ms,
            note: "TLS 握手可达但未收到认证确认帧 (旧服务端?)".to_string(),
        }),
    }
}
