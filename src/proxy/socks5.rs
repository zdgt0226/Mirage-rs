use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub enum SocksCommand {
    TcpConnect(String),
    UdpAssociate,
}

/// RFC 1929 用户名/密码子协商。
/// 请求: [VER=0x01][ULEN][UNAME][PLEN][PASSWD]; 响应: [VER=0x01][STATUS] (0=成功)。
async fn verify_userpass(
    stream: &mut TcpStream,
    cred: &crate::config::InboundAuth,
) -> Result<()> {
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;
    if ver[0] != 0x01 {
        return Err(anyhow!("unsupported auth subnegotiation version: {}", ver[0]));
    }

    let mut ulen = [0u8; 1];
    stream.read_exact(&mut ulen).await?;
    let mut username = vec![0u8; ulen[0] as usize];
    stream.read_exact(&mut username).await?;

    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    let mut password = vec![0u8; plen[0] as usize];
    stream.read_exact(&mut password).await?;

    if cred.verify(&username, &password) {
        stream.write_all(&[0x01, 0x00]).await?;
        Ok(())
    } else {
        // 失败也要按协议回一帧再断, 否则客户端看到的是裸 RST 而非"认证失败"。
        let _ = stream.write_all(&[0x01, 0x01]).await;
        Err(anyhow!("socks5 auth failed"))
    }
}

/// 执行 SOCKS5 握手，解析并返回目标地址及命令类型。
///
/// `auth` 为 `Some` 时**强制** RFC 1929 用户名/密码认证 (方法 0x02); 为 `None` 时沿用
/// 无认证 (方法 0x00)。注意: 配了 auth 就不再接受 0x00 —— 否则客户端只要声明"我不想认证"
/// 就能绕过, 等于没鉴权。
pub async fn handshake(
    stream: &mut TcpStream,
    auth: Option<&crate::config::InboundAuth>,
) -> Result<SocksCommand> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        return Err(anyhow!("Unsupported SOCKS version: {}", header[0]));
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    match auth {
        Some(cred) => {
            // 只认 0x02。客户端不支持 → 回 0xFF (无可接受方法) 后断开。
            if !methods.contains(&0x02) {
                let _ = stream.write_all(&[0x05, 0xFF]).await;
                return Err(anyhow!("client does not support username/password auth"));
            }
            stream.write_all(&[0x05, 0x02]).await?;
            verify_userpass(stream, cred).await?;
        }
        None => {
            if !methods.contains(&0x00) {
                let _ = stream.write_all(&[0x05, 0xFF]).await;
                return Err(anyhow!("No supported auth methods"));
            }
            stream.write_all(&[0x05, 0x00]).await?;
        }
    }

    // 读取客户端的 CONNECT 或 UDP ASSOCIATE 请求
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;

    if req_header[0] != 0x05 {
        return Err(anyhow!("Unsupported version in request"));
    }
    
    let cmd = req_header[1];
    if cmd != 0x01 && cmd != 0x03 {
        return Err(anyhow!("Unsupported command (only CONNECT and UDP ASSOCIATE supported)"));
    }

    let target = match req_header[3] {
        // IPv4
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            format!("{}:{}", Ipv4Addr::from(ip), port)
        }
        // Domain
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            format!("{}:{}", String::from_utf8(domain)?, port)
        }
        // IPv6
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            format!("[{}]:{}", Ipv6Addr::from(ip), port)
        }
        _ => return Err(anyhow!("Unsupported address type")),
    };

    if cmd == 0x01 {
        // TCP CONNECT: 握手成功响应
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;
        Ok(SocksCommand::TcpConnect(target))
    } else {
        // UDP ASSOCIATE: do not reply yet, caller must reply with bound UDP port!
        Ok(SocksCommand::UdpAssociate)
    }
}

#[cfg(test)]
mod auth_tests {
    use super::{handshake, SocksCommand};
    use crate::config::InboundAuth;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn cred() -> InboundAuth {
        InboundAuth { username: "alice".into(), password: "s3cret".into() }
    }

    /// 起一对真实 TCP: 返回 (服务端 stream, 客户端 stream)。
    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let cli = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (srv, _) = l.accept().await.unwrap();
        (srv, cli.await.unwrap())
    }

    /// CONNECT 1.2.3.4:80 请求帧
    const CONNECT_REQ: &[u8] = &[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];

    #[tokio::test]
    async fn userpass_success() {
        let (mut srv, mut cli) = pair().await;
        let h = tokio::spawn(async move { handshake(&mut srv, Some(&cred())).await });

        cli.write_all(&[0x05, 0x01, 0x02]).await.unwrap(); // 只报 0x02
        let mut r = [0u8; 2];
        cli.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [0x05, 0x02], "服务端应选用户名/密码方法");

        cli.write_all(&[0x01, 5, b'a', b'l', b'i', b'c', b'e', 6, b's', b'3', b'c', b'r', b'e', b't'])
            .await.unwrap();
        let mut a = [0u8; 2];
        cli.read_exact(&mut a).await.unwrap();
        assert_eq!(a, [0x01, 0x00], "认证应成功");

        cli.write_all(CONNECT_REQ).await.unwrap();
        match h.await.unwrap() {
            Ok(SocksCommand::TcpConnect(t)) => assert_eq!(t, "1.2.3.4:80"),
            other => panic!("期望 TcpConnect, 得到 {:?}", other.is_ok()),
        }
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let (mut srv, mut cli) = pair().await;
        let h = tokio::spawn(async move { handshake(&mut srv, Some(&cred())).await });

        cli.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut r = [0u8; 2];
        cli.read_exact(&mut r).await.unwrap();
        cli.write_all(&[0x01, 5, b'a', b'l', b'i', b'c', b'e', 3, b'b', b'a', b'd'])
            .await.unwrap();

        let mut a = [0u8; 2];
        cli.read_exact(&mut a).await.unwrap();
        assert_eq!(a, [0x01, 0x01], "应回失败状态帧而非裸断");
        assert!(h.await.unwrap().is_err(), "handshake 必须失败");
    }

    /// 最关键的一条: 配了 auth 时, 客户端只声明 0x00 (无认证) **不能**绕过。
    #[tokio::test]
    async fn no_auth_method_cannot_bypass() {
        let (mut srv, mut cli) = pair().await;
        let h = tokio::spawn(async move { handshake(&mut srv, Some(&cred())).await });

        cli.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // 我不想认证
        let mut r = [0u8; 2];
        cli.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [0x05, 0xFF], "必须回 0xFF 无可接受方法");
        assert!(h.await.unwrap().is_err(), "绝不能放行");
    }

    /// 未配 auth 时保持原有无认证行为 (向后兼容)。
    #[tokio::test]
    async fn no_auth_configured_still_works() {
        let (mut srv, mut cli) = pair().await;
        let h = tokio::spawn(async move { handshake(&mut srv, None).await });

        cli.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut r = [0u8; 2];
        cli.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [0x05, 0x00]);

        cli.write_all(CONNECT_REQ).await.unwrap();
        assert!(h.await.unwrap().is_ok());
    }
}
