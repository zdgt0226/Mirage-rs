use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub enum SocksCommand {
    TcpConnect(String),
    UdpAssociate,
}

/// 执行 SOCKS5 握手，解析并返回目标地址及命令类型。
pub async fn handshake(stream: &mut TcpStream) -> Result<SocksCommand> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        return Err(anyhow!("Unsupported SOCKS version: {}", header[0]));
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // 强制使用 NO AUTH (0x00)
    if !methods.contains(&0x00) {
        return Err(anyhow!("No supported auth methods"));
    }
    stream.write_all(&[0x05, 0x00]).await?;

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
            format!("{}:{}", Ipv6Addr::from(ip), port)
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
