//! 查本机连接的发起进程名 (comm), 供 `process_name` 路由维度用。
//!
//! **仅对本机 loopback 连接有意义** —— app 从 `127.0.0.1:srcport` 连进本地 socks/mixed
//! 入站时, 我们能通过 `/proc` 反查是哪个程序。透明/LAN 转发的连接进程在别的机器上, 无从取。
//!
//! 路径: peer(app 的 local 端) → `/proc/net/tcp{,6}` 找 socket inode → 扫 `/proc/*/fd` 找持有
//! 该 inode 的 PID → 读进程名。查不到 (无权限/竞态/非本机) 一律返回 None。
//!
//! **成本**: 每次查要扫 `/proc/*/fd` (随系统总 fd 数, 非本连接)。每条新连接的 socket inode
//! 都不同, 无法跨连接缓存 —— 故不缓存。调用方 (handler) 已用 `router.uses_process_name()` +
//! loopback + `spawn_blocking` 三重门控: 没配 process_name 规则完全不触发, 触发也不占 reactor。
//!
//! **进程名 = 可执行文件 basename** (`/proc/PID/exe`), 与 clash/sing-box 一致; 取不到 (无权限/
//! 内核线程) 回落 `/proc/PID/comm` (注意 comm 被内核截断到 15 字符)。

use std::net::{IpAddr, SocketAddr};

/// peer 是否本机 (含双栈下的 v4-mapped loopback `::ffff:127.0.0.1`)。
/// `Ipv6Addr::is_loopback` 只认 `::1`, 不认 v4-mapped, 故单独判。供 handler 预门控复用。
pub fn is_local_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// 查发起连接的本机进程名。非本机 / 查不到 → None (调用方据此不填 process_name)。
pub fn process_name_for_peer(peer: SocketAddr) -> Option<String> {
    if !is_local_peer(peer.ip()) {
        return None;
    }
    let inode = socket_inode_for_local(peer)?;
    let pid = pid_for_socket_inode(inode)?;
    name_for_pid(pid)
}

/// 把 peer 格式化成 `/proc/net/tcp{,6}` 里 local_address 那列的 hex 串 (大写)。
/// v4: 4 octet 逆序; v6: 每 4 字节一组组内逆序 (内核按 32 位字小端存)。port 为大端 hex。
fn proc_hex_local(peer: SocketAddr) -> String {
    let port = format!("{:04X}", peer.port());
    let ip_hex = match peer.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{:02X}{:02X}{:02X}{:02X}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut s = String::with_capacity(32);
            for word in o.chunks(4) {
                for b in word.iter().rev() {
                    s.push_str(&format!("{b:02X}"));
                }
            }
            s
        }
    };
    format!("{ip_hex}:{port}")
}

/// 在 `/proc/net/tcp{,6}` 找 local_address == peer 的行, 取其 socket inode (第 10 列)。
fn socket_inode_for_local(peer: SocketAddr) -> Option<u64> {
    let path = match peer.ip() {
        IpAddr::V4(_) => "/proc/net/tcp",
        IpAddr::V6(_) => "/proc/net/tcp6",
    };
    let want = proc_hex_local(peer);
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines().skip(1) {
        let mut cols = line.split_whitespace();
        // 列: sl local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode
        let _sl = cols.next()?;
        let local = cols.next()?;
        if local != want {
            continue;
        }
        // 跳到 inode (local 之后第 8 个字段)
        return cols.nth(7).and_then(|s| s.parse().ok());
    }
    None
}

/// 扫 `/proc/*/fd/*` 找持有 `socket:[inode]` 的 PID。
fn pid_for_socket_inode(inode: u64) -> Option<u32> {
    let want = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue, // 非数字目录 (如 /proc/self)
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue; // 无权限 / 进程已退出
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).ok().as_deref().and_then(|p| p.to_str()) == Some(want.as_str()) {
                return Some(pid);
            }
        }
    }
    None
}

/// 进程名 = `/proc/PID/exe` 的 basename (完整可执行名, 与 clash/sing-box 一致);
/// 取不到 (无权限/内核线程/竞态) 回落 `/proc/PID/comm` (内核截断到 15 字符)。
fn name_for_pid(pid: u32) -> Option<String> {
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(base) = exe.file_name().and_then(|s| s.to_str()) {
            if !base.is_empty() {
                return Some(base.to_string());
            }
        }
    }
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = s.trim_end_matches('\n').to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_hex_v4() {
        // 127.0.0.1:8080 → "0100007F:1F90"
        let p: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(proc_hex_local(p), "0100007F:1F90");
    }

    #[test]
    fn proc_hex_v6_loopback() {
        // ::1 → 每 4 字节组内逆序; ::1 = 15×00 + 01, 最后一组 00000000→"01000000"
        let p: SocketAddr = "[::1]:443".parse().unwrap();
        let h = proc_hex_local(p);
        assert!(h.ends_with(":01BB"), "port 443 = 0x1BB: {h}");
        assert_eq!(h, "00000000000000000000000001000000:01BB");
    }

    #[test]
    fn non_loopback_is_none() {
        assert!(process_name_for_peer("8.8.8.8:53".parse().unwrap()).is_none());
    }

    #[test]
    fn v4_mapped_loopback_recognized() {
        // 双栈 [::]:port 下, v4 客户端显示为 ::ffff:127.0.0.1 —— 要认作本机。
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_local_peer(ip), "v4-mapped loopback 应判本机");
        assert!(!is_local_peer("::ffff:8.8.8.8".parse().unwrap()), "v4-mapped 公网非本机");
        // hex 格式 = 内核 /proc/net/tcp6 的 v4-mapped 形式
        let p: SocketAddr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        assert_eq!(proc_hex_local(p), "0000000000000000FFFF00000100007F:1F90");
    }

    #[test]
    fn resolves_own_process() {
        // 起一个真 TCP 连接, 用它的本地端 (loopback) 反查, 应查到本测试进程名。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (_srv, _peer) = listener.accept().unwrap();
        // client 的 local 端 = 本进程持有的 socket, 反查应得本进程名 (exe basename)。
        let mine = name_for_pid(std::process::id()).unwrap();
        let looked = process_name_for_peer(client.local_addr().unwrap());
        // CI 无权限扫 /proc 时可能 None, 有结果则必须等于自己。
        if let Some(name) = looked {
            assert_eq!(name, mine, "反查到的进程名应是本测试进程");
        }
        drop(client);
    }
}
