#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod sys {
    use anyhow::Result;
    use aya::{Ebpf, programs::SkMsg};
    use aya::maps::SockHash;
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;
    use tracing::info;

    pub struct EbpfEngine {
        bpf: Ebpf,
    }

    impl EbpfEngine {
        pub fn init() -> Result<Self> {
            let mut bpf = Ebpf::load_file("ebpf-src/sockmap.elf")?;
            
            let sockmap_fd = {
                let map = bpf.map("mirage_sockmap").unwrap();
                let sock_hash = SockHash::<_, u64>::try_from(map)?;
                sock_hash.fd().try_clone()?.try_into()?
            };
            
            let program: &mut SkMsg = bpf.program_mut("mirage_sk_msg").unwrap().try_into()?;
            program.load()?;
            program.attach(&sockmap_fd)?;
            
            info!("eBPF Engine initialized! Waiting for sockmap registrations.");

            Ok(Self { bpf })
        }

        pub fn register_splice(&mut self, local: &TcpStream, remote: &TcpStream) -> Result<()> {
            let mut map = SockHash::<_, u64>::try_from(self.bpf.map_mut("mirage_sockmap").unwrap())?;
            
            let local_cookie = get_socket_cookie(local.as_raw_fd())?;
            let remote_cookie = get_socket_cookie(remote.as_raw_fd())?;
            
            let local_fd = local.as_raw_fd();
            let remote_fd = remote.as_raw_fd();
            
            map.insert(local_cookie, remote_fd, 0)?;
            map.insert(remote_cookie, local_fd, 0)?;
            
            info!("eBPF SockMap: spliced local_cookie={} <-> remote_cookie={} (Zero-copy bypass activated)", local_cookie, remote_cookie);
            Ok(())
        }
    }

    fn get_socket_cookie(fd: std::os::unix::io::RawFd) -> Result<u64> {
        let mut cookie: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        let res = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                &mut cookie as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if res < 0 {
            return Err(anyhow::anyhow!("Failed to get socket cookie"));
        }
        Ok(cookie)
    }
}

#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
mod sys {
    use anyhow::Result;
    use tokio::net::TcpStream;
    use tracing::info;

    pub struct EbpfEngine {}

    impl EbpfEngine {
        pub fn init() -> Result<Self> {
            info!("eBPF Engine is disabled (Requires feature 'ebpf' and Linux OS). Falling back to Tokio userspace forwarding.");
            Ok(Self {})
        }

        pub fn register_splice(&mut self, _local: &TcpStream, _remote: &TcpStream) -> Result<()> {
            // No-op. Tokio io::copy will take over.
            Ok(())
        }
    }
}

pub use sys::EbpfEngine;
