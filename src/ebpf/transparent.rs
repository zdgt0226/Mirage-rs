

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod sys {
    use anyhow::{Context, Result};
    use aya::{
        Ebpf,
        programs::SkLookup,
    };
    use aya::maps::{Array, SockMap};
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpListener;
    use tracing::info;
    use crate::ebpf::get_socket_cookie;

    // fake-ip configuration structure matching the C definition
    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct FakeIpCfg {
        pub net: u32,
        pub mask: u32,
    }

    unsafe impl aya::Pod for FakeIpCfg {}

    pub struct TransparentEngine {
        bpf: std::sync::Mutex<Ebpf>,
        attached: bool,
    }

    impl TransparentEngine {
        pub fn init() -> Result<Self> {
            static TRANSPARENT_ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_TRANSPARENT_ELF"));
            let bpf = Ebpf::load(TRANSPARENT_ELF).context("Failed to load transparent.elf")?;
            tracing::info!("eBPF Transparent Engine initialized.");
            Ok(Self { 
                bpf: std::sync::Mutex::new(bpf),
                attached: false,
            })
        }

        pub fn attach_to_netns(&mut self, fakeip_net: std::net::Ipv4Addr, prefix_len: u8) -> Result<()> {
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());

            // 1. Write the fake-ip range to the BPF map
            let mut fakeip_map = Array::<_, FakeIpCfg>::try_from(bpf.map_mut("mirage_fakeip_cfg").unwrap())?;
            
            let net_u32 = u32::from(fakeip_net).to_be(); // network byte order
            let mask_u32 = if prefix_len == 0 { 0 } else { (!0u32 << (32 - prefix_len)).to_be() };
            
            let cfg = FakeIpCfg {
                net: net_u32 & mask_u32,
                mask: mask_u32,
            };
            fakeip_map.set(0, cfg, 0).context("Failed to write fakeip config to BPF map")?;
            
            info!("eBPF Transparent Engine configured with Fake-IP: {}/{}", fakeip_net, prefix_len);

            // 2. Attach sk_lookup program to the current network namespace
            if !self.attached {
                let netns = std::fs::File::open("/proc/self/ns/net").context("Failed to open /proc/self/ns/net")?;
                
                let program: &mut SkLookup = bpf.program_mut("mirage_sk_lookup").unwrap().try_into()?;
                if program.fd().is_err() {
                    program.load().context("Failed to load mirage_sk_lookup")?;
                }
                
                let _ = program.attach(netns).context("Failed to attach sk_lookup to netns")?;
                self.attached = true;
                tracing::info!("eBPF sk_lookup program attached to current netns.");
            }
            Ok(())
        }
        
        pub fn register_listener(&self, listener: &TcpListener) -> Result<()> {
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
            let fd = listener.as_raw_fd();
            let cookie = get_socket_cookie(fd)?;

            // Write actual listener socket into sockmap
            let mut sk_map = SockMap::<_>::try_from(bpf.map_mut("mirage_listener_sk").unwrap())?;
            // SockMap key is 0, value is the file descriptor
            sk_map.set(0, listener, 0).context("Failed to insert listener socket fd")?;

            info!("eBPF Transparent Engine: listener registered (cookie: {}, fd: {})", cookie, fd);
            Ok(())
        }
    }
}

#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
mod sys {
    use anyhow::Result;
    use tokio::net::TcpListener;
    use tracing::info;

    pub struct TransparentEngine {}

    impl TransparentEngine {
        pub fn init() -> Result<Self> {
            info!("eBPF Transparent Engine disabled (requires Linux and 'ebpf' feature). Use SOCKS5 / HTTP / Mixed inbound types for non-transparent operation.");
            Ok(Self {})
        }

        pub fn attach_to_netns(&mut self, _fakeip_net: std::net::Ipv4Addr, _prefix_len: u8) -> Result<()> {
            Ok(())
        }

        pub fn register_listener(&self, _listener: &TcpListener) -> Result<()> {
            Ok(())
        }
    }
}

pub use sys::TransparentEngine;
