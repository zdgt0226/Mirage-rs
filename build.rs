fn main() {
    println!("cargo:rerun-if-changed=ebpf-src/sockmap.c");
    println!("cargo:rerun-if-changed=ebpf-src/dns_xdp.c");
    println!("cargo:rerun-if-env-changed=PATH");

    let uname = std::process::Command::new("uname").arg("-m").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "x86_64".to_string());
    
    let arch_inc = format!("-I/usr/include/{}-linux-gnu", uname);
    
    for (src, dst) in [
        ("ebpf-src/sockmap.c", "ebpf-src/sockmap.elf"),
        ("ebpf-src/dns_xdp.c", "ebpf-src/dns_xdp.elf"),
    ] {
        let status = std::process::Command::new("clang")
            .args([
                "-O2", "-g", "-target", "bpf",
                &arch_inc,
                "-c", src,
                "-o", dst,
            ])
            .status();
        
        match status {
            Ok(s) if s.success() => {
                let _ = std::process::Command::new("llvm-strip")
                    .args(["--strip-debug", dst]).status();
            }
            _ => {
                println!("cargo:warning=eBPF compile failed for {}, using committed ELF if exists", src);
            }
        }
    }
}
