fn main() {
    println!("cargo:rerun-if-changed=ebpf-src/sockmap.c");
    println!("cargo:rerun-if-env-changed=PATH");
    let uname = std::process::Command::new("uname").arg("-m").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "x86_64".to_string());
    
    let arch_inc = format!("-I/usr/include/{}-linux-gnu", uname);

    let status = std::process::Command::new("clang")
        .args([
            "-O2", "-g", "-target", "bpf",
            &arch_inc,
            "-c", "ebpf-src/sockmap.c",
            "-o", "ebpf-src/sockmap.elf",
        ])
        .status();
        
    match status {
        Ok(s) if s.success() => {
            let _ = std::process::Command::new("llvm-strip")
                .args(["--strip-debug", "ebpf-src/sockmap.elf"])
                .status();
        }
        _ => println!("cargo:warning=eBPF compile failed, using committed ELF if exists"),
    }
}
