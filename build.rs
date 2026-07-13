fn main() {
    println!("cargo:rerun-if-changed=ebpf-src/sockmap.c");
    println!("cargo:rerun-if-changed=ebpf-src/dns_xdp.c");
    println!("cargo:rerun-if-changed=ebpf-src/transparent.c");
    println!("cargo:rerun-if-changed=ebpf-src/tc_divert.c");
    println!("cargo:rerun-if-changed=ebpf-src/cgroup_connect.c");
    println!("cargo:rerun-if-changed=ebpf-src/mss_clamp.c");
    println!("cargo:rerun-if-env-changed=PATH");

    // Inject `git describe` so --version shows actual build state independent
    // of Cargo.toml. Rerun when:
    //   .git/HEAD            分支切换 (HEAD 文件内容变)
    //   .git/refs/heads      在当前分支新 commit (refs/heads/<branch> SHA 变)
    //   .git/refs/tags       新打 tag
    //   .git/index           staged 变化 (能让 --dirty 状态及时刷新)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/index");
    let git_desc = std::process::Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=MIRAGE_GIT={}", git_desc);

    let uname = std::process::Command::new("uname").arg("-m").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "x86_64".to_string());
    
    let arch_inc = format!("-I/usr/include/{}-linux-gnu", uname);
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    
    for (src, elf_name, env_var) in [
        ("ebpf-src/sockmap.c", "sockmap.elf", "BPF_SOCKMAP_ELF"),
        ("ebpf-src/dns_xdp.c", "dns_xdp.elf", "BPF_DNS_XDP_ELF"),
        ("ebpf-src/transparent.c", "transparent.elf", "BPF_TRANSPARENT_ELF"),
        ("ebpf-src/tc_divert.c", "tc_divert.elf", "BPF_TC_DIVERT_ELF"),
        ("ebpf-src/cgroup_connect.c", "cgroup_connect.elf", "BPF_CGROUP_CONNECT_ELF"),
        ("ebpf-src/mss_clamp.c", "mss_clamp.elf", "BPF_MSS_CLAMP_ELF"),
    ] {
        let src_path = manifest_dir.join(src);
        let dst_path = out_dir.join(elf_name);

        let status = std::process::Command::new("clang")
            .args([
                "-O2", "-g", "-target", "bpf",
                &arch_inc,
                "-c", src_path.to_str().unwrap(),
                "-o", dst_path.to_str().unwrap(),
            ])
            .status();
        
        match status {
            Ok(s) if s.success() => {
                println!("cargo:rustc-env={}={}", env_var, dst_path.display());
            }
            _ => {
                let fallback_path = manifest_dir.join("ebpf-src").join(elf_name);
                println!("cargo:warning=eBPF compile failed for {}, using committed ELF at {}", src, fallback_path.display());
                println!("cargo:rustc-env={}={}", env_var, fallback_path.display());
            }
        }
    }
}
