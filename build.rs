fn main() {
    println!("cargo:rerun-if-changed=ebpf-src/sockmap.c");
    println!("cargo:rerun-if-changed=ebpf-src/dns_xdp.c");
    println!("cargo:rerun-if-changed=ebpf-src/transparent.c");
    println!("cargo:rerun-if-changed=ebpf-src/tc_divert.c");
    println!("cargo:rerun-if-changed=ebpf-src/cgroup_connect.c");
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

    // 只在 feature=ebpf && Linux 目标下真编译 BPF (env! 也只在这两条件下经 aya 引用)。
    // 否则 (默认无 ebpf / 非 Linux / 交叉编译 / 无 clang) 直接指向 committed ELF, 不跑 clang,
    // 免无谓噪声和交叉环境的不确定差异。committed ELF 始终存在, env 变量始终有定义。
    let ebpf_on = std::env::var_os("CARGO_FEATURE_EBPF").is_some();
    let is_linux = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");

    for (src, elf_name, env_var) in [
        ("ebpf-src/sockmap.c", "sockmap.elf", "BPF_SOCKMAP_ELF"),
        ("ebpf-src/dns_xdp.c", "dns_xdp.elf", "BPF_DNS_XDP_ELF"),
        ("ebpf-src/transparent.c", "transparent.elf", "BPF_TRANSPARENT_ELF"),
        ("ebpf-src/tc_divert.c", "tc_divert.elf", "BPF_TC_DIVERT_ELF"),
        ("ebpf-src/cgroup_connect.c", "cgroup_connect.elf", "BPF_CGROUP_CONNECT_ELF"),
    ] {
        let fallback_path = manifest_dir.join("ebpf-src").join(elf_name);

        if !(ebpf_on && is_linux) {
            // 不编译 BPF (默认无 ebpf / 非 Linux): env 仍定义以满足 env! 展开, 但此配置下
            // aya 加载代码整体 #[cfg(feature="ebpf")] 编译掉、include_bytes! 不生成, 故该路径
            // 指向的文件从不被读 (committed ELF 已删除, 这里只是个占位路径字符串)。
            println!("cargo:rustc-env={}={}", env_var, fallback_path.display());
            continue;
        }

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
                // clang 缺失/失败。**只回落到本地存在的 ebpf-src/*.elf, 且这些文件不入库**
                // (见 .gitignore) —— 故回落只可能命中"刚由可信流程新鲜生成"的 ELF:
                //   · release CI: 先在 runner 上用 clang 显式编译 BPF 到 ebpf-src/*.elf, 再经
                //     cross-rs 容器 (容器内无 clang) 构建 musl 目标 → 容器里 build.rs 回落到这批
                //     **新鲜** ELF。这是 musl 发版能成立的关键。
                //   · 本地 `--features ebpf` 无 clang: ebpf-src/*.elf 不存在 (未入库/未生成) →
                //     **硬 panic**, 不再像旧版静默加载仓库里的陈旧 committed ELF (那会跑带 bug 的
                //     BPF, 如 dns_xdp 域名哈希碰撞 P1 → 流量劫持到错 IP)。
                if fallback_path.exists() {
                    println!(
                        "cargo:warning=clang 不可用, {} 回落到已存在的 {} (应仅出现在 CI 交叉编译: \
                         该 ELF 由 runner 上的显式 clang 步骤新鲜生成)",
                        src,
                        fallback_path.display()
                    );
                    println!("cargo:rustc-env={}={}", env_var, fallback_path.display());
                } else {
                    panic!(
                        "eBPF 编译失败且无可回落的 ELF: {src}\n\
                         开启了 `--features ebpf` 就必须能编译 BPF 程序。请安装 clang + llvm \
                         (如 `apt install clang llvm libbpf-dev`), 或去掉 `--features ebpf` \
                         构建纯用户态版本 (默认即无 ebpf, 不需要 clang)。\n\
                         (注: ebpf-src/*.elf 不入库, 故本地无 clang 时无陈旧 ELF 可静默加载。)"
                    );
                }
            }
        }
    }
}
