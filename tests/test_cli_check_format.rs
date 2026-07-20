//! `mirage-rs check` / `format` / `import` 子命令的行为锁定。
//!
//! 直接跑编译出的二进制, 断言**退出码**与关键输出性质 —— 退出码是 check 的核心契约
//! (`check && systemctl restart` 靠它当闸门), 光测库函数覆盖不到。

use std::io::Write;
use std::process::Command;

/// 被测二进制路径 (与本集成测试同一 profile)。
fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    p.pop(); // debug/ or release/
    p.push("mirage");
    p
}

fn write_tmp(name: &str, content: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("mirage_cli_{}_{}", std::process::id(), name));
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    p
}

const CLEAN: &str = r#"{
  "log_level": "info",
  "inbounds": [{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "port": 1080 }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "routing": { "default_outbound": "direct", "rules": [] }
}"#;

#[test]
fn check_clean_config_exits_zero() {
    let p = write_tmp("clean.json", CLEAN);
    let out = Command::new(bin()).args(["check", "-c", p.to_str().unwrap()]).output().unwrap();
    std::fs::remove_file(&p).ok();
    assert!(out.status.success(), "干净配置应 exit 0, stderr={}",
            String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("校验通过"));
}

#[test]
fn check_reports_issues_and_exits_nonzero() {
    // 拼错的键 + 引用了不存在的 outbound
    let bad = CLEAN.replace(
        r#""rules": []"#,
        r#""rules": [{ "outbound": "ghost" }]"#,
    ).replace(
        r#""log_level": "info","#,
        r#""log_levle": "info","#,
    );
    let p = write_tmp("bad.json", &bad);
    let out = Command::new(bin()).args(["check", "-c", p.to_str().unwrap()]).output().unwrap();
    std::fs::remove_file(&p).ok();

    assert!(!out.status.success(), "有问题必须非零退出 (否则闸门失效)");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("log_levle"), "应报未知字段, 实际: {err}");
    assert!(err.contains("ghost"), "应报不存在的 outbound, 实际: {err}");
}

#[test]
fn check_missing_file_exits_nonzero() {
    let out = Command::new(bin())
        .args(["check", "-c", "/definitely/not/here.json"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn check_invalid_json_exits_nonzero() {
    let p = write_tmp("broken.json", "{ not json");
    let out = Command::new(bin()).args(["check", "-c", p.to_str().unwrap()]).output().unwrap();
    std::fs::remove_file(&p).ok();
    assert!(!out.status.success());
}

#[test]
fn format_preserves_key_order_and_unknown_fields() {
    // 故意让键序**非字母序**, 且带一个 Config 结构体不认识的字段
    let src = r#"{"routing":{"default_outbound":"direct","rules":[]},"zzz_unknown":"keep-me","log_level":"info","inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","port":1080}],"outbounds":[{"type":"direct","tag":"direct"}]}"#;
    let p = write_tmp("fmt.json", src);
    let out = Command::new(bin()).args(["format", "-c", p.to_str().unwrap()]).output().unwrap();
    std::fs::remove_file(&p).ok();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);

    // 未知字段不能被 Config 结构体吞掉 (那是改写不是格式化)
    assert!(s.contains("zzz_unknown"), "未知字段必须保留, 实际:\n{s}");
    // 键序保持: routing 必须仍在 zzz_unknown / log_level 之前 (字母序会把它排到后面)
    let i_routing = s.find("\"routing\"").expect("routing");
    let i_log = s.find("\"log_level\"").expect("log_level");
    assert!(i_routing < i_log, "键序应保持原样而非字母序重排, 实际:\n{s}");
    // 输出必须是合法 JSON
    serde_json::from_str::<serde_json::Value>(&s).expect("格式化输出应是合法 JSON");
}

#[test]
fn format_is_idempotent() {
    let p = write_tmp("idem.json", CLEAN);
    let first = Command::new(bin()).args(["format", "-c", p.to_str().unwrap()]).output().unwrap();
    let p2 = write_tmp("idem2.json", &String::from_utf8_lossy(&first.stdout));
    let second = Command::new(bin()).args(["format", "-c", p2.to_str().unwrap()]).output().unwrap();
    std::fs::remove_file(&p).ok();
    std::fs::remove_file(&p2).ok();
    assert_eq!(first.stdout, second.stdout, "格式化两次结果应一致");
}

#[test]
fn format_invalid_json_exits_nonzero() {
    let p = write_tmp("bad_fmt.json", "{ nope");
    let out = Command::new(bin()).args(["format", "-c", p.to_str().unwrap()]).output().unwrap();
    std::fs::remove_file(&p).ok();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("不是合法 JSON"));
}

// ── import ────────────────────────────────────────────────────────────────

const URI: &str = "mirage://p%40ss@vps.example.com:9443?sni=www.apple.com";

fn read_json(p: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// 用管道喂 stdin 跑 import。
fn run_import(cfg: &std::path::Path, uri: &str, stdin_lines: &str) -> std::process::Output {
    use std::process::Stdio;
    let mut c = Command::new(bin())
        .args(["import", "-c", cfg.to_str().unwrap(), uri])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.as_mut().unwrap().write_all(stdin_lines.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

#[test]
fn import_adds_outbound_with_chosen_tag() {
    let p = write_tmp("imp.json", CLEAN);
    let out = run_import(&p, URI, "my-node\n");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));

    let v = read_json(&p);
    let obs = v["outbounds"].as_array().unwrap();
    let last = obs.last().unwrap();
    assert_eq!(last["tag"], "my-node");
    assert_eq!(last["type"], "mirage");
    assert_eq!(last["server"], "vps.example.com");
    assert_eq!(last["server_port"], 9443);
    assert_eq!(last["password"], "p@ss", "百分号编码的密码必须解码还原");
    assert_eq!(last["camouflage_host"], "www.apple.com");
    // 原有出站不能被动到
    assert_eq!(obs[0]["tag"], "direct");

    std::fs::remove_file(&p).ok();
    std::fs::remove_file(format!("{}.bak", p.display())).ok();
}

#[test]
fn import_rejects_conflicting_tag_then_accepts() {
    let p = write_tmp("imp_conflict.json", CLEAN);
    // 先输入已存在的 `direct` (应被拒绝并重问), 再输入合法 tag
    let out = run_import(&p, URI, "direct\nok-tag\n");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("已存在"), "应提示 tag 冲突, 实际: {stdout}");

    let v = read_json(&p);
    let obs = v["outbounds"].as_array().unwrap();
    assert_eq!(obs.len(), 2, "只应新增一个出站");
    assert_eq!(obs.last().unwrap()["tag"], "ok-tag");
    // 冲突的那个名字不能被覆盖
    assert_eq!(obs[0]["tag"], "direct");
    assert_eq!(obs[0]["type"], "direct", "既有 direct 出站不能被顶掉");

    std::fs::remove_file(&p).ok();
    std::fs::remove_file(format!("{}.bak", p.display())).ok();
}

#[test]
fn import_keeps_backup_of_original() {
    let p = write_tmp("imp_bak.json", CLEAN);
    let out = run_import(&p, URI, "t1\n");
    assert!(out.status.success());
    let bak = format!("{}.bak", p.display());
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), CLEAN, "备份应是导入前的原文件");
    std::fs::remove_file(&p).ok();
    std::fs::remove_file(&bak).ok();
}

#[test]
fn import_result_still_passes_check() {
    let p = write_tmp("imp_check.json", CLEAN);
    assert!(run_import(&p, URI, "node-x\n").status.success());
    let out = Command::new(bin()).args(["check", "-c", p.to_str().unwrap()]).output().unwrap();
    assert!(out.status.success(), "导入后的配置应仍能通过校验: {}",
            String::from_utf8_lossy(&out.stderr));
    std::fs::remove_file(&p).ok();
    std::fs::remove_file(format!("{}.bak", p.display())).ok();
}

#[test]
fn import_bad_uri_exits_nonzero_without_touching_config() {
    let p = write_tmp("imp_bad.json", CLEAN);
    let out = run_import(&p, "http://not-a-mirage-uri", "t\n");
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(&p).unwrap(), CLEAN, "URI 非法时绝不能改动配置");
    std::fs::remove_file(&p).ok();
}
