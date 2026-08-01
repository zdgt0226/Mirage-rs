//! 抗审查**泄漏守卫**场景测试 —— 对照 docs/threat-model.md 的验收目标 (T1–T5)。
//!
//! 对防审查代理, 最重要的不是单函数正确, 而是**行为保证**: 被代理流量不泄漏真实 IP、
//! 失败即关闭 (fail-closed) 而非静默走直连、被代理域名不采信被污染的本地 DNS。本文件把这些
//! 保证提成一等公民的集成断言, 每个测试名标注它守的威胁模型目标。
//!
//! 注: 需要真内核 / netns 的行为 (透明数据面全链路、tc/sk_lookup) 不在此文件 —— 那些由
//! examples/verify_*.sh 在 CI 的 ebpf-verify job 里覆盖。这里只放纯用户态可判定的守卫。

use mirage_rs::config::{Config, InboundConfig, UdpPolicy, UpstreamConfig};
use mirage_rs::dns::fake_ip::FakeIpMapper;
use std::net::Ipv4Addr;

fn cfg_with_ss_upstream(extra: &str) -> Config {
    let s = format!(
        r#"{{
          "inbounds": [{{ "type": "mirage_server", "tag": "srv", "listen": "0.0.0.0",
                          "port": 443, "password": "pw",
                          "upstream": {{ "type": "shadowsocks", "server": "h", "server_port": 8388,
                                        "password": "p", "method": "aes-256-gcm"{extra} }} }}],
          "outbounds": [{{ "type": "direct", "tag": "direct" }}],
          "routing": {{ "default_outbound": "direct", "rules": [] }}
        }}"#
    );
    serde_json::from_str(&s).expect("配置应能解析")
}

/// T3 (不泄漏真实 IP): SS 上游未显式配 udp 时, 策略**默认 Block**。
/// 反例代价: 若默认放行, UDP 会从本机/服务端真实 IP 裸奔出去, 与 TCP 出口 IP 不一致 →
/// 暴露真实出口 + 可关联。这条默认值是抗审查红线, 不能被改成 Direct。
#[test]
fn t3_ss_upstream_udp_defaults_to_block() {
    let cfg = cfg_with_ss_upstream(""); // 不写 udp 字段
    let InboundConfig::MirageServer { upstream: Some(up), .. } = &cfg.inbounds[0] else {
        panic!("应是带上游的 mirage_server 入站");
    };
    let UpstreamConfig::Shadowsocks { udp, .. } = up else {
        panic!("应是 shadowsocks 上游");
    };
    assert!(matches!(udp, UdpPolicy::Block), "SS 上游 UDP 默认必须 Block —— 否则从真实 IP 裸奔");
}

/// T3/T4 (fail-closed): SS 上游配 udp=tunnel (SS 的 UDP 尚未实现) → check 阶段**报错**,
/// 而不是静默降级成某个默认行为悄悄放行/裸奔。
#[test]
fn t3_ss_upstream_tunnel_udp_rejected_at_check() {
    let cfg = cfg_with_ss_upstream(r#", "udp": "tunnel""#);
    let issues = cfg.semantic_issues();
    assert!(
        issues.iter().any(|i| i.contains("tunnel")),
        "SS 上游 udp=tunnel 应被 check 拦下 (不静默降级), 实际 issues: {issues:?}"
    );
}

/// T4 (fail-closed): 一个在 fake-IP 网段内、但**从未分配**的 IP, 反查域名必须是 None。
/// 调用方 (transparent handler) 拿到 None 会 **drop**, 绝不凭空编个目标去直连 —— 这是
/// "fake-IP 丢失/未知 → 断, 不泄漏" 的基础。若这里返回了某域名 = 会误路由/泄漏。
#[test]
fn t4_fakeip_unknown_inrange_ip_returns_none_not_invented() {
    let mapper = FakeIpMapper::new("198.18.0.0/16").unwrap();
    mapper.lookup_or_assign("youtube.com"); // 占掉起始槽位
    // 取一个网段内、明显未分配的 IP
    let never = Ipv4Addr::new(198, 18, 200, 200);
    assert!(mapper.is_fake_ip(&never), "该 IP 应在 fake 网段内");
    assert_eq!(
        mapper.lookup_domain(&never),
        None,
        "未分配的 fake-IP 反查必须 None (调用方据此 fail-closed drop, 不得凭空编目标)"
    );
}

/// T4 (fail-closed): 小网段跑满触发 round-robin 淘汰后, 被淘汰域名的**原 IP** 不得再反查回
/// 那个旧域名 (否则会把新域名的流量误发到旧域名的目标)。淘汰即彻底失效, 交由调用方 fail-closed。
#[test]
fn t4_fakeip_eviction_leaves_no_stale_reverse_mapping() {
    // /29 = 最小网段, 主机位少, 易跑满触发淘汰。
    let mapper = FakeIpMapper::new("198.18.0.0/29").unwrap();
    let first = "a.example";
    let first_ip = mapper.lookup_or_assign(first);
    // 灌足够多不同域名把网段跑满 + round-robin 复用到 first_ip 那个槽位。
    for i in 0..64 {
        mapper.lookup_or_assign(&format!("d{i}.example"));
    }
    // first_ip 被复用后, 反查它得到的**绝不能**还是旧域名 first。
    match mapper.lookup_domain(&first_ip) {
        None => {}                       // 槽位空出: 可
        Some(d) => assert_ne!(d, first, "淘汰后旧 IP 不得再反查回旧域名 (会误路由)"),
    }
    // 且旧域名要么重分到新 IP、要么已失效, 反正不能还钉在被复用的 first_ip 上造成串味。
}
