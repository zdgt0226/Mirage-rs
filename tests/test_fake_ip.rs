// Tests for src/dns/fake_ip.rs FakeIpMapper.
// Covers CIDR parsing edge cases, allocation, reverse lookup, conflict avoidance.

use mirage_rs::dns::fake_ip::FakeIpMapper;
use std::net::Ipv4Addr;

#[test]
fn test_basic_alloc_and_reverse() {
    let mapper = FakeIpMapper::new("198.18.0.0/16").unwrap();
    let ip = mapper.lookup_or_assign("youtube.com");
    assert!(mapper.is_fake_ip(&ip));
    assert_eq!(mapper.lookup_domain(&ip), Some("youtube.com".to_string()));
}

#[test]
fn test_same_domain_returns_same_ip() {
    let mapper = FakeIpMapper::new("198.18.0.0/16").unwrap();
    let ip1 = mapper.lookup_or_assign("youtube.com");
    let ip2 = mapper.lookup_or_assign("youtube.com");
    assert_eq!(ip1, ip2);
}

#[test]
fn test_different_domains_get_different_ips() {
    let mapper = FakeIpMapper::new("198.18.0.0/16").unwrap();
    let ip1 = mapper.lookup_or_assign("youtube.com");
    let ip2 = mapper.lookup_or_assign("google.com");
    assert_ne!(ip1, ip2);
}

#[test]
fn test_case_insensitive_domain() {
    let mapper = FakeIpMapper::new("198.18.0.0/16").unwrap();
    let ip_lower = mapper.lookup_or_assign("youtube.com");
    let ip_upper = mapper.lookup_or_assign("YouTube.COM");
    assert_eq!(ip_lower, ip_upper);
}

#[test]
fn test_is_fake_ip_classification() {
    let mapper = FakeIpMapper::new("198.18.0.0/16").unwrap();
    assert!(mapper.is_fake_ip(&Ipv4Addr::new(198, 18, 0, 5)));
    assert!(mapper.is_fake_ip(&Ipv4Addr::new(198, 18, 200, 100)));
    assert!(!mapper.is_fake_ip(&Ipv4Addr::new(8, 8, 8, 8)));
    assert!(!mapper.is_fake_ip(&Ipv4Addr::new(198, 19, 0, 5))); // adjacent range
}

#[test]
fn test_cidr_prefix_too_large_rejected() {
    // prefix > 32 must be rejected to avoid arithmetic overflow
    let result = FakeIpMapper::new("198.18.0.0/33");
    assert!(result.is_err(), "prefix > 32 should fail");
}

#[test]
fn test_cidr_prefix_zero_handled() {
    // prefix = 0 means "match everything" — must not overflow `!0u32 << 32`
    let result = FakeIpMapper::new("0.0.0.0/0");
    assert!(result.is_ok(), "prefix = 0 must not panic");
}

#[test]
fn test_cidr_prefix_32_exact() {
    // Single-IP range
    let result = FakeIpMapper::new("192.0.2.1/32");
    assert!(result.is_ok());
}

#[test]
fn test_cidr_invalid_format() {
    assert!(FakeIpMapper::new("not.a.cidr").is_err());
    assert!(FakeIpMapper::new("198.18.0.0").is_err()); // missing /prefix
    assert!(FakeIpMapper::new("198.18.0.0/abc").is_err());
}

#[test]
fn test_unknown_ip_reverse_lookup_returns_none() {
    let mapper = FakeIpMapper::new("198.18.0.0/16").unwrap();
    let _ = mapper.lookup_or_assign("youtube.com"); // populate one entry
    let unrelated = Ipv4Addr::new(198, 18, 99, 99);
    // An IP in range but not yet assigned should return None
    assert_eq!(mapper.lookup_domain(&unrelated), None);
}

#[test]
fn test_network_and_prefix_exposed() {
    let mapper = FakeIpMapper::new("198.18.0.0/15").unwrap();
    assert_eq!(mapper.network(), Ipv4Addr::new(198, 18, 0, 0));
    assert_eq!(mapper.prefix_len(), 15);
}

#[test]
fn test_small_range_does_not_panic() {
    // /30 = 4 addresses, /28 = 16. lookup_or_assign starts at network+2.
    // Verify rapid allocation in a small range doesn't infinite-loop the
    // conflict-resolution while-loop.
    let mapper = FakeIpMapper::new("192.0.2.0/28").unwrap();
    for i in 0..20 {
        let domain = format!("test-{}.example", i);
        let _ip = mapper.lookup_or_assign(&domain);
        // Should return *some* IP; may be a recycled one once exhausted
    }
}
