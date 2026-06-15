// No std::io::Write needed

#[tokio::test]
async fn test_mixed_parse_http() {
    let _http_req = b"GET http://user:pass@example.com:8080/path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    let uri = "http://user:pass@example.com:8080/path";
    
    let without_scheme = &uri[7..];
    let host_end = without_scheme.find('/').unwrap_or(without_scheme.len());
    let host_part = &without_scheme[..host_end];
    
    let actual_host = match host_part.rfind('@') {
        Some(at_idx) => &host_part[at_idx + 1..],
        None => host_part,
    };
    
    let target = if actual_host.contains(':') {
        actual_host.to_string()
    } else {
        format!("{}:80", actual_host)
    };
    
    assert_eq!(target, "example.com:8080");
}
