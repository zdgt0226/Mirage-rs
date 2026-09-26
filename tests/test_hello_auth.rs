use mirage_rs::crypto::hello_auth::{
    make_session_token, verify_session_token, TokenReplayCache, QUIC_LEAN_BIND,
};

#[test]
fn test_token_auth_roundtrip() {
    let password = "super_secret_password";
    let client_random = [0x42u8; 32];
    
    // Generate token bound to client_random
    let token = make_session_token(password, &client_random);
    assert_eq!(token.len(), 32);
    
    // Verify valid token with matching bind
    let mut token_arr = [0u8; 32];
    token_arr.copy_from_slice(&token);
    assert!(verify_session_token(password, &token_arr, &client_random, 60));

    // Replay should fail
    assert!(!verify_session_token(password, &token_arr, &client_random, 60));
}

#[test]
fn test_token_bind_bit_flip_fails() {
    let password = "super_secret_password";
    let client_random = [0x55u8; 32];
    let token = make_session_token(password, &client_random);

    // 翻转 client_random 的 1 bit
    let mut tampered_random = client_random;
    tampered_random[0] ^= 0x01;

    assert!(
        !verify_session_token(password, &token, &tampered_random, 60),
        "bind 翻转 1 bit 校验必须失败"
    );
}

#[test]
fn test_token_domain_quic_tcp_separation() {
    let password = "super_secret_password";
    let client_random = [0x77u8; 32];

    // QUIC lean token 绑定 QUIC_LEAN_BIND
    let quic_token = make_session_token(password, QUIC_LEAN_BIND);
    // 用 TCP bind 校验必须失败
    assert!(
        !verify_session_token(password, &quic_token, &client_random, 60),
        "QUIC lean token 不能用 TCP client_random 校验通过"
    );

    // TCP token 绑定 client_random
    let tcp_token = make_session_token(password, &client_random);
    // 用 QUIC_LEAN_BIND 校验必须失败
    assert!(
        !verify_session_token(password, &tcp_token, QUIC_LEAN_BIND, 60),
        "TCP token 不能用 QUIC_LEAN_BIND 校验通过"
    );
}

#[test]
fn random_substitution_attack_blocked() {
    // 攻击场景回归: 攻击者拦截合法客户端发起的会话 2 (随机数 R2, Token T2),
    // 将 ClientHello.random 替换为历史会话 1 的随机数 R1, 保留新鲜 Token T2。
    let password = "victim_password";
    let r1 = [0x11u8; 32];
    let r2 = [0x22u8; 32];

    // 客户端生成针对会话 2 (R2) 的新鲜 Token T2
    let t2 = make_session_token(password, &r2);

    // 服务端收到了被篡改后的 ClientHello, 其 random 字段为 R1, session_id 为 T2
    // 服务端以收到的 random (R1) 作为 bind 校验 T2: 必失败!
    let verified = verify_session_token(password, &t2, &r1, 60);
    assert!(!verified, "随机数替换攻击必须在 token 校验阶段被阻断 (fail-closed)");
}

#[test]
fn test_time_sync_bypass_and_replay_cache() {
    // We simulate time offset
    let _password = "pass";
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Setup TokenReplayCache directly
    let cache = TokenReplayCache::new();
    
    // Generate token with ts = now - 300 (client is 5 minutes behind)
    let token = [1u8; 32];
    let ts = now - 300;

    // The cache should accept it since we removed the duplicate SystemTime restriction in P0
    let accepted = cache.check_and_insert(ts, &token, 14);
    assert!(accepted, "Cache should accept token regardless of raw SystemTime difference");

    // But repeating the exact same token should fail (replay attack detected)
    let accepted_again = cache.check_and_insert(ts, &token, 14);
    assert!(!accepted_again, "Replay attack should be blocked");
}
