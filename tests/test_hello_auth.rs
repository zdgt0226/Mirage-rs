use mirage_rs::crypto::hello_auth::{make_session_token, verify_session_token, TokenReplayCache};

#[test]
fn test_token_auth_roundtrip() {
    let password = "super_secret_password";
    
    // Generate
    let token = make_session_token(password);
    assert_eq!(token.len(), 32);
    
    // Verify valid token
    let mut token_arr = [0u8; 32];
    token_arr.copy_from_slice(&token);
    assert!(verify_session_token(password, &token_arr, 60));

    // Replay should fail
    assert!(!verify_session_token(password, &token_arr, 60));
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
