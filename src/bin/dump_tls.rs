use std::fs;
use mirage_rs::crypto::tls_raw;

fn main() {
    let session_id = [0u8; 32];
    let client_random = [0u8; 32];
    let sni = b"www.apple.com";
    
    // We don't care about the randomness matching exactly, because the extract_ja3 function 
    // will ignore the random bytes entirely. We just want structurally valid ClientHellos.
    
    let chrome = tls_raw::build_chrome(sni, &session_id, &client_random);
    let firefox = tls_raw::build_firefox(sni, &session_id, &client_random);
    let safari = tls_raw::build_safari(sni, &session_id, &client_random);
    
    let output = format!("{}\n{}\n{}", hex::encode(chrome), hex::encode(firefox), hex::encode(safari));
    fs::write("/tmp/rust_tls.hex", output).unwrap();
}
