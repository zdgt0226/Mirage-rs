use mirage_rs::crypto::aead::create_crypto_pair;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8443").await.unwrap();
    println!("Mock upstream server listening on 8443");

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let (read_half, write_half) = stream.into_split();
            // is_initiator = false (Server side)
            let (mut reader, _writer) = create_crypto_pair(
                read_half, write_half, "my_secure_password", b"my_salt", false
            );
            
            // Read target header
            match reader.recv_data().await {
                Ok(target_data) => {
                    let target_len = u16::from_be_bytes([target_data[0], target_data[1]]) as usize;
                    let target = String::from_utf8_lossy(&target_data[2..2+target_len]);
                    println!("Mock Server accepted tunnel to: {}", target);
                }
                Err(e) => {
                    println!("Mock Server error reading target: {:?}", e);
                    return;
                }
            }
            
            // Discard data forever for upload throughput testing
            loop {
                match reader.recv_data().await {
                    Ok(_data) => {
                        // Discard
                    }
                    Err(_) => break,
                }
            }
        });
    }
}
