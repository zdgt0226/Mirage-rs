//! cipher agility 协商集成测试 (SPEC 场景 7-10)。
//! 用 duplex + 真实 CryptoReader/Writer 复刻 control.rs(服务端) + pool.rs(客户端) 的协商帧交换,
//! 但**注入** client_aes/server_aes (绕过真机 AES-NI 检测) 以确定性覆盖各组合。

use mirage_rs::crypto::aead::create_crypto_pair;
use mirage_rs::crypto::cipher::{self, Cipher};
use tokio::io::{duplex, split};

/// 跑一次完整协商 + 数据 round-trip。返回协商出的 cipher (已断言两端一致 + 数据正确)。
/// - `server_agility`: 服务端是否开 cipher_agility (广播 proto_ver=0x02)
/// - `client_new`: 客户端是否**支持** agility (老客户端=false, 收到 0x02 也不协商, 直发 target)
/// - `client_aes` / `server_aes`: 两端注入的 AES 能力
async fn simulate(server_agility: bool, client_new: bool, client_aes: bool, server_aes: bool) -> Cipher {
    let (c_end, s_end) = duplex(1 << 20);
    let (c_r, c_w) = split(c_end);
    let (s_r, s_w) = split(s_end);
    let pw = "shared-pw";
    let salt = [5u8; 32];
    let (mut cr, mut cw) = create_crypto_pair(c_r, c_w, pw, &salt, true); // client (initiator)
    let (mut sr, mut sw) = create_crypto_pair(s_r, s_w, pw, &salt, false); // server

    // ── 服务端 (control.rs::dispatch_authenticated 的协商片段) ──
    let server = tokio::spawn(async move {
        let mut ts = [0u8; 10];
        ts[0] = 0x01;
        ts[1] = if server_agility { cipher::PROTO_VER_AGILITY } else { cipher::PROTO_VER_LEGACY };
        sw.send_data(&ts).await.unwrap();

        let first = sr.recv_data().await.unwrap();
        let first = if server_agility {
            if let Some(reported) = cipher::parse_cipher_nego(&first) {
                let fin = cipher::negotiate(reported, server_aes);
                sw.send_data(&cipher::build_cipher_ack(fin)).await.unwrap();
                sw.rekey(fin);
                sr.rekey(fin);
                sr.recv_data().await.unwrap() // 真 target
            } else {
                first
            }
        } else {
            first
        };
        assert_eq!(&first, b"TARGET-example.com:443");
        sw.send_data(b"ECHO-BODY").await.unwrap();
        sw.cipher()
    });

    // ── 客户端 (pool.rs::connect_upstream 的协商片段) ──
    let ts = cr.recv_data().await.unwrap();
    let server_agility_seen =
        ts.len() == 10 && ts[0] == 0x01 && ts[1] == cipher::PROTO_VER_AGILITY;
    if client_new && server_agility_seen {
        cw.send_data(&cipher::build_cipher_nego(client_aes)).await.unwrap();
        let ack = cr.recv_data().await.unwrap();
        let fin = cipher::parse_cipher_ack(&ack).unwrap();
        cw.rekey(fin);
        cr.rekey(fin);
    }
    cw.send_data(b"TARGET-example.com:443").await.unwrap();
    assert_eq!(&cr.recv_data().await.unwrap(), b"ECHO-BODY");
    let client_cipher = cw.cipher();

    let server_cipher = server.await.unwrap();
    assert_eq!(client_cipher, server_cipher, "两端最终 cipher 必须一致");
    client_cipher
}

// 场景 7: 新客户端 ↔ 新服务端, 两端都 AES → 协商 AES-256-GCM
#[tokio::test]
async fn both_aes_negotiates_aes() {
    assert_eq!(simulate(true, true, true, true).await, Cipher::Aes256Gcm);
}

// 场景 8: 一端无 AES → 维持 ChaCha20
#[tokio::test]
async fn one_side_no_aes_stays_chacha() {
    assert_eq!(simulate(true, true, true, false).await, Cipher::ChaCha20Poly1305, "服务端无AES");
    assert_eq!(simulate(true, true, false, true).await, Cipher::ChaCha20Poly1305, "客户端无AES");
    assert_eq!(simulate(true, true, false, false).await, Cipher::ChaCha20Poly1305, "都无AES");
}

// 场景 9: 服务端 agility 关 (老服务端) → 不协商, 全程 ChaCha20 (即便两端都有 AES)
#[tokio::test]
async fn agility_off_stays_chacha() {
    assert_eq!(simulate(false, true, true, true).await, Cipher::ChaCha20Poly1305);
}

// 场景 10: 老客户端 (不协商) ↔ 新服务端 (agility 开) → 服务端首帧收到真 target, 不协商, ChaCha20
#[tokio::test]
async fn old_client_new_server_stays_chacha() {
    assert_eq!(simulate(true, false, true, true).await, Cipher::ChaCha20Poly1305);
}
