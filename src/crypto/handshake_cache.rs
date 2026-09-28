use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};
use rand::RngExt;
use ring::agreement::{self, EphemeralPrivateKey};
use ring::rand::SystemRandom;

static HANDSHAKE_CACHE: OnceLock<Mutex<Vec<Vec<u8>>>> = OnceLock::new();
static WARMING_UP: AtomicBool = AtomicBool::new(false);
/// 30 分钟刷新后台任务只 spawn 一次 (主动预热或懒预热谁先谁 spawn).
static REFRESH_SPAWNED: AtomicBool = AtomicBool::new(false);

struct WarmGuard;
impl Drop for WarmGuard {
    fn drop(&mut self) {
        WARMING_UP.store(false, Ordering::SeqCst);
    }
}

fn cache() -> &'static Mutex<Vec<Vec<u8>>> {
    HANDSHAKE_CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

/// 模板是否**含齐客户端握手所需的三种 content-type**: 0x16 (ServerHello) + 0x14
/// (ChangeCipherSpec) + 0x17 (加密 flight)。
///
/// 为什么必须齐: 客户端 `pool::read_server_handshake` 循环读记录**直到集齐这三种**才
/// 返回、才发 fake tail。若服务端回放的模板缺其一 (如 camouflage_host 是 TLS 1.2 站,
/// 其 ServerHello flight 全是 0x16 Handshake 记录、无中间盒兼容 0x14/无加密 0x17),
/// 客户端会永远等不到 → 握手超时不发 tail → 服务端 `read_exact tail timed out`。
/// 故 fetch 到的不完整模板必须丢弃, 回落到恒完整的 `fallback_server_hello`。
///
/// 顺带校验帧完整性: 每条 record 的 body 必须在 buf 内 (无有头无体的截断帧)。
pub(crate) fn template_is_complete(t: &[u8]) -> bool {
    let mut pos = 0usize;
    let (mut sh, mut ccs, mut enc) = (false, false, false);
    while pos + 5 <= t.len() {
        let ct = t[pos];
        let len = u16::from_be_bytes([t[pos + 3], t[pos + 4]]) as usize;
        if pos + 5 + len > t.len() {
            return false; // 截断帧: 有头无体
        }
        match ct {
            0x16 => sh = true,
            0x14 => ccs = true,
            0x17 => enc = true,
            _ => {}
        }
        pos += 5 + len;
    }
    // 必须**恰好**消费完整个 buf (无尾部残字节) 且三种齐。
    pos == t.len() && sh && ccs && enc
}

/// 并发拉 5 个真实 ServerHello 模板, 收集成功的.
async fn fetch_batch(host: &str) -> Vec<Vec<u8>> {
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let h = host.to_string();
        set.spawn(async move { fetch_real_server_hello(&h).await });
    }
    let mut out = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Ok(t)) = res {
            out.push(t);
        }
    }
    out
}

/// 启动一次性的 30 分钟刷新后台任务 (幂等, 全局只一个).
fn spawn_refresh_task(camouflage_host: &str) {
    if REFRESH_SPAWNED.swap(true, Ordering::SeqCst) {
        return;
    }
    let host = camouflage_host.to_string();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1800)).await;
            let templates = fetch_batch(&host).await;
            if !templates.is_empty() {
                *cache().lock().await = templates;
            }
        }
    });
}

/// 服务端启动时主动预热 HandshakeCache: 抢先拉真实模板填充 cache + 启动刷新任务.
/// 消除懒预热的冷启动窗口 —— 首个连接不再触发 fetch 或拿 fallback, 避免重启后
/// 头几个连接时序异常被探针识别. 应在 accept loop 之前 await.
///
/// camouflage 不可达时最多阻塞 ~5s (fetch 内建超时) 后返回, cache 留空由懒路径
/// 在首连接时重试 (降级但不阻塞启动过久).
pub async fn prewarm(camouflage_host: &str) {
    if !cache().lock().await.is_empty() {
        return; // 已有模板
    }
    if WARMING_UP.swap(true, Ordering::SeqCst) {
        return; // 已在预热 (启动阶段理论上不会撞)
    }
    let _guard = WarmGuard;
    info!("Prewarming HandshakeCache from {} at startup", camouflage_host);
    let templates = fetch_batch(camouflage_host).await;
    if !templates.is_empty() {
        let mut guard = cache().lock().await;
        guard.extend(templates);
        info!("HandshakeCache prewarmed with {} real templates", guard.len());
    } else {
        warn!(
            "HandshakeCache prewarm got no templates from {} — will retry lazily on first connection",
            camouflage_host
        );
    }
    spawn_refresh_task(camouflage_host);
}

pub async fn get_server_hello(camouflage_host: &str, client_hello: &[u8]) -> Vec<u8> {
    get_server_hello_pfs(camouflage_host, client_hello, None).await.0
}

/// 同 `get_server_hello`, 但可用 `server_random_override` 把回放模板的 ServerHello.random
/// (flight[11..43]) 覆写成指定 32B —— PFS 用它注入服务端一次性 X25519 公钥 (见 crypto::pfs)。
/// 返回 (flight, 实际发出的 server_random)，保证线上发出的 random 与参与密钥派生的 random 严格一致。
/// 覆写在**所有返回路径末尾**统一施加, 故 patch/fallback 各分支都生效。
pub async fn get_server_hello_pfs(
    camouflage_host: &str,
    client_hello: &[u8],
    server_random_override: Option<&[u8; 32]>,
) -> (Vec<u8>, [u8; 32]) {
    let client_session_id = get_session_id(client_hello).unwrap_or(&[]);

    // 末尾统一覆写 ServerHello.random 并返回 (flight, server_random)。
    let apply = |flight: Vec<u8>| -> (Vec<u8>, [u8; 32]) {
        apply_server_random(flight, server_random_override)
    };

    if cache().lock().await.is_empty() {
        // 主动预热正常应已填充; 走到这说明预热失败或未运行 —— 懒预热兜底.
        if !WARMING_UP.swap(true, Ordering::SeqCst) {
            let _guard = WarmGuard;
            info!("HandshakeCache empty, lazy-warming from {}", camouflage_host);
            let templates = fetch_batch(camouflage_host).await;
            let mut guard = cache().lock().await;
            if !templates.is_empty() {
                guard.extend(templates);
            } else {
                // WARN 而非 ERROR: 这是**优雅降级**, 非故障 —— 拉不到真模板 (无外网/camouflage
                // 不可达的 VPS/容器很常见) 就用恒完整的合成 fallback, 握手照常。降级为 WARN 免得
                // 无外网服务端满屏吓人的 ERROR。
                warn!("Failed to fetch any templates from {}. Using synthetic fallback (握手不受影响).", camouflage_host);
                guard.push(fallback_server_hello(client_hello, client_session_id));
            }
            drop(guard);
            spawn_refresh_task(camouflage_host);
        } else {
            // 别人正在预热, 等它完成
            let mut attempts = 0;
            while WARMING_UP.load(Ordering::SeqCst) && attempts < 50 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                attempts += 1;
            }
            if cache().lock().await.is_empty() {
                let fb = fallback_server_hello(client_hello, client_session_id);
                return apply(patch_server_hello(&fb, client_session_id));
            }
        }
    }

    let guard = cache().lock().await;
    let template_idx = rand::rng().random_range(0..guard.len());
    let response = guard[template_idx].clone();
    drop(guard);

    apply(patch_server_hello(&response, client_session_id))
}

async fn fetch_real_server_hello(host: &str) -> anyhow::Result<Vec<u8>> {
    let target = crate::net_util::host_with_default_port(host, 443);

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&target)
    ).await??;

    let mut session_id = [0u8; 32];
    rand::fill(&mut session_id);
    let hostname = crate::net_util::extract_hostname(host);
    // 模板 fetch **固定用 OkHttp CH** (无 MLKEM, 只提供 X25519/P256/P384) —— 这三个曲线是
    // 所有 profile (Chrome/FF/OkHttp) 的**交集**, camouflage 站据此协商出的曲线 (通常 X25519)
    // 任何 profile 的客户端都提供过 → 回放的 ServerHello 恒自洽、不会"选了没提供的曲线"= 非法 TLS。
    // 代价: Chrome/FF 客户端拿到的是 X25519 (而非 MLKEM) ServerHello —— 完全正常的协商 (大量
    // 服务器不支持 MLKEM), 非可疑。换来对无 MLKEM 的 OkHttp profile 也自洽, 免去对变长 KEM
    // 密文做 ServerHello 字节手术。
    let mut client_random = [0u8; 32];
    rand::fill(&mut client_random);
    let ch = crate::crypto::tls_raw::build_okhttp(hostname.as_bytes(), &session_id, &client_random);

    stream.write_all(&ch).await?;

    let mut buf = Vec::new();
    let mut header = [0u8; 5];
    
    // Read ServerHello (0x16)。超时/读不全绝不能返回 Ok(空 buf) —— fetch_batch
    // 无长度过滤会把它当合法模板灌进 cache 毒化全局 (所有连接随机取到空/残破模板 →
    // 客户端 read_server_handshake 校验崩)。抖动丢包时返回 Err 让上层回落 fallback。
    if tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut header)).await.is_err() {
        return Err(anyhow::anyhow!("timeout reading ServerHello header from camouflage host"));
    }
    // 首记录必须是 Handshake(0x16). 若对端回 Alert(0x15) 说明 ClientHello 被拒,
    // 决不能把 alert 当模板缓存 (会毒化 cache 让所有客户端收到 alert). 返回 Err
    // 让上层回落到 fallback_server_hello.
    if header[0] != 0x16 {
        return Err(anyhow::anyhow!(
            "camouflage host rejected ClientHello (first record type 0x{:02x}, not Handshake)",
            header[0]
        ));
    }
    buf.extend_from_slice(&header);
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    if tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut body)).await.is_err() {
        return Err(anyhow::anyhow!("timeout reading ServerHello body (len={}) from camouflage host", len));
    }
    buf.extend_from_slice(&body);

    // Read subsequent flights (ChangeCipherSpec, ApplicationData/EncryptedExtensions)。
    // header 必须推迟到 body 也读全后再与 body 一起 append —— 否则 body 读超时 break
    // 会在 buf 尾留下有头无体的截断 record, 缓存后客户端解析到该帧报 TLS decode 错。
    // 只追加"完整整数帧", 超时则 buf 停在此前完好帧边界。
    //
    // **读到集齐 0x16+0x14+0x17 才停** (封顶 8 帧防坏站吊死)。旧版固定读 2 帧, 遇到把
    // flight 拆成多条记录的站 (或 TLS 1.2 站) 会漏掉 0x14/0x17, 缓存出不完整模板 → 客户端
    // read_server_handshake 永等不到三型齐、不发 tail → 服务端 read_exact tail timed out。
    // 见 template_is_complete。
    for _ in 0..8 {
        if template_is_complete(&buf) {
            break;
        }
        if tokio::time::timeout(std::time::Duration::from_secs(2), stream.read_exact(&mut header)).await.is_ok() {
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0u8; len];
            if tokio::time::timeout(std::time::Duration::from_secs(2), stream.read_exact(&mut body)).await.is_ok() {
                buf.extend_from_slice(&header);
                buf.extend_from_slice(&body);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    // 完整性门禁: 模板缺三型之一决不缓存 (否则毒化 cache)。返回 Err 让上层回落到恒完整的
    // fallback_server_hello。空 buf 也在此被挡 (不完整)。
    if !template_is_complete(&buf) {
        return Err(anyhow::anyhow!(
            "camouflage host template incomplete (missing 0x16/0x14/0x17 or truncated); {} bytes",
            buf.len()
        ));
    }

    // 校验 ServerHello 的 key_share 是可重生成的 group (X25519 32B 或 P-256 65B),
    // 否则 key_share 跨连接恒定, 当作不合格模板返回 Err (让上层回落 fallback)。
    match key_share_group(&buf) {
        Some((0x001d, 32)) | Some((0x0017, 65)) => {}
        Some((g, len)) => {
            return Err(anyhow::anyhow!(
                "camouflage host template has unsupported key_share group 0x{g:04x} (len {len})"
            ));
        }
        None => {
            return Err(anyhow::anyhow!(
                "camouflage host template missing or malformed key_share extension"
            ));
        }
    }

    Ok(buf)
}

/// 覆写 ServerHello.random (flight[11..43])。真 TLS 的 ServerHello.random **每次握手全新**,
/// 故回放模板必须逐连接改写它, 否则同模板所有连接共享一个 random = 被动可辨指纹。
/// - PFS 开 (`override_random` = Some): 注入服务端一次性 X25519 公钥 (客户端读它做 ECDH, 见 crypto::pfs)。
/// - PFS 关 (None): 填 32B 新随机, 沿 handshake → control 管道传递参与会话密钥派生。
///
/// 返回 (改写后的 flight, 实际注入的 server_random)。
/// flight 恒以 0x16 ServerHello 记录起头; random 在 [11..43] (5B record + 4B hs + 2B version)。
fn apply_server_random(
    mut flight: Vec<u8>,
    override_random: Option<&[u8; 32]>,
) -> (Vec<u8>, [u8; 32]) {
    let mut server_random = [0u8; 32];
    if flight.len() >= 43 && flight[0] == 0x16 {
        match override_random {
            Some(pk) => {
                server_random = *pk;
                flight[11..43].copy_from_slice(pk);
            }
            None => {
                rand::fill(&mut server_random);
                flight[11..43].copy_from_slice(&server_random);
            }
        }
    }
    (flight, server_random)
}

/// 为 ServerHello 生成指定 group 的全新合法公钥。
/// - X25519 (0x001d): ring 生成 32B 公钥。真服务器公钥最高位 (RFC 7748 u 坐标 < 2^255-19) 恒为 0, 保持原样不随机化。
/// - ECDH_P256 (0x0017): ring 生成 65B 未压缩公钥 (0x04 || X || Y)。
/// - 未知 group 返回 None (调用方保持原样)。
fn generate_key_share(group: u16) -> Option<Vec<u8>> {
    let rng = SystemRandom::new();
    match group {
        0x001d => {
            let private = EphemeralPrivateKey::generate(&agreement::X25519, &rng).ok()?;
            let pk = private.compute_public_key().ok()?;
            let pk_bytes = pk.as_ref();
            if pk_bytes.len() == 32 {
                Some(pk_bytes.to_vec())
            } else {
                None
            }
        }
        0x0017 => {
            let private = EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).ok()?;
            let pk = private.compute_public_key().ok()?;
            let pk_bytes = pk.as_ref();
            if pk_bytes.len() == 65 {
                Some(pk_bytes.to_vec())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// 解析 ServerHello 扩展中的 key_share (0x0033):
/// 返回 Option<(group, key_len, key_start_offset)>
fn key_share_info(flight: &[u8]) -> Option<(u16, usize, usize)> {
    if flight.len() < 9 || flight[0] != 0x16 {
        return None;
    }
    let sh_rec_len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let rec_end = 5 + sh_rec_len;
    if rec_end > flight.len() || rec_end < 9 {
        return None;
    }
    // HandshakeType 必须是 ServerHello (0x02)
    if flight[5] != 0x02 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, flight[6], flight[7], flight[8]]) as usize;
    let hs_end = 9 + hs_len;
    if hs_end > rec_end || hs_end < 44 {
        return None;
    }
    let sid_len = flight[43] as usize;
    let cipher_off = 44 + sid_len;
    if cipher_off + 5 > hs_end {
        return None;
    }
    let ext_len_off = cipher_off + 3;
    let ext_len = u16::from_be_bytes([flight[ext_len_off], flight[ext_len_off + 1]]) as usize;
    let ext_start = ext_len_off + 2;
    let ext_end = ext_start + ext_len;
    if ext_end > hs_end {
        return None;
    }

    let mut curr = ext_start;
    while curr + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([flight[curr], flight[curr + 1]]);
        let ext_data_len = u16::from_be_bytes([flight[curr + 2], flight[curr + 3]]) as usize;
        let data_start = curr + 4;
        let data_end = data_start + ext_data_len;
        if data_end > ext_end {
            break;
        }
        if ext_type == 0x0033 {
            // key_share ServerHello: group (2B) + key_exchange_len (2B) + key_exchange
            if ext_data_len >= 4 {
                let group = u16::from_be_bytes([flight[data_start], flight[data_start + 1]]);
                let klen = u16::from_be_bytes([flight[data_start + 2], flight[data_start + 3]]) as usize;
                let key_start = data_start + 4;
                let key_end = key_start + klen;
                if key_end == data_end {
                    return Some((group, klen, key_start));
                }
            }
            break;
        }
        curr = data_end;
    }
    None
}

/// 解析 ServerHello 扩展中的 key_share group 与公钥长度: (group, klen)。
pub(crate) fn key_share_group(flight: &[u8]) -> Option<(u16, usize)> {
    key_share_info(flight).map(|(g, klen, _)| (g, klen))
}

/// 解析 ServerHello 扩展, 查找 key_share (0x0033) 并用全新真公钥替换 key_exchange 内容。
/// 全程边界检查, 遇到越界或畸形结构安全退回 (不改 key_share)。
fn patch_key_share(buf: &mut [u8], _sh_rec_len: usize) {
    if let Some((group, klen, key_start)) = key_share_info(buf) {
        let key_end = key_start + klen;
        if (group == 0x001d && klen == 32) || (group == 0x0017 && klen == 65) {
            if let Some(new_key) = generate_key_share(group) {
                buf[key_start..key_end].copy_from_slice(&new_key);
            }
        }
    }
}

/// 遍历 ServerHello 之后的所有记录: 记录头保持, content type 0x17 (ApplicationData) 的记录体
/// 替换为等长随机字节; 0x14 (CCS) 不动。按记录头长度遍历, 遇到截断/畸形记录停止遍历保持剩余原样。
fn randomize_encrypted_records(buf: &mut [u8], sh_rec_len: usize) {
    let mut pos = 5 + sh_rec_len;
    while pos + 5 <= buf.len() {
        let ct = buf[pos];
        let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        let body_end = pos + 5 + rec_len;
        if body_end > buf.len() {
            break; // 截断/畸形记录, 停止遍历保持剩余原样
        }
        if ct == 0x17 {
            rand::fill(&mut buf[pos + 5..body_end]);
        }
        pos = body_end;
    }
}

fn patch_server_hello(flight: &[u8], client_session_id: &[u8]) -> Vec<u8> {
    if flight.len() < 44 || flight[0] != 0x16 {
        return flight.to_vec();
    }
    
    let sid_len = flight[43] as usize;
    if flight.len() < 44 + sid_len {
        return flight.to_vec();
    }
    
    let diff = client_session_id.len() as isize - sid_len as isize;
    
    let mut result = Vec::with_capacity(flight.len() + client_session_id.len());
    result.extend_from_slice(&flight[..43]);
    result.push(client_session_id.len() as u8);
    result.extend_from_slice(client_session_id);
    result.extend_from_slice(&flight[44 + sid_len..]);
    
    // Server Random
    let mut new_random = [0u8; 32];
    rand::fill(&mut new_random);
    result[11..43].copy_from_slice(&new_random);
    
    let old_record_len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let old_hs_len = u32::from_be_bytes([0, flight[6], flight[7], flight[8]]) as usize;
    
    // clamp 到各字段合法范围, 别让负值/越界静默回绕成乱长度 (record 16bit, hs 24bit)。
    // 正常输入 (session_id <= 32B) 恒落区间内, clamp 只是防御。
    let new_record_len = (old_record_len as isize + diff).clamp(0, u16::MAX as isize) as u16;
    let new_hs_len = (old_hs_len as isize + diff).clamp(0, 0xFF_FFFF) as u32;
    
    result[3] = (new_record_len >> 8) as u8;
    result[4] = (new_record_len & 0xFF) as u8;
    
    result[6] = (new_hs_len >> 16) as u8;
    result[7] = (new_hs_len >> 8) as u8;
    result[8] = (new_hs_len & 0xFF) as u8;

    patch_key_share(&mut result, new_record_len as usize);
    randomize_encrypted_records(&mut result, new_record_len as usize);
    
    result
}

fn get_session_id(client_hello: &[u8]) -> Option<&[u8]> {
    if client_hello.len() < 44 { return None; }
    let sid_len = client_hello[43] as usize;
    if client_hello.len() >= 44 + sid_len {
        Some(&client_hello[44..44+sid_len])
    } else {
        None
    }
}

/// 从 ClientHello 选一个客户端**确实提供**的 TLS 1.3 cipher (否则真实服务器不会
/// 选它没提供的套件, 浅层探针可识破). 偏好 AES256>AES128>ChaCha; 解析失败退 1301.
fn pick_cipher(client_hello: &[u8]) -> [u8; 2] {
    let default = [0x13, 0x01];
    if client_hello.len() < 44 { return default; }
    let sid_len = client_hello[43] as usize;
    let off = 44 + sid_len;
    if client_hello.len() < off + 2 { return default; }
    let cl = u16::from_be_bytes([client_hello[off], client_hello[off + 1]]) as usize;
    let end = (off + 2 + cl).min(client_hello.len());
    let ciphers = &client_hello[off + 2..end];
    // as_chunks::<2> 而非 chunks_exact(2): 常量块大小, 新 clippy 要求前者 (语义同, 丢末尾奇数字节)。
    let (pairs, _rem) = ciphers.as_chunks::<2>();
    for pref in [[0x13u8, 0x02], [0x13, 0x01], [0x13, 0x03]] {
        if pairs.contains(&pref) {
            return pref;
        }
    }
    default
}

/// 合成 ServerHello flight (camouflage_host 不可达时的最后回落).
///
/// ⚠️ 根本限制: 无真实后端, 无法产出有效证书/CertVerify/Finished. 完成完整握手的
/// **深度探针必然识破** (推导密钥解密加密 flight → MAC 失败). 本函数只求骗过被动
/// 观测 + 浅层探针 (只读 ServerHello 不完成握手): 结构合法 + 尺寸可信.
/// 真正的解是保持 camouflage 可达 / 多域名备份.
fn fallback_server_hello(client_hello: &[u8], client_session_id: &[u8]) -> Vec<u8> {
    let cipher = pick_cipher(client_hello);

    let mut hs_body = Vec::with_capacity(80);
    hs_body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    let mut rnd = [0u8; 32];
    rand::fill(&mut rnd);
    hs_body.extend_from_slice(&rnd); // server_random
    hs_body.push(client_session_id.len() as u8);
    hs_body.extend_from_slice(client_session_id); // echo legacy_session_id
    hs_body.extend_from_slice(&cipher); // cipher_suite
    hs_body.push(0x00); // compression_method

    // extensions: supported_versions(TLS1.3) + key_share(X25519 合法 32B 公钥)
    let ks = generate_key_share(0x001d).unwrap_or_else(|| {
        let mut k = vec![0u8; 32];
        rand::fill(&mut k[..]);
        k[31] &= 0x7f;
        k
    });
    let mut exts = Vec::with_capacity(48);
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions
    exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]); // key_share X25519 len=32
    exts.extend_from_slice(&ks);
    hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&exts);

    let mut out = Vec::with_capacity(hs_body.len() + 4096);
    // ServerHello record
    out.extend_from_slice(&[0x16, 0x03, 0x03]);
    out.extend_from_slice(&((4 + hs_body.len()) as u16).to_be_bytes());
    out.push(0x02); // Handshake: ServerHello
    out.extend_from_slice(&(hs_body.len() as u32).to_be_bytes()[1..4]);
    out.extend_from_slice(&hs_body);

    // ChangeCipherSpec (兼容)
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

    // ApplicationData: 模拟加密的 {EncryptedExtensions, Certificate, CertVerify,
    // Finished} flight. 真实约 2-5KB (证书链主导). 加密内容不可读, 随机字节 +
    // 可信尺寸即可骗过被动/浅层. 用 ~2.8-4.2KB 随机, 单条 record (< 16KB 上限).
    let flight_len = 2800 + fastrand::usize(0..1400);
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(flight_len as u16).to_be_bytes());
    let base = out.len();
    out.resize(base + flight_len, 0);
    rand::fill(&mut out[base..]);

    out
}

#[cfg(test)]
mod tests {
    use super::{apply_server_random, fallback_server_hello, generate_key_share, key_share_group, patch_server_hello, pick_cipher};

    #[test]
    fn server_random_per_connection_and_pfs_override() {
        // 造个最小合法起头的 flight: 0x16 + 占位到 ≥43B, random 段全 0。
        let base = {
            let mut v = vec![0u8; 60];
            v[0] = 0x16;
            v
        };
        // PFS 关: 两次覆写 random 应各不相同 (每连接新随机), 且都非全 0 (确实写了)。
        let (a, r_a) = apply_server_random(base.clone(), None);
        let (b, r_b) = apply_server_random(base.clone(), None);
        assert_ne!(&a[11..43], &b[11..43], "PFS 关时 ServerHello.random 必须每连接不同");
        assert_ne!(&a[11..43], &[0u8; 32], "random 必须被真正写入");
        assert_eq!(&a[11..43], &r_a);
        assert_eq!(&b[11..43], &r_b);
        // PFS 开: random == 注入的公钥。
        let pk = [0x5Au8; 32];
        let (c, r_c) = apply_server_random(base.clone(), Some(&pk));
        assert_eq!(&c[11..43], &pk, "PFS 开时 random 必须 == 注入的 X25519 公钥");
        assert_eq!(r_c, pk);
        // 非 ServerHello (首字节非 0x16) 不动。
        let mut not_sh = base.clone();
        not_sh[0] = 0x17;
        let (d, r_d) = apply_server_random(not_sh.clone(), None);
        assert_eq!(d, not_sh);
        assert_eq!(r_d, [0u8; 32]);
    }

    // 构造一个最小合法 ClientHello 骨架, cipher 列表 = [1301,1302,1303].
    fn make_client_hello() -> Vec<u8> {
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x00]; // record header (len 占位)
        let mut hs = vec![0x01, 0x00, 0x00, 0x00]; // hs type + len 占位
        hs.extend_from_slice(&[0x03, 0x03]); // version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(32); // sid_len
        hs.extend_from_slice(&[0xAB; 32]); // session_id (token)
        hs.extend_from_slice(&6u16.to_be_bytes()); // cipher_len
        hs.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]); // ciphers
        hs.extend_from_slice(&[0x01, 0x00]); // compression
        hs.extend_from_slice(&[0x00, 0x00]); // extensions len = 0
        let body_len = (hs.len() - 4) as u32;
        hs[1..4].copy_from_slice(&body_len.to_be_bytes()[1..4]);
        let rec_len = hs.len() as u16;
        ch[3..5].copy_from_slice(&rec_len.to_be_bytes());
        ch.extend_from_slice(&hs);
        ch
    }

    fn u16(b: &[u8], i: usize) -> usize {
        ((b[i] as usize) << 8) | b[i + 1] as usize
    }

    #[test]
    fn pick_cipher_from_offered() {
        let ch = make_client_hello();
        // 偏好 1302 (AES256), 且必须在提供列表里
        assert_eq!(pick_cipher(&ch), [0x13, 0x02]);
    }

    #[test]
    fn fallback_is_structurally_valid() {
        let ch = make_client_hello();
        let sid = [0xABu8; 32];
        let sh = fallback_server_hello(&ch, &sid);

        // ---- ServerHello record ----
        assert_eq!(sh[0], 0x16, "record type Handshake");
        let rec_len = u16(&sh, 3);
        assert_eq!(sh[5], 0x02, "handshake type ServerHello");
        // session_id 回显 (offset 43 = sid_len, 44.. = sid)
        assert_eq!(sh[43], 32, "echo sid_len");
        assert_eq!(&sh[44..76], &sid, "echo session_id");
        // cipher (紧跟 sid) = 客户端提供的
        let cipher = [sh[76], sh[77]];
        assert!(
            [[0x13, 0x01], [0x13, 0x02], [0x13, 0x03]].contains(&cipher),
            "cipher 必须是 TLS1.3 且客户端提供的"
        );

        // ---- 遍历 extensions, 校验 key_share 合法 ----
        // hs_body: 03 03 | random32 | sid_len(1)+sid | cipher(2) | comp(1) | extlen(2) | exts
        let ext_len_off = 76 + 2 + 1; // cipher(2)+comp(1) 之后
        let ext_len = u16(&sh, ext_len_off);
        let mut i = ext_len_off + 2;
        let ext_end = i + ext_len;
        let mut saw_keyshare = false;
        let mut saw_supver = false;
        while i + 4 <= ext_end {
            let et = u16(&sh, i);
            let el = u16(&sh, i + 2);
            let data = &sh[i + 4..i + 4 + el];
            if et == 0x0033 {
                // ServerHello key_share: group(2) + key_len(2) + key
                saw_keyshare = true;
                let group = u16(data, 0);
                let klen = u16(data, 2);
                assert_eq!(group, 0x001d, "X25519");
                assert_eq!(klen, 32, "X25519 公钥 32 字节");
                assert_eq!(data.len(), 4 + 32, "key_share 内容长度自洽 (旧版畸形已修)");
            }
            if et == 0x002b {
                saw_supver = true;
                assert_eq!(data, &[0x03, 0x04], "supported_versions = TLS 1.3");
            }
            i += 4 + el;
        }
        assert!(saw_keyshare && saw_supver, "必须有 key_share + supported_versions");

        // ---- CCS + ApplicationData flight ----
        let mut j = 5 + rec_len; // ServerHello record 之后
        assert_eq!(&sh[j..j + 6], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01], "ChangeCipherSpec");
        j += 6;
        assert_eq!(sh[j], 0x17, "ApplicationData");
        let flight_len = u16(&sh, j + 3);
        assert!(
            (2800..=4200).contains(&flight_len),
            "加密 flight 应 ~2.8-4.2KB (旧版仅 21B), 实际 {}",
            flight_len
        );
        assert_eq!(j + 5 + flight_len, sh.len(), "总长度自洽");
    }

    use super::{fetch_real_server_hello, template_is_complete};
    #[allow(unused_imports)]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 拼一条 TLS record: [ct][03 03][len][body(len 个 0)]。
    fn rec(ct: u8, len: usize) -> Vec<u8> {
        let mut r = vec![ct, 0x03, 0x03];
        r.extend_from_slice(&(len as u16).to_be_bytes());
        r.extend(std::iter::repeat_n(0u8, len));
        r
    }

    #[test]
    fn fallback_template_is_complete() {
        let ch = make_client_hello();
        let fb = fallback_server_hello(&ch, &[0xAB; 32]);
        assert!(template_is_complete(&fb), "fallback 必须含齐 0x16+0x14+0x17");
    }

    #[test]
    fn complete_three_types_ok() {
        let mut t = rec(0x16, 40);
        t.extend(rec(0x14, 1));
        t.extend(rec(0x17, 100));
        assert!(template_is_complete(&t));
    }

    #[test]
    fn tls12_all_handshake_records_incomplete() {
        // TLS 1.2 站: ServerHello + Certificate + SKE + Done 全是 0x16, 无 0x14/0x17。
        let mut t = rec(0x16, 40);
        t.extend(rec(0x16, 800));
        t.extend(rec(0x16, 300));
        t.extend(rec(0x16, 4));
        assert!(!template_is_complete(&t), "全 0x16 (缺 CCS/加密) 必须判不完整");
    }

    #[test]
    fn missing_enc_incomplete() {
        let mut t = rec(0x16, 40);
        t.extend(rec(0x14, 1));
        assert!(!template_is_complete(&t), "缺 0x17 应判不完整");
    }

    #[test]
    fn missing_ccs_incomplete() {
        let mut t = rec(0x16, 40);
        t.extend(rec(0x17, 100));
        assert!(!template_is_complete(&t), "缺 0x14 应判不完整");
    }

    #[test]
    fn trailing_junk_incomplete() {
        // 三型齐, 但末尾拖 2B 垃圾 (不足一条记录头, 循环不处理)。
        // 只有 `pos == t.len()` 尾部等长检能挡, 截断守卫挡不到。
        let mut t = rec(0x16, 40);
        t.extend(rec(0x14, 1));
        t.extend(rec(0x17, 100));
        t.extend_from_slice(&[0xFF, 0xFF]);
        assert!(!template_is_complete(&t), "尾部残字节应判不完整");
    }

    #[test]
    fn truncated_record_incomplete() {
        // 记录头声称 body 100B, 实际只给 10B → 截断帧, 判不完整。
        let mut t = rec(0x16, 40);
        t.extend(rec(0x14, 1));
        let mut bad = vec![0x17, 0x03, 0x03];
        bad.extend_from_slice(&100u16.to_be_bytes());
        bad.extend(std::iter::repeat_n(0u8, 10)); // 只 10B, 不足 100
        t.extend(bad);
        assert!(!template_is_complete(&t), "截断帧应判不完整");
    }

    /// fetch 边界端到端: 假 camouflage 站只回一条 ServerHello(0x16) 单帧 (模拟拆帧/
    /// TLS1.2 站), `fetch_real_server_hello` 必须判不完整、返回 Err —— 决不能把它当合法
    /// 模板灌进 cache 毒化全局。这正是用户 read_exact tail timed out 的复现根因。
    #[tokio::test]
    async fn fetch_rejects_serverhello_only_template() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // 读掉 ClientHello
            // 只回一条 ServerHello record: [0x16][03 03][len=48][48B]。缺 0x14/0x17。
            let mut sh = vec![0x16, 0x03, 0x03];
            sh.extend_from_slice(&48u16.to_be_bytes());
            sh.extend(std::iter::repeat_n(0u8, 48));
            let _ = sock.write_all(&sh).await;
            // 保持连接开着让后续读走超时路径, 不主动关。
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let res = fetch_real_server_hello(&addr.to_string()).await;
        assert!(res.is_err(), "只回 ServerHello 的不完整模板必须被拒, 得到: {:?}", res.map(|b| b.len()));
    }

    fn extract_key_share(flight: &[u8]) -> Option<(u16, Vec<u8>)> {
        if flight.len() < 5 || flight[0] != 0x16 { return None; }
        let rec_len = u16(flight, 3);
        if flight.len() < 5 + rec_len || rec_len < 44 { return None; }
        let sid_len = flight[43] as usize;
        let cipher_off = 44 + sid_len;
        if cipher_off + 5 > 5 + rec_len { return None; }
        let ext_len_off = cipher_off + 3;
        let ext_len = u16(flight, ext_len_off);
        let ext_start = ext_len_off + 2;
        let ext_end = ext_start + ext_len;
        if ext_end > 5 + rec_len { return None; }
        let mut curr = ext_start;
        while curr + 4 <= ext_end {
            let et = u16(flight, curr);
            let el = u16(flight, curr + 2);
            let dstart = curr + 4;
            let dend = dstart + el;
            if dend > ext_end { break; }
            if et == 0x0033 && el >= 4 {
                let group = u16(flight, dstart) as u16;
                let klen = u16(flight, dstart + 2);
                if dstart + 4 + klen == dend {
                    return Some((group, flight[dstart + 4..dend].to_vec()));
                }
            }
            curr = dend;
        }
        None
    }

    fn extract_enc_body(flight: &[u8]) -> Option<Vec<u8>> {
        if flight.len() < 5 || flight[0] != 0x16 { return None; }
        let sh_len = u16(flight, 3);
        let mut pos = 5 + sh_len;
        while pos + 5 <= flight.len() {
            let ct = flight[pos];
            let rlen = u16(flight, pos + 3);
            let body_end = pos + 5 + rlen;
            if body_end > flight.len() { break; }
            if ct == 0x17 {
                return Some(flight[pos + 5..body_end].to_vec());
            }
            pos = body_end;
        }
        None
    }

    #[test]
    fn patch_server_hello_twice_different_keys_and_bodies_same_headers() {
        let ch = make_client_hello();
        let orig_sid = [0x11u8; 32];
        let fb = fallback_server_hello(&ch, &orig_sid);

        let new_sid = [0x22u8; 32];
        let p1 = patch_server_hello(&fb, &new_sid);
        let p2 = patch_server_hello(&fb, &new_sid);

        // 总长度与所有记录头长度不变
        assert_eq!(p1.len(), fb.len(), "总长度不变");
        assert_eq!(p2.len(), fb.len(), "总长度不变");

        let sh_len_fb = u16(&fb, 3);
        let sh_len_p1 = u16(&p1, 3);
        let sh_len_p2 = u16(&p2, 3);
        assert_eq!(sh_len_p1, sh_len_fb, "ServerHello 记录长度不变");
        assert_eq!(sh_len_p2, sh_len_fb, "ServerHello 记录长度不变");

        // CCS 记录头与内容不变
        let ccs_pos = 5 + sh_len_fb;
        assert_eq!(&p1[ccs_pos..ccs_pos + 6], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        assert_eq!(&p2[ccs_pos..ccs_pos + 6], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

        // 0x17 记录头不变
        let enc_pos = ccs_pos + 6;
        assert_eq!(&p1[enc_pos..enc_pos + 5], &fb[enc_pos..enc_pos + 5], "0x17 记录头不变");
        assert_eq!(&p2[enc_pos..enc_pos + 5], &fb[enc_pos..enc_pos + 5], "0x17 记录头不变");

        // session_id/random 逻辑不回归
        assert_eq!(&p1[44..76], &new_sid, "p1 session_id 已替换");
        assert_eq!(&p2[44..76], &new_sid, "p2 session_id 已替换");
        assert_ne!(&p1[11..43], &p2[11..43], "两次 patch 的 server random 必须不同");

        // key_share 公钥不同且合法
        let (g1, ks1) = extract_key_share(&p1).expect("p1 须提取到 key_share");
        let (g2, ks2) = extract_key_share(&p2).expect("p2 须提取到 key_share");
        assert_eq!(g1, 0x001d);
        assert_eq!(g2, 0x001d);
        assert_eq!(ks1.len(), 32);
        assert_eq!(ks2.len(), 32);
        assert_ne!(ks1, ks2, "两次 patch 的 key_share 公钥必须不同");
        assert_eq!(ks1[31] & 0x80, 0, "p1 key_share 最高位必须为 0");
        assert_eq!(ks2[31] & 0x80, 0, "p2 key_share 最高位必须为 0");

        // 0x17 记录体不同
        let enc1 = extract_enc_body(&p1).expect("p1 须提取到 0x17 body");
        let enc2 = extract_enc_body(&p2).expect("p2 须提取到 0x17 body");
        assert_ne!(enc1, enc2, "两次 patch 的 0x17 加密记录体必须不同");
    }

    #[test]
    fn x25519_key_share_msb_always_zero() {
        for _ in 0..50 {
            let k = generate_key_share(0x001d).expect("X25519 key generation");
            assert_eq!(k.len(), 32);
            assert_eq!(k[31] & 0x80, 0, "X25519 u 坐标最高位恒为 0");
        }
    }

    #[test]
    fn p256_key_share_patch() {
        let sid = [0x33u8; 32];
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(32);
        hs_body.extend_from_slice(&sid);
        hs_body.extend_from_slice(&[0x13, 0x01]);
        hs_body.push(0x00);

        // group = 0x0017 (P-256), klen = 65, dummy key = [0x55; 65]
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41]);
        exts.extend_from_slice(&[0x55; 65]);
        hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&exts);

        let mut flight = Vec::new();
        flight.extend_from_slice(&[0x16, 0x03, 0x03]);
        flight.extend_from_slice(&((4 + hs_body.len()) as u16).to_be_bytes());
        flight.push(0x02);
        flight.extend_from_slice(&(hs_body.len() as u32).to_be_bytes()[1..4]);
        flight.extend_from_slice(&hs_body);

        let patched1 = patch_server_hello(&flight, &sid);
        let patched2 = patch_server_hello(&flight, &sid);

        let (g1, ks1) = extract_key_share(&patched1).expect("extract P-256 ks1");
        let (g2, ks2) = extract_key_share(&patched2).expect("extract P-256 ks2");
        assert_eq!(g1, 0x0017);
        assert_eq!(g2, 0x0017);
        assert_eq!(ks1.len(), 65);
        assert_eq!(ks2.len(), 65);
        assert_eq!(ks1[0], 0x04, "P-256 uncompressed point prefix");
        assert_eq!(ks2[0], 0x04, "P-256 uncompressed point prefix");
        assert_ne!(ks1, ks2, "两次生成的 P-256 公钥不同");
        assert_ne!(&ks1[..], &[0x55; 65], "dummy key 已被替换");
    }

    #[test]
    fn malformed_truncated_does_not_panic() {
        // 空输入
        assert_eq!(patch_server_hello(&[], &[0x11; 32]), Vec::<u8>::new());
        // 过短输入
        let short = vec![0x16, 0x03, 0x03];
        assert_eq!(patch_server_hello(&short, &[0x11; 32]), short);
        // 首字节不是 0x16
        let mut not_sh = vec![0x17, 0x03, 0x03];
        not_sh.extend_from_slice(&[0u8; 50]);
        assert_eq!(patch_server_hello(&not_sh, &[0x11; 32]), not_sh);

        // 截断 extensions 或截断 key_share
        let ch = make_client_hello();
        let fb = fallback_server_hello(&ch, &[0x11; 32]);
        let mut truncated = fb.clone();
        truncated.truncate(60); // 截断在 ServerHello 内部
        let p_trunc = patch_server_hello(&truncated, &[0x11; 32]);
        assert!(!p_trunc.is_empty(), "不 panic 且安全返回");

        // 未知 group 保持原样不 panic
        let mut unknown_group = fb.clone();
        // 找到 key_share group 0x001d 改为 0x0099
        for i in 0..unknown_group.len() - 4 {
            if unknown_group[i..i + 4] == [0x00, 0x33, 0x00, 0x24] {
                unknown_group[i + 4] = 0x00;
                unknown_group[i + 5] = 0x99;
                let old_key = unknown_group[i + 8..i + 40].to_vec();
                let patched = patch_server_hello(&unknown_group, &[0x11; 32]);
                let (g, k) = extract_key_share(&patched).expect("extract unknown");
                assert_eq!(g, 0x0099);
                assert_eq!(k, old_key, "未知 group 保持原样公钥");
                break;
            }
        }
    }

    #[test]
    fn patch_preserves_template_is_complete() {
        let ch = make_client_hello();
        let sid = [0xAAu8; 32];
        let fb = fallback_server_hello(&ch, &sid);
        assert!(template_is_complete(&fb));

        let new_sid = [0xBBu8; 32];
        let patched = patch_server_hello(&fb, &new_sid);
        assert!(template_is_complete(&patched), "patch 后的模板必须保持 template_is_complete == true");
    }

    #[test]
    fn test_key_share_group_parsing() {
        let ch = make_client_hello();
        let sid = [0xAAu8; 32];
        let fb = fallback_server_hello(&ch, &sid);
        assert_eq!(key_share_group(&fb), Some((0x001d, 32)));

        let mut unknown_group = fb.clone();
        for i in 0..unknown_group.len() - 4 {
            if unknown_group[i..i + 4] == [0x00, 0x33, 0x00, 0x24] {
                unknown_group[i + 4] = 0x00;
                unknown_group[i + 5] = 0x99;
                break;
            }
        }
        assert_eq!(key_share_group(&unknown_group), Some((0x0099, 32)));
    }

    #[tokio::test]
    async fn fetch_rejects_unknown_key_share_template() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ch = make_client_hello();
        let mut unknown_sh = fallback_server_hello(&ch, &[0xAA; 32]);
        for i in 0..unknown_sh.len() - 4 {
            if unknown_sh[i..i + 4] == [0x00, 0x33, 0x00, 0x24] {
                unknown_sh[i + 4] = 0x00;
                unknown_sh[i + 5] = 0x99;
                break;
            }
        }
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(&unknown_sh).await;
        });
        let res = fetch_real_server_hello(&addr.to_string()).await;
        assert!(res.is_err(), "未知 key_share group 模板必须被拒: {:?}", res);
    }
}
