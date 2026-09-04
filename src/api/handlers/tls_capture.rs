//! TLS 指纹捕获 API (给已运行的透明网关免重启抓取; WebUI 按钮)。
//! - POST /api/v1/tls/capture — arm 一次性抓取 (仅内存)。用真浏览器经本网关访问一次 HTTPS。
//! - GET  /api/v1/tls/capture — 查状态 + 取回已抓模板 (client_hello base64 + 偏移 sidecar)。

use axum::Json;
use serde_json::{json, Value};

pub async fn post_capture() -> Json<Value> {
    crate::proxy::tls_capture::arm(None); // 仅存内存, 经 GET 取回
    Json(json!({
        "status": "success",
        "armed": true,
        "hint": "现在用真浏览器经本网关访问任意 HTTPS 一次, 再 GET 本端点取回模板"
    }))
}

pub async fn get_capture() -> Json<Value> {
    use base64::Engine;
    let armed = crate::proxy::tls_capture::is_armed();
    match crate::proxy::tls_capture::last() {
        Some(cap) => Json(json!({
            "status": "success",
            "armed": armed,
            "captured": true,
            "sni": cap.sni_host,
            "record_len": cap.record_len,
            "client_hello_b64": base64::engine::general_purpose::STANDARD.encode(&cap.bytes),
            "sidecar": crate::proxy::tls_capture::sidecar(&cap),
        })),
        None => Json(json!({ "status": "success", "armed": armed, "captured": false })),
    }
}
