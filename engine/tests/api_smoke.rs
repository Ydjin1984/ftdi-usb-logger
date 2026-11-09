//! Смоук HTTP API: health/status/сессии/события/файлы/экспорт/импорт/статика.

use clap::Parser;
use ftdi_logger::config::{Cli, Config};
use ftdi_logger::models::{Event, EventKind, ServerMsg, SessionMeta, Transport};
use ftdi_logger::store::SessionStore;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    content_type: &str,
) -> (u16, String, String) {
    http_with_headers(addr, method, path, body, content_type, &[]).await
}

async fn http_with_headers(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    content_type: &str,
    extra: &[(&str, &str)],
) -> (u16, String, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = body.unwrap_or("");
    let extra_headers = extra
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect::<String>();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let (headers, payload) = text.split_once("\r\n\r\n").unwrap_or(("", text.as_str()));
    (status, headers.to_string(), payload.to_string())
}

/// Проверить, что ошибка API — JSON `{"error": …}` с ожидаемым кодом.
fn assert_json_error(code: u16, headers: &str, body: &str, expected: u16, context: &str) {
    assert_eq!(code, expected, "{context}: ожидали {expected}, тело: {body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("content-type: application/json"),
        "{context}: не JSON content-type, заголовки: {headers}"
    );
    let err: Value = serde_json::from_str(body)
        .unwrap_or_else(|e| panic!("{context}: тело не JSON ({e}): {body}"));
    let text = err
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{context}: нет поля error: {body}"));
    assert!(!text.trim().is_empty(), "{context}: пустой error");
}

/// OPTIONS-предзапрос с Origin: возвращает (status, headers_lower).
async fn options_origin(addr: std::net::SocketAddr, path: &str, origin: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "OPTIONS {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {origin}\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let headers = text.split("\r\n\r\n").next().unwrap_or("").to_string();
    (status, headers)
}

async fn get_json(addr: std::net::SocketAddr, path: &str) -> Value {
    let (status, _headers, body) = http(addr, "GET", path, None, "").await;
    assert_eq!(status, 200, "GET {path} → {body}");
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("GET {path}: не JSON ({e}): {body}"))
}

async fn post_json(addr: std::net::SocketAddr, path: &str, body: &str) -> (u16, Value) {
    let (status, _headers, payload) = http(addr, "POST", path, Some(body), "application/json").await;
    let value = serde_json::from_str(&payload).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn api_smoke() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().to_path_buf();
    let cli = Cli::parse_from([
        "ftdi-logger",
        "--root",
        root.to_str().unwrap(),
        "--no-open",
        "--no-bridge",
    ]);
    let cfg = Arc::new(Config::from_cli(&cli).unwrap());
    cfg.ensure_dirs().unwrap();
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).unwrap());
    let (bus, _) = tokio::sync::broadcast::channel::<ServerMsg>(256);
    let capture = Arc::new(ftdi_logger::capture::CaptureManager::new(
        cfg.clone(),
        store.clone(),
        bus.clone(),
    ));
    let state = ftdi_logger::api::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
        capture: capture.clone(),
        bus: bus.clone(),
        started: Instant::now(),
    };
    let app = ftdi_logger::api::router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Сессия с двумя событиями и отчётом.
    let mut meta = SessionMeta::new("api-session", "api");
    meta.status = "finished".into();
    let mut w = store.create(meta).unwrap();
    let dir = w.dir().to_path_buf();
    let mut tx = Event::new(EventKind::Tx, Transport::Vcp, 1.0, "");
    tx.api = "WriteFile".into();
    tx.hex = "12 04 0d 1b".into();
    tx.len = 4;
    w.append(&mut tx).unwrap();
    let mut rx = Event::new(EventKind::Rx, Transport::Vcp, 1.1, "");
    rx.api = "ReadFile".into();
    rx.hex = "12 04 0d 1b".into();
    rx.len = 4;
    w.append(&mut rx).unwrap();
    let m = w.meta.clone();
    w.finish(&m).unwrap();
    drop(w);
    std::fs::write(dir.join("report.txt"), "СЕССИЯ api").unwrap();

    // health
    let health = get_json(addr, "/api/health").await;
    assert!(health.get("version").is_some());
    assert!(health.get("uptime_s").is_some());
    assert_eq!(health.get("ui_dist"), Some(&Value::Bool(false)));
    assert!(health.get("capture").is_some());
    assert!(health.get("bridge").is_some());
    assert!(health.get("python").is_some());

    // capture/status
    let status = get_json(addr, "/api/capture/status").await;
    assert_eq!(status.get("recording"), Some(&Value::Bool(false)));
    assert!(status.get("hooks").is_some());

    // devices / tools — массивы
    for path in ["/api/devices", "/api/tools"] {
        let (code, _h, body) = http(addr, "GET", path, None, "").await;
        assert_eq!(code, 200);
        assert!(body.trim_start().starts_with('['), "{path}: {body}");
    }

    // sessions — голый массив
    let (code, _h, body) = http(addr, "GET", "/api/sessions", None, "").await;
    assert_eq!(code, 200);
    let sessions: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["id"], "api-session");

    // session detail
    let detail = get_json(addr, "/api/sessions/api-session").await;
    assert!(detail.get("meta").is_some());
    assert!(detail.get("steps").is_some());

    // events
    let events = get_json(addr, "/api/sessions/api-session/events?limit=100").await;
    assert_eq!(events["events"].as_array().unwrap().len(), 2);
    assert_eq!(events["total"], 2);
    assert!(events["counts"].get("tx_bytes").is_some());

    // context + decode
    let ctx = get_json(addr, "/api/sessions/api-session/events/0/context?n=5").await;
    assert_eq!(ctx["seq"], 0);
    assert!(!ctx["events"].as_array().unwrap().is_empty());
    let decoded = get_json(addr, "/api/sessions/api-session/events/0/decode").await;
    assert_eq!(decoded["cmd"], "cmd=0x0D");

    // файл сессии
    let (code, headers, body) = http(
        addr,
        "GET",
        "/api/sessions/api-session/file/report.txt",
        None,
        "",
    )
    .await;
    assert_eq!(code, 200);
    assert!(body.contains("СЕССИЯ api"));
    assert!(headers.to_ascii_lowercase().contains("text/plain"));
    // path traversal отбит
    let (code, _h, _b) = http(
        addr,
        "GET",
        "/api/sessions/api-session/file/../../../../Windows/win.ini",
        None,
        "",
    )
    .await;
    assert_ne!(code, 200, "path traversal не должен отдавать файл");

    // path traversal через САМ id сессии: id из URL не должен становиться каталогом на диске
    // (C:\Windows, абсолютные пути, ..) — иначе GET /api/sessions/<id>/file/<x> читает что угодно.
    for bad in [
        "/api/sessions/C:%5CWindows/file/win.ini",
        "/api/sessions/C:/Windows/file/win.ini",
        "/api/sessions/..%5C..%5CWindows/file/win.ini",
        "/api/sessions/%2e%2e/file/win.ini",
        "/api/sessions/D:%5CFTDI_USB_Logger/file/README.md",
    ] {
        let (code, _h, body) = http(addr, "GET", bad, None, "").await;
        assert_ne!(
            code, 200,
            "id-traversal не должен отдавать файл: {bad} → {code}: {body}"
        );
    }


    // экспорт csv
    let (code, value) = post_json(
        addr,
        "/api/sessions/api-session/export",
        r#"{"format":"csv"}"#,
    )
    .await;
    assert_eq!(code, 200, "{value}");
    let path = value["path"].as_str().unwrap();
    assert!(PathBuf::from(path).is_file(), "экспорт не создан: {path}");

    // reparse
    let (code, value) = post_json(addr, "/api/sessions/api-session/reparse", "{}").await;
    assert_eq!(code, 200, "{value}");
    assert_eq!(value["ok"], true);

    // импорт по пути
    let import_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/logs/bms46-no-traffic.log");
    let body = serde_json::json!({ "path": import_src.to_string_lossy() }).to_string();
    let (code, value) = post_json(addr, "/api/import", &body).await;
    assert_eq!(code, 200, "{value}");
    let imported_id = value["session_id"].as_str().unwrap().to_string();
    assert!(!imported_id.is_empty());

    // импорт загрузкой
    let tiny = b"# capture start: label=upload\n[+1.000s] VCP TX WriteFile(COM6) n=2 : 12 04\n";
    let (code, _h, payload) = http(
        addr,
        "POST",
        "/api/import/upload?name=tiny.log",
        Some(std::str::from_utf8(tiny).unwrap()),
        "application/octet-stream",
    )
    .await;
    assert_eq!(code, 200, "upload: {payload}");
    let uploaded: Value = serde_json::from_str(&payload).unwrap();
    assert!(uploaded["session_id"].as_str().unwrap().len() > 3);

    // CORS: разрешён только точный localhost-хост; `http://127.0.0.1.evil.com` — нет.
    let (code_ok, hdr_ok) = options_origin(addr, "/api/sessions", "http://127.0.0.1:5173").await;
    assert!(code_ok == 200 || code_ok == 204, "preflight localhost: {code_ok}");
    assert!(
        hdr_ok.contains("access-control-allow-origin: http://127.0.0.1:5173"),
        "localhost-origin должен получать ACAO: {hdr_ok}"
    );
    for evil in [
        "http://127.0.0.1.evil.com",
        "http://localhost.evil.com",
        "http://127.0.0.1@evil.com",
    ] {
        let (_code, hdr) = options_origin(addr, "/api/sessions", evil).await;
        assert!(
            !hdr.contains("access-control-allow-origin"),
            "CORS не должен разрешать {evil}: {hdr}"
        );
    }

    // ошибка на неизвестной ручке — JSON {"error"}
    let (code, _h, payload) = http(addr, "GET", "/api/nope", None, "").await;
    assert_eq!(code, 404);
    let err: Value = serde_json::from_str(&payload).unwrap();
    assert!(err.get("error").is_some());

    // заглушка UI (ui/dist отсутствует)
    let (code, _h, payload) = http(addr, "GET", "/", None, "").await;
    assert_eq!(code, 200);
    assert!(payload.contains("UI не собран"));
    assert!(payload.contains("pnpm -C ui build"));

    // удаление
    let (code, _h, payload) = http(addr, "DELETE", "/api/sessions/api-session", None, "").await;
    assert_eq!(code, 200, "{payload}");
    assert!(store.get("api-session").is_none());

    server.abort();
}

#[tokio::test]
async fn api_error_contract() {
    // Дерево API: 404 на несуществующие сессии, 409 на hookctl без attach,
    // JSON-ошибки от экстракторов axum, негативный CORS.
    let td = tempfile::tempdir().unwrap();
    let root = td.path().to_path_buf();
    let cli = Cli::parse_from([
        "ftdi-logger",
        "--root",
        root.to_str().unwrap(),
        "--no-open",
        "--no-bridge",
    ]);
    let cfg = Arc::new(Config::from_cli(&cli).unwrap());
    cfg.ensure_dirs().unwrap();
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).unwrap());
    let (bus, _) = tokio::sync::broadcast::channel::<ServerMsg>(64);
    let capture = Arc::new(ftdi_logger::capture::CaptureManager::new(
        cfg.clone(),
        store.clone(),
        bus.clone(),
    ));
    let state = ftdi_logger::api::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
        capture: capture.clone(),
        bus: bus.clone(),
        started: Instant::now(),
    };
    let app = ftdi_logger::api::router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // API-01: несуществующий session_id → 404 JSON во всех читающих ручках.
    for path in [
        "/api/sessions/nope",
        "/api/sessions/nope/events",
        "/api/sessions/nope/report",
        "/api/sessions/nope/steps/1",
        "/api/sessions/nope/events/0/decode",
        "/api/sessions/nope/events/0/context",
        "/api/sessions/nope/file/report.txt",
    ] {
        let (code, headers, body) = http(addr, "GET", path, None, "").await;
        assert_json_error(code, &headers, &body, 404, path);
    }

    // POST по несуществующей сессии → 404.
    let (code, headers, body) = http(
        addr,
        "POST",
        "/api/sessions/nope/files",
        Some(r#"{"paths":[]}"#),
        "application/json",
    )
    .await;
    assert_json_error(code, &headers, &body, 404, "files nope");

    // POST/export/reparse/share по несуществующей сессии → 404.
    let (code, headers, body) = http(
        addr,
        "POST",
        "/api/sessions/nope/export",
        Some(r#"{"format":"csv"}"#),
        "application/json",
    )
    .await;
    assert_json_error(code, &headers, &body, 404, "export nope");
    let (code, headers, body) = http(
        addr,
        "POST",
        "/api/sessions/nope/share",
        Some(r#"{"url":"http://127.0.0.1:9/x"}"#),
        "application/json",
    )
    .await;
    assert_json_error(code, &headers, &body, 404, "share nope");

    // reparse — отдельно, потому что post_json глотает тело.
    let (code, headers, body) = http(
        addr,
        "POST",
        "/api/sessions/nope/reparse",
        Some("{}"),
        "application/json",
    )
    .await;
    assert_json_error(code, &headers, &body, 404, "reparse nope");

    // API-12: DELETE несуществующей сессии → 404, а не 200.
    let (code, headers, body) = http(addr, "DELETE", "/api/sessions/nope", None, "").await;
    assert_json_error(code, &headers, &body, 404, "delete nope");

    // CAP-02: hookctl без attach → 409/400 JSON, не 500 text/plain.
    let (code, headers, body) = http(
        addr,
        "POST",
        "/api/capture/hookctl",
        Some(r#"{"value":"pause"}"#),
        "application/json",
    )
    .await;
    assert!(
        code == 409 || code == 400,
        "hookctl без attach: ожидали 409/400, получили {code}: {body}"
    );
    assert_json_error(code, &headers, &body, code, "hookctl без attach");

    // API-07: битый JSON body → 400 JSON, а не text/plain от Json-экстрактора.
    let (code, headers, body) = http(
        addr,
        "POST",
        "/api/import",
        Some(r#"{"path":"#),
        "application/json",
    )
    .await;
    assert_json_error(code, &headers, &body, 400, "битый JSON");

    // API-09: неверный Content-Type → 415 JSON.
    let (code, headers, body) = http(
        addr,
        "POST",
        "/api/import",
        Some(r#"{"path":"x"}"#),
        "text/plain",
    )
    .await;
    assert_json_error(code, &headers, &body, 415, "неверный Content-Type");

    // API-15: limit=abc → 400 JSON (отказ Query-экстрактора обёрнут).
    let (code, headers, body) = http(
        addr,
        "GET",
        "/api/sessions/nope/events?limit=abc",
        None,
        "",
    )
    .await;
    assert_json_error(code, &headers, &body, 400, "limit=abc");

    // Негативный CORS: чужой origin не получает Access-Control-Allow-Origin.
    let (code, headers, _body) = http_with_headers(
        addr,
        "GET",
        "/api/health",
        None,
        "",
        &[("Origin", "http://evil.example")],
    )
    .await;
    assert_eq!(code, 200);
    assert!(
        !headers
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"),
        "чужой origin не должен получать ACAO: {headers}"
    );
    let (code, headers, _body) = http_with_headers(
        addr,
        "GET",
        "/api/health",
        None,
        "",
        &[("Origin", "http://127.0.0.1:5173")],
    )
    .await;
    assert_eq!(code, 200);
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("access-control-allow-origin: http://127.0.0.1:5173"),
        "localhost-origin должен получать ACAO: {headers}"
    );

    // Статика не должна превращаться в JSON-ошибку.
    let (code, headers, body) = http(addr, "GET", "/some-ui-asset.js", None, "").await;
    assert_eq!(code, 200);
    assert!(body.contains("UI не собран"));
    assert!(!headers
        .to_ascii_lowercase()
        .contains("content-type: application/json"));

    server.abort();
}
