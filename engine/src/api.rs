//! HTTP/WS API. Владелец: ded-bekend.
//!
//! Ручки — docs/02 §6 + дополнение контракта от UI (файлы сессии, upload-импорт,
//! capture/status, decode события). Ошибки — JSON `{"error": "…"}` с кодом 4xx/5xx.

use crate::capture::CaptureManager;
use crate::config::Config;
use crate::models::{
    CaptureStatus, ClientMsg, Event, EventKind, FileHash, FtdiDevice, PayloadDecode, ProcessDetail,
    ServerMsg, SessionCounts, SessionMeta, StepEvent, StepSummary, ToolProcess,
};
use crate::store::SessionStore;
use crate::{decode, import, procscan, report};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::services::ServeDir;

/// Максимальный размер загружаемого старого лога.
const IMPORT_UPLOAD_LIMIT: usize = 256 * 1024 * 1024;
/// Батчи WS: не больше 256 событий.
const WS_BATCH_EVENTS: usize = 256;
/// Батчи WS: не больше ~32 КиБ полезной нагрузки.
const WS_BATCH_BYTES: usize = 32 * 1024;
/// Коалесценция WS ≈ 20 раз/с.
const WS_FLUSH_EVERY: Duration = Duration::from_millis(50);
/// Сколько событий бэклога отдаём при subscribe.
const WS_BACKLOG_MAX: usize = 2560;

const UI_STUB: &str = r#"<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>FTDI/USB Logger</title>
<style>body{font:16px/1.5 system-ui,sans-serif;background:#111;color:#ddd;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
main{max-width:640px;padding:32px;border:1px solid #333;border-radius:12px;background:#1a1a1a}
code{background:#000;padding:2px 6px;border-radius:4px;color:#7ee787}</style></head>
<body><main><h1>UI не собран</h1>
<p>Соберите интерфейс и перезагрузите страницу:</p>
<p><code>pnpm -C ui build</code></p>
<p>Движок уже работает: REST/WS доступны на этом же адресе (<code>/api/health</code>).</p>
</main></body></html>"#;

// ─────────────────────────────── ошибки ──────────────────────────────────

/// Ошибка API: HTTP-код + JSON `{"error": …}`.
#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}"))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
    }
}

type ApiResult<T> = Result<T, AppError>;

/// Открыть читатель сессии; отсутствие сессии/каталога — 404, прочее — 500.
fn reader_or_404(
    st: &AppState,
    id: &str,
) -> ApiResult<crate::store::SessionReader> {
    if st.store.get(id).is_none() {
        return Err(AppError::not_found(format!("сессия {id} не найдена")));
    }
    if !st.store.dir_for(id).is_dir() {
        return Err(AppError::not_found(format!(
            "каталог сессии {id} отсутствует"
        )));
    }
    st.store.reader(id).map_err(AppError::from)
}

// ─────────────────────────────── состояние ───────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<SessionStore>,
    pub capture: Arc<CaptureManager>,
    pub bus: broadcast::Sender<ServerMsg>,
    pub started: std::time::Instant,
}

// ─────────────────────────────── роутер ──────────────────────────────────

pub fn router(state: AppState) -> Router {
    let cors = cors_layer();

    let api = Router::new()
        .route("/health", get(health))
        .route("/devices", get(devices))
        .route("/tools", get(tools))
        .route("/tools/:pid/detail", get(tool_detail))
        .route("/capture/status", get(capture_status))
        .route("/capture/attach", post(capture_attach))
        .route("/capture/detach", post(capture_detach))
        .route("/capture/hookctl", post(capture_hookctl))
        .route("/sessions", get(sessions))
        .route("/sessions/:id", get(session_detail).delete(session_delete))
        .route("/sessions/:id/events", get(session_events))
        .route("/sessions/:id/events/:seq/context", get(event_context))
        .route("/sessions/:id/events/:seq/decode", get(event_decode))
        .route("/sessions/:id/steps/:n", get(step_detail))
        .route("/sessions/:id/report", get(session_report))
        .route("/sessions/:id/reparse", post(session_reparse))
        .route("/sessions/:id/export", post(session_export))
        .route("/sessions/:id/share", post(session_share))
        .route("/sessions/:id/files", post(session_files))
        .route("/sessions/:id/file/*path", get(session_file))
        .route("/sessions/:id/step/start", post(step_start))
        .route("/sessions/:id/step/end", post(step_end))
        .route("/sessions/:id/mark", post(mark))
        .route("/sessions/:id/note", post(note))
        .route("/sessions/:id/shot", post(shot))
        .route("/import", post(import_path))
        .route(
            "/import/upload",
            post(import_upload).layer(DefaultBodyLimit::max(IMPORT_UPLOAD_LIMIT)),
        )
        .fallback(api_not_found);

    let mut app = Router::new()
        .nest("/api", api)
        .route("/ws", get(ws_handler));

    // Статика UI: если dist собран — ServeDir, иначе страница-заглушка на всё.
    if state.cfg.ui_dist.is_dir() {
        app = app.fallback_service(
            ServeDir::new(state.cfg.ui_dist.clone()).not_found_service(get(ui_fallback)),
        );
    } else {
        app = app.fallback(get(ui_fallback));
    }

    app.layer(cors)
        .layer(axum::middleware::from_fn(api_json_errors))
        .with_state(state)
}

/// Все ошибки под `/api/` отдаём JSON-ом `{"error": …}` — в том числе отказы
/// экстракторов axum (битый JSON, неверный Content-Type, limit=abc), которые
/// по умолчанию приходят text/plain. Статику и файлы сессий не трогаем.
async fn api_json_errors(req: axum::extract::Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let response = next.run(req).await;
    if !is_api || !(response.status().is_client_error() || response.status().is_server_error()) {
        return response;
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.starts_with("application/json") {
        return response;
    }

    let status = response.status();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 128 * 1024)
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    let message = if text.is_empty() {
        status
            .canonical_reason()
            .unwrap_or("ошибка API")
            .to_string()
    } else {
        text
    };
    let payload = serde_json::to_vec(&json!({ "error": message }))
        .unwrap_or_else(|_| b"{\"error\":\"\xd0\xbe\xd1\x88\xd0\xb8\xd0\xb1\xd0\xba\xd0\xb0 API\"}".to_vec());

    let mut out = Response::new(axum::body::Body::from(payload));
    *out.status_mut() = status;
    out.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // Сохраняем прочие заголовки (CORS и т.п.), кроме длины тела.
    for (name, value) in parts.headers.iter() {
        if name != header::CONTENT_TYPE && name != header::CONTENT_LENGTH {
            out.headers_mut().insert(name.clone(), value.clone());
        }
    }
    out
}

/// Origin разрешён, только если хост РОВНО 127.0.0.1 / localhost / [::1].
/// Префиксная проверка пропускала `http://127.0.0.1.evil.com` (CORS-обход).
fn origin_is_local(origin: &str) -> bool {
    let lower = origin.trim().to_ascii_lowercase();
    let rest = match lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
    {
        Some(r) => r,
        None => return false,
    };
    // отсекаем userinfo (защита от http://evil@127.0.0.1 — не наш случай)
    if rest.contains('@') {
        return false;
    }
    let end = rest
        .find(|c: char| c == ':' || c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    matches!(&rest[..end], "127.0.0.1" | "localhost" | "[::1]")
}

fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            |origin: &HeaderValue, _parts: &axum::http::request::Parts| {
                let Ok(text) = origin.to_str() else {
                    return false;
                };
                origin_is_local(text)
            },
        ))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT, Method::OPTIONS])
        .allow_headers(Any)
}

async fn ui_fallback() -> Html<&'static str> {
    Html(UI_STUB)
}

async fn api_not_found() -> AppError {
    AppError::not_found("неизвестная ручка API")
}

// ─────────────────────────────── health ──────────────────────────────────

async fn health(State(st): State<AppState>) -> Json<Value> {
    let sessions = st.store.list().len();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": st.started.elapsed().as_secs(),
        "bridge": st.capture.bridge().is_running(),
        "capture": st.capture.status(),
        "sessions": sessions,
        "ui_dist": st.cfg.ui_dist.is_dir(),
        "python": st.cfg.python.to_string_lossy(),
    }))
}

// ─────────────────────────── discovery / процессы ────────────────────────

async fn devices() -> Json<Vec<FtdiDevice>> {
    Json(crate::discovery::list_ftdi_devices())
}

const KNOWN_TOOLS: &[&str] = &[
    "winkfpt.exe",
    "inpa.exe",
    "tool32.exe",
    "ncsx.exe",
    "ediabas.exe",
    "nfs.exe",
    "quickflash.exe",
];

async fn tools() -> Json<Vec<ToolProcess>> {
    Json(procscan::list_candidates(KNOWN_TOOLS))
}

async fn tool_detail(Path(pid): Path<u32>) -> ApiResult<Json<ProcessDetail>> {
    procscan::process_detail(pid)
        .map(Json)
        .ok_or_else(|| AppError::not_found(format!("процесс pid={pid} не найден")))
}

// ─────────────────────────────── capture ────────────────────────────────

async fn capture_status(State(st): State<AppState>) -> Json<CaptureStatus> {
    Json(st.capture.status())
}

#[derive(Debug, Deserialize)]
struct AttachReq {
    pid: u32,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    adapter: Option<String>,
}

async fn capture_attach(
    State(st): State<AppState>,
    Json(req): Json<AttachReq>,
) -> ApiResult<Json<SessionMeta>> {
    let meta = st
        .capture
        .attach(req.pid, req.label.unwrap_or_default(), req.adapter)
        .await
        .map_err(|err| AppError::conflict(format!("{err:#}")))?;
    let _ = st.bus.send(ServerMsg::Toast {
        level: "info".into(),
        text: format!("захват сессии {} запущен", meta.id),
    });
    Ok(Json(meta))
}

async fn capture_detach(State(st): State<AppState>) -> ApiResult<Json<Option<SessionMeta>>> {
    let meta = st.capture.detach().await?;
    Ok(Json(meta))
}

#[derive(Debug, Deserialize)]
struct HookReq {
    value: String,
}

async fn capture_hookctl(
    State(st): State<AppState>,
    Json(req): Json<HookReq>,
) -> ApiResult<Json<Value>> {
    let value = req.value.trim().to_ascii_lowercase();
    if value != "pause" && value != "resume" {
        return Err(AppError::bad("value должен быть pause или resume"));
    }
    st.capture
        .hookctl(&value)
        .await
        .map_err(|err| AppError::conflict(format!("{err:#}")))?;
    Ok(Json(json!({ "hooks": st.capture.status().hooks })))
}

/// Проверить, что сессия из пути — активная (шаги/метки идут в живую сессию).
fn require_active(st: &AppState, id: &str) -> ApiResult<()> {
    match st.capture.active() {
        Some(meta) if meta.id == id => Ok(()),
        Some(meta) => Err(AppError::conflict(format!(
            "активна другая сессия: {}",
            meta.id
        ))),
        None => Err(AppError::conflict("захват не идёт: нет активной сессии")),
    }
}

#[derive(Debug, Deserialize)]
struct TitleReq {
    #[serde(default)]
    title: String,
}

async fn step_start(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TitleReq>,
) -> ApiResult<Json<StepEvent>> {
    require_active(&st, &id)?;
    st.capture
        .start_step(req.title)
        .await
        .map(Json)
        .map_err(|err| AppError::conflict(format!("{err:#}")))
}

async fn step_end(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<StepSummary>> {
    require_active(&st, &id)?;
    st.capture
        .end_step()
        .await
        .map(Json)
        .map_err(|err| AppError::conflict(format!("{err:#}")))
}

async fn mark(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TitleReq>,
) -> ApiResult<Json<Value>> {
    require_active(&st, &id)?;
    let ev = st
        .capture
        .mark(req.title)
        .await
        .map_err(|err| AppError::conflict(format!("{err:#}")))?;
    Ok(Json(json!({ "seq": ev.seq })))
}

#[derive(Debug, Deserialize)]
struct NoteReq {
    #[serde(default)]
    text: String,
}

async fn note(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<NoteReq>,
) -> ApiResult<Json<Value>> {
    require_active(&st, &id)?;
    st.capture
        .note(req.text)
        .await
        .map_err(|err| AppError::conflict(format!("{err:#}")))?;
    Ok(Json(json!({ "ok": true })))
}

async fn shot(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    require_active(&st, &id)?;
    let path = st
        .capture
        .shot()
        .await
        .map_err(|err| AppError::conflict(format!("{err:#}")))?;
    Ok(Json(json!({ "path": path })))
}

// ─────────────────────────────── сессии ─────────────────────────────────

async fn sessions(State(st): State<AppState>) -> Json<Vec<SessionMeta>> {
    Json(st.store.list())
}

async fn session_detail(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let reader = reader_or_404(&st, &id)?;
    Ok(Json(json!({
        "meta": reader.meta(),
        "steps": reader.steps(),
    })))
}

async fn session_delete(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if st.store.get(&id).is_none() {
        return Err(AppError::not_found(format!("сессия {id} не найдена")));
    }
    st.store.delete(&id)?;
    let _ = st.bus.send(ServerMsg::Toast {
        level: "info".into(),
        text: format!("сессия {id} удалена"),
    });
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    #[serde(default)]
    from: Option<u64>,
    #[serde(default)]
    to: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    kinds: Option<String>,
    #[serde(default)]
    q: Option<String>,
}

fn kind_matches(kind: EventKind, filter: &[String]) -> bool {
    filter.is_empty() || filter.iter().any(|k| k == report::kind_name(kind))
}

fn event_matches(ev: &Event, kinds: &[String], q: &Option<String>) -> bool {
    if !kind_matches(ev.kind, kinds) {
        return false;
    }
    if let Some(needle) = q {
        let needle = needle.trim().to_ascii_lowercase();
        if !needle.is_empty() {
            let hay = format!(
                "{} {} {} {}",
                ev.raw,
                ev.api,
                ev.hex,
                ev.text.clone().unwrap_or_default()
            )
            .to_ascii_lowercase();
            if !hay.contains(&needle) {
                return false;
            }
        }
    }
    true
}

async fn session_events(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let reader = reader_or_404(&st, &id)?;
    let limit = q.limit.unwrap_or(1000).clamp(1, 10_000);
    let total = reader.count_events();
    let counts = reader.meta().counts.clone();
    let kinds: Vec<String> = q
        .kinds
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let mut out: Vec<Event> = Vec::new();
    let mut cursor = q.from.unwrap_or(0);
    loop {
        let page = reader.events(Some(cursor), q.to, 512);
        if page.is_empty() {
            break;
        }
        for ev in page {
            cursor = ev.seq + 1;
            if event_matches(&ev, &kinds, &q.q) {
                out.push(ev);
                if out.len() >= limit {
                    break;
                }
            }
        }
        if out.len() >= limit {
            break;
        }
    }
    Ok(Json(json!({
        "events": out,
        "counts": counts,
        "total": total,
    })))
}

#[derive(Debug, Deserialize)]
struct ContextQuery {
    #[serde(default)]
    n: Option<usize>,
}

async fn event_context(
    State(st): State<AppState>,
    Path((id, seq)): Path<(String, u64)>,
    Query(q): Query<ContextQuery>,
) -> ApiResult<Json<Value>> {
    let reader = reader_or_404(&st, &id)?;
    let n = q.n.unwrap_or(20).min(500) as u64;
    let from = seq.saturating_sub(n);
    let to = seq.saturating_add(n).saturating_add(1);
    let events = reader.events(Some(from), Some(to), 0);
    if events.is_empty() {
        return Err(AppError::not_found(format!("событие seq={seq} не найдено")));
    }
    Ok(Json(json!({ "events": events, "seq": seq })))
}

async fn event_decode(
    State(st): State<AppState>,
    Path((id, seq)): Path<(String, u64)>,
) -> ApiResult<Json<PayloadDecode>> {
    let reader = reader_or_404(&st, &id)?;
    let event = reader
        .events(Some(seq), Some(seq + 1), 1)
        .into_iter()
        .next()
        .ok_or_else(|| AppError::not_found(format!("событие seq={seq} не найдено")))?;
    Ok(Json(decode::decode_payload(&event.hex)))
}

async fn step_detail(
    State(st): State<AppState>,
    Path((id, n)): Path<(String, u32)>,
) -> ApiResult<Json<StepSummary>> {
    let reader = reader_or_404(&st, &id)?;
    reader
        .steps()
        .into_iter()
        .find(|s| s.idx == n)
        .map(Json)
        .ok_or_else(|| AppError::not_found(format!("шаг {n} не найден")))
}

#[derive(Debug, Deserialize)]
struct ReportQuery {
    #[serde(default)]
    format: Option<String>,
}

async fn session_report(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ReportQuery>,
) -> ApiResult<Response> {
    let reader = reader_or_404(&st, &id)?;
    let format = q.format.unwrap_or_else(|| "txt".into());
    match format.as_str() {
        "txt" | "text" => {
            let text = if reader.dir().join("report.txt").is_file() {
                std::fs::read_to_string(reader.dir().join("report.txt"))?
            } else {
                report::render_text(reader.meta(), &reader.steps())
            };
            Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response())
        }
        "md" | "markdown" => {
            let text = if reader.dir().join("report.md").is_file() {
                std::fs::read_to_string(reader.dir().join("report.md"))?
            } else {
                report::render_markdown(reader.meta(), &reader.steps())
            };
            Ok(([(header::CONTENT_TYPE, "text/markdown; charset=utf-8")], text).into_response())
        }
        other => Err(AppError::bad(format!(
            "неизвестный формат отчёта: {other} (txt|md)"
        ))),
    }
}

async fn session_reparse(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let reader = reader_or_404(&st, &id)?;
    if reader.meta().status == "recording" {
        return Err(AppError::conflict(
            "сессия ещё пишется: переразбор после остановки захвата",
        ));
    }
    drop(reader);
    import::reparse_session(&st.store, &id)?;
    let _ = st.bus.send(ServerMsg::Toast {
        level: "info".into(),
        text: format!("сессия {id}: переразбор готов"),
    });
    Ok(Json(json!({ "ok": true })))
}

// ─────────────────────────────── экспорт ─────────────────────────────────

fn abs_display(path: &StdPath) -> String {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut text = abs.to_string_lossy().to_string();
    if let Some(stripped) = text.strip_prefix(r"\\?\") {
        text = stripped.to_string();
    }
    text
}

fn export_dir(st: &AppState, id: &str) -> PathBuf {
    st.store.dir_for(id).join("export")
}

fn export_name(format: &str) -> String {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let ext = match format {
        "zip" => "zip",
        "jsonl" => "jsonl",
        "csv" => "csv",
        _ => "md",
    };
    format!("export-{stamp}.{ext}")
}

#[derive(Debug, Deserialize)]
struct ExportReq {
    format: String,
}

async fn session_export(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ExportReq>,
) -> ApiResult<Json<Value>> {
    let reader = reader_or_404(&st, &id)?;
    let dir = reader.dir().to_path_buf();
    let out_dir = export_dir(&st, &id);
    std::fs::create_dir_all(&out_dir)?;
    let format = req.format.trim().to_ascii_lowercase();
    let out = out_dir.join(export_name(&format));
    match format.as_str() {
        "zip" => report::export_zip(&dir, &out)?,
        "jsonl" => report::export_jsonl(&dir, &out)?,
        "csv" => report::export_csv(&reader.all_events(), &out)?,
        "md" | "markdown" => {
            report::export_markdown(reader.meta(), &reader.steps(), &out)?;
        }
        other => {
            return Err(AppError::bad(format!(
                "неизвестный формат экспорта: {other} (zip|jsonl|csv|md)"
            )))
        }
    }
    Ok(Json(json!({ "path": abs_display(&out) })))
}

#[derive(Debug, Deserialize)]
struct ShareReq {
    url: String,
}

async fn session_share(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ShareReq>,
) -> ApiResult<Json<Value>> {
    let url = req.url.trim().to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(AppError::bad("url должен начинаться с http:// или https://"));
    }
    let reader = reader_or_404(&st, &id)?;
    let dir = reader.dir().to_path_buf();
    let out_dir = export_dir(&st, &id);
    std::fs::create_dir_all(&out_dir)?;
    let zip_path = out_dir.join("share.zip");
    report::export_zip(&dir, &zip_path)?;

    let mut cmd = tokio::process::Command::new("curl.exe");
    cmd.arg("-sS")
        .arg("-F")
        .arg(format!("file=@{}", abs_display(&zip_path)))
        .arg(&url);
    let output = tokio::time::timeout(Duration::from_secs(90), cmd.output())
        .await
        .map_err(|_| AppError::new(StatusCode::GATEWAY_TIMEOUT, "curl: таймаут отправки"))?
        .map_err(|e| AppError::new(StatusCode::BAD_GATEWAY, format!("curl: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("curl завершился с ошибкой: {}", stderr.trim()),
        ));
    }
    let _ = st.bus.send(ServerMsg::Toast {
        level: "info".into(),
        text: format!("сессия {id} отправлена на {url}"),
    });
    Ok(Json(json!({ "ok": true })))
}

// ─────────────────────────── файлы сессии ────────────────────────────────

async fn session_file(
    State(st): State<AppState>,
    Path((id, path)): Path<(String, String)>,
) -> ApiResult<Response> {
    // ВАЖНО: id приходит из URL и не должен попадать в join напрямую.
    // Разрешаем только id существующей сессии из индекса (иначе "C:\Windows",
    // "..", "D:/x" превращались в произвольный каталог на диске).
    let meta = st
        .store
        .get(&id)
        .ok_or_else(|| AppError::not_found(format!("сессия {id} не найдена")))?;
    let session_dir = st.store.dir_for(&meta.id);
    if !session_dir.is_dir() {
        return Err(AppError::not_found(format!("сессия {id} не найдена")));
    }
    let rel = path.trim_start_matches(['/', '\\']);
    if rel.is_empty() || rel.contains("..") || rel.contains(':') {
        return Err(AppError::bad("недопустимый путь файла"));
    }
    let candidate = session_dir.join(rel);
    let canonical = candidate
        .canonicalize()
        .map_err(|_| AppError::not_found("файл не найден"))?;
    let base = session_dir.canonicalize()?;
    if !canonical.starts_with(&base) {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "выход за каталог сессии запрещён",
        ));
    }
    if !canonical.is_file() {
        return Err(AppError::not_found("не файл"));
    }
    let bytes = tokio::fs::read(&canonical).await?;
    let mime = mime_guess::from_path(&canonical).first_or_octet_stream();
    let content_type = if canonical
        .extension()
        .map(|e| e.eq_ignore_ascii_case("png"))
        .unwrap_or(false)
    {
        "image/png".to_string()
    } else {
        mime.to_string()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(axum::body::Body::from(bytes))
        .map_err(|e| AppError::from(anyhow::anyhow!(e)))
}

#[derive(Debug, Deserialize)]
struct FilesReq {
    #[serde(default)]
    paths: Vec<String>,
}

async fn session_files(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<FilesReq>,
) -> ApiResult<Json<Value>> {
    let _reader = reader_or_404(&st, &id)?; // сессия должна существовать
    let mut files: Vec<FileHash> = Vec::new();
    for path in &req.paths {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.is_file() {
                if let Ok(bytes) = std::fs::read(path) {
                    files.push(FileHash {
                        path: path.clone(),
                        size: bytes.len() as u64,
                        sha256: crate::models::util::sha256_hex(&bytes),
                        mode: "requested".into(),
                    });
                }
            }
        }
    }

    // Если сессия уже не пишется — фиксируем хеши событиями (живой сессией владеет capture).
    let active = st.capture.active().map(|m| m.id);
    let mut recorded = false;
    if active.as_deref() != Some(id.as_str()) {
        if let Ok(mut writer) = st.store.writer(&id) {
            for file in &files {
                let mut ev = Event::new(EventKind::FileHash, crate::models::Transport::File, 0.0, "");
                ev.api = "FILEHASH".into();
                ev.text = Some(file.path.clone());
                ev.meta = json!({
                    "path": file.path,
                    "size": file.size,
                    "sha256": file.sha256,
                });
                writer.append(&mut ev)?;
            }
            let meta = writer.meta.clone();
            writer.finish(&meta)?;
            recorded = true;
        }
    }
    Ok(Json(json!({ "files": files, "recorded": recorded })))
}

// ─────────────────────────────── импорт ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct ImportReq {
    path: String,
}

async fn import_path(
    State(st): State<AppState>,
    Json(req): Json<ImportReq>,
) -> ApiResult<Json<Value>> {
    let path = PathBuf::from(req.path.trim());
    if !path.is_file() {
        return Err(AppError::not_found(format!(
            "лог не найден: {}",
            path.display()
        )));
    }
    let meta = import::import_legacy_log(&st.store, &path, None)?;
    let _ = st.bus.send(ServerMsg::Toast {
        level: "info".into(),
        text: format!("импортирована сессия {}", meta.id),
    });
    Ok(Json(json!({ "session_id": meta.id })))
}

#[derive(Debug, Deserialize)]
struct UploadQuery {
    #[serde(default)]
    name: Option<String>,
}

fn safe_upload_name(name: Option<&str>) -> String {
    let base = name
        .map(|s| {
            s.rsplit(['/', '\\'])
                .next()
                .unwrap_or("import.log")
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "import.log".into());
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "import.log".into()
    } else {
        cleaned
    }
}

async fn import_upload(
    State(st): State<AppState>,
    Query(q): Query<UploadQuery>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    if body.is_empty() {
        return Err(AppError::bad("пустое тело запроса: ожидаются байты старого лога"));
    }
    let name = safe_upload_name(q.name.as_deref());
    let tmp = std::env::temp_dir().join(format!(
        "ftdi-import-{}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4(),
        name
    ));
    std::fs::write(&tmp, &body)?;
    let result = import::import_legacy_log(&st.store, &tmp, None);
    let _ = std::fs::remove_file(&tmp);
    let meta = result?;
    let _ = st.bus.send(ServerMsg::Toast {
        level: "info".into(),
        text: format!("загружен и импортирован лог: сессия {}", meta.id),
    });
    Ok(Json(json!({ "session_id": meta.id })))
}

// ─────────────────────────────── WebSocket ───────────────────────────────

async fn ws_handler(ws: WebSocketUpgrade, State(st): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_loop(socket, st))
}

async fn send_msg(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: &ServerMsg,
) -> bool {
    let Ok(text) = serde_json::to_string(msg) else {
        return false;
    };
    sender.send(Message::Text(text)).await.is_ok()
}

fn batch_bytes(events: &[Event]) -> usize {
    events
        .iter()
        .map(|e| e.hex.len() + e.raw.len() + 64)
        .sum::<usize>()
}

async fn ws_loop(socket: WebSocket, st: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut bus_rx = st.bus.subscribe();
    let hello = ServerMsg::Hello {
        server_version: env!("CARGO_PKG_VERSION").into(),
        active_session: st.capture.active().map(|m| m.id),
    };
    if !send_msg(&mut sender, &hello).await {
        return;
    }
    // None — ещё не подписан; Some(None) — все сессии; Some(Some(id)) — одна.
    let mut subscribed: Option<Option<String>> = None;
    let mut session_id: Option<String> = None;
    let mut pending: Vec<Event> = Vec::new();
    let mut counts = SessionCounts::default();
    let mut ticker = tokio::time::interval(WS_FLUSH_EVERY);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMsg>(&text) {
                            Ok(ClientMsg::Subscribe { session, since }) => {
                                subscribed = Some(session.clone());
                                session_id = session.clone();
                                if let Some(id) = &session {
                                    if let Ok(reader) = st.store.reader(id) {
                                        counts = reader.meta().counts.clone();
                                        // Бэклог: отдаём не больше WS_BACKLOG_MAX событий.
                                        let mut backlog: Vec<Event> = Vec::new();
                                        let mut cursor = since;
                                        while backlog.len() < WS_BACKLOG_MAX {
                                            let page = reader.events(Some(cursor), None, 256);
                                            if page.is_empty() {
                                                break;
                                            }
                                            cursor = page.last().map(|e| e.seq + 1).unwrap_or(cursor);
                                            backlog.extend(page);
                                        }
                                        while !backlog.is_empty() {
                                            let take = backlog.len().min(WS_BATCH_EVENTS);
                                            let batch: Vec<Event> = backlog.drain(..take).collect();
                                            let msg = ServerMsg::Batch {
                                                session: id.clone(),
                                                events: batch,
                                                counts: counts.clone(),
                                            };
                                            if !send_msg(&mut sender, &msg).await {
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(ClientMsg::Ping) => {
                                let _ = sender.send(Message::Pong(Vec::new().into())).await;
                            }
                            Err(_) => {}
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = sender.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            msg = bus_rx.recv() => {
                match msg {
                    Ok(ServerMsg::Batch { session, events, counts: c }) => {
                        let pass = match &session_id {
                            None => true,
                            Some(id) => &session == id,
                        };
                        if !pass {
                            continue;
                        }
                        counts = c;
                        pending.extend(events);
                        while pending.len() >= WS_BATCH_EVENTS || batch_bytes(&pending) >= WS_BATCH_BYTES {
                            let take = pending.len().min(WS_BATCH_EVENTS);
                            let batch: Vec<Event> = pending.drain(..take).collect();
                            let msg = ServerMsg::Batch {
                                session: session.clone(),
                                events: batch,
                                counts: counts.clone(),
                            };
                            if !send_msg(&mut sender, &msg).await {
                                return;
                            }
                            if pending.is_empty() {
                                break;
                            }
                        }
                    }
                    Ok(other) => {
                        if !send_msg(&mut sender, &other).await {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        let toast = ServerMsg::Toast {
                            level: "warn".into(),
                            text: format!(
                                "подписка отстала на {skipped} событий — догрузите пропуск через GET /api/sessions/…/events?from="
                            ),
                        };
                        let _ = send_msg(&mut sender, &toast).await;
                        break; // рвём подписку, как требует контракт
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = ticker.tick() => {
                if !pending.is_empty() && subscribed.is_some() {
                    let batch: Vec<Event> = std::mem::take(&mut pending);
                    let session = session_id
                        .clone()
                        .or_else(|| st.capture.active().map(|m| m.id))
                        .unwrap_or_default();
                    let msg = ServerMsg::Batch {
                        session,
                        events: batch,
                        counts: counts.clone(),
                    };
                    if !send_msg(&mut sender, &msg).await {
                        return;
                    }
                }
            }
        }
    }
    let _ = sender.send(Message::Close(None)).await;
}



