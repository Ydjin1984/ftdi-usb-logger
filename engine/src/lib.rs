pub mod config;
pub mod discovery;
pub mod procscan;
pub mod screenshot;
pub mod frida;
pub mod models;
pub mod store;
pub mod decode;
pub mod capture;
pub mod api;
pub mod report;
pub mod import;
pub mod ediabas;
pub mod usbdevices;
pub mod j2534;
pub mod usbpcap;

use std::sync::Arc;
use anyhow::Context;
use tokio::sync::broadcast;

/// Точка входа: собрать состояние, поднять HTTP/WS и жить до Ctrl+C.
pub async fn run(cli: config::Cli) -> anyhow::Result<()> {
    let cfg = Arc::new(config::Config::from_cli(&cli)?);
    cfg.ensure_dirs().context("каталоги сессий")?;

    let store = Arc::new(store::SessionStore::open(&cfg.sessions_dir)?);
    let (bus, _) = broadcast::channel::<models::ServerMsg>(4096);
    let capture = Arc::new(capture::CaptureManager::new(cfg.clone(), store.clone(), bus.clone()));
    capture.spawn_workers().await?;

    let state = api::AppState {
        cfg: cfg.clone(),
        store,
        capture,
        bus,
        started: std::time::Instant::now(),
    };

    let app = api::router(state);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("не удалось занять порт {}", cfg.port))?;

    let url = format!("http://127.0.0.1:{}/", cfg.port);
    tracing::info!("FTDI/USB Logger слушает {url}");
    if cfg.open_ui {
        let u = url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", "", "msedge", &format!("--app={u}")])
                .spawn();
        });
    }

    axum::serve(listener, app).await?;
    Ok(())
}

