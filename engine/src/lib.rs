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
pub mod proxy;
pub mod usbpcap;
pub mod scope;
pub mod uiactions;
pub mod textfix;
pub mod signals;
pub mod operations;

use std::sync::Arc;
use anyhow::Context;
use tokio::sync::broadcast;

/// Точка входа: собрать состояние, поднять HTTP/WS и жить до Ctrl+C.
pub async fn run(cli: config::Cli) -> anyhow::Result<()> {
    let cfg = Arc::new(config::Config::from_cli(&cli)?);
    cfg.ensure_dirs().context("каталоги сессий")?;

    // J2534-прокси лежит в пользовательском каталоге, и его файл может подменить
    // сторонний установщик: тогда устройство грузит чужой драйвер, а интерфейс
    // честно показывает «не подхвачен». Возвращаем нашу DLL до открытия окна —
    // иначе пользователь узнаёт о поломке только по отсутствию захвата.
    let proxy_dir = cfg.root.join("j2534proxy");
    if proxy::read_ini(&proxy_dir).enabled {
        if let Some(note) = proxy::ensure_dll(&proxy_dir) {
            tracing::warn!("{note}");
        }
    }

    let store = Arc::new(store::SessionStore::open(&cfg.sessions_dir)?);
    let (bus, _) = broadcast::channel::<models::ServerMsg>(4096);
    let capture = Arc::new(capture::CaptureManager::new(cfg.clone(), store.clone(), bus.clone()));
    capture.spawn_workers().await?;
    capture.spawn_target_watchdog();

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


