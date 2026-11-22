//! Контракт с осциллографом «Хелтег да Винчи» на реальном ответе `/api/capture/v2`.
//!
//! Фикстура `fixtures/scope_capture_v2.json` снята с работающей службы
//! (`GET /api/capture/v2?width=500`, три включённых канала). Тест поднимает
//! крошечный HTTP-сервер на 127.0.0.1:0 и отдаёт её — так проверяется весь путь
//! «сокет → заголовки → chunked → JSON → Frame», а не только парсер JSON.
//!
//! Внешняя сеть не используется: единственный «недоступный» адрес — порт 9 на
//! localhost, где заведомо никто не слушает.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ftdi_logger::scope::{
    fetch_channels, fetch_frame, probe, spawn_poller, PollMsg, ScopeConfig, DEFAULT_URL,
};
use serde_json::{json, Value};

const FIXTURE: &str = include_str!("fixtures/scope_capture_v2.json");

/// Ответ `/api/info` «по образцу» живой службы: только нужные тесту поля.
fn info_json() -> String {
    json!({
        "running": true,
        "link": "mock-device",
        "sample_rate": 600000.0,
        "block_samples": 1000,
        "blocks_per_s": 17.7,
        "time_div": "20 ns/div",
        "window_s": 0.0016666,
        "error": null,
        "state": "free",
        "frame_id": 1,
        "held": false,
        "rec": false,
        "trigger": {"mode": "free", "edge": "rise", "source": 0, "level_v": -0.365},
        "blocks_total": 1,
    })
    .to_string()
}

/// Ответ `/api/channels` как у живой службы: `ch` 1..8 (не 0..7, как обещает
/// контракт) — клиент обязан понять нумерацию сам.
fn channels_json() -> String {
    let mut items = Vec::new();
    for ch in 1..=8usize {
        let on = ch <= 3;
        let freq = if ch == 1 { Some(1000.0) } else { None };
        items.push(json!({
            "ch": ch,
            "enabled": on,
            "autoscale": false,
            "range": "±20 V",
            "range_id": 3,
            "range_v": if ch <= 2 { 6.0 } else { 20.0 },
            "min": if on { Some(-0.39) } else { None },
            "max": if on { Some(-0.29) } else { None },
            "pp": if on { Some(0.1) } else { None },
            "mean": if on { Some(-0.33) } else { None },
            "rms": if on { Some(0.33) } else { None },
            "rms_ac": if on { Some(0.008) } else { None },
            "freq": freq,
            "duty": if ch == 1 { Some(50.0) } else { None },
            "peak_min": null,
            "peak_max": null,
            "resolution": 0.01,
        }));
    }
    json!(items).to_string()
}

/// Сервер, изображающий службу осциллографа: три ручки, ответ по пути запроса.
struct MockScope {
    url: String,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl MockScope {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind 127.0.0.1:0");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("local_addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => serve(&mut stream),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}"),
            stop,
            join: Some(join),
        }
    }
}

impl Drop for MockScope {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Прочитать запрос и ответить по пути.
///
/// Кадр отдаём chunked с расширениями и мелкими кусками: клиент обязан собрать
/// тело из чанков, а не полагаться на Content-Length.
fn serve(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut head: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&head);
    let path = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let (body, chunked) = if path.starts_with("/api/info") {
        (info_json(), false)
    } else if path.starts_with("/api/channels") {
        (channels_json(), false)
    } else if path.starts_with("/api/capture/v2") {
        (FIXTURE.to_string(), true)
    } else {
        (String::from("{}"), false)
    };
    let response: Vec<u8> = if chunked {
        let bytes = body.as_bytes();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
              Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        );
        for part in bytes.chunks(7777) {
            out.extend_from_slice(format!("{:x};part=1\r\n", part.len()).as_bytes());
            out.extend_from_slice(part);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    } else {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    };
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

fn close_enough(actual: f64, expected: f64) -> bool {
    (actual - expected).abs() <= 1e-9 * expected.abs().max(1.0)
}

#[test]
fn fixture_frame_is_parsed_over_real_http() {
    let mock = MockScope::start();
    let cfg = ScopeConfig {
        enabled: true,
        url: mock.url.clone(),
        width: 500,
        ..ScopeConfig::default()
    };
    let frame = fetch_frame(&cfg).expect("кадр должен разобраться");
    let fx: Value = serde_json::from_str(FIXTURE).expect("фикстура — валидный JSON");

    assert_eq!(frame.frame_id, fx["frame_id"].as_u64().unwrap());
    assert_eq!(frame.generation, 0);
    assert_eq!(frame.n_block, 1000);
    assert!(close_enough(
        frame.sample_rate,
        fx["sample_rate"].as_f64().unwrap()
    ));
    assert!(close_enough(frame.dt_s, fx["dt_s"].as_f64().unwrap()));
    assert!(close_enough(
        frame.window_s,
        fx["window_s"].as_f64().unwrap()
    ));
    assert_eq!(frame.state, "free");
    assert!(!frame.held);

    // channels в API 0-based (0,1,2) → в Frame 1..8.
    assert_eq!(frame.channels, vec![1, 2, 3]);
    assert_eq!(frame.channel_meta.len(), 3);
    for (index, info) in frame.channel_meta.iter().enumerate() {
        assert_eq!(info.ch, index + 1);
        assert_eq!(info.raw_ch, index);
        assert!(info.enabled, "meta приходит только по включённым каналам");
    }
    // Шкала из channel_meta: у первых двух ±6 В, у третьего ±20 В.
    assert_eq!(frame.channel_meta[0].full_scale_v, 6.0);
    assert_eq!(frame.channel_meta[2].full_scale_v, 20.0);
    assert_eq!(frame.channel_meta[0].range, "±6 V");
    assert_eq!(frame.channel_meta[2].range, "±20 V");
    assert_eq!(frame.channel_meta[0].center_v, 0.0);

    // stats: измерения есть, freq/duty у фикстуры — null (сигнал без фронтов).
    assert_eq!(frame.stats.len(), 3);
    for (index, stat) in frame.stats.iter().enumerate() {
        assert_eq!(stat.ch, index + 1);
        assert_eq!(stat.n, 1000);
        assert!(!stat.aliased);
        assert!(close_enough(stat.window_s, frame.window_s));
    }
    assert!(frame.stats[0].vpp.unwrap() > 0.0);
    assert!(frame.stats[0].vmin.is_some() && frame.stats[0].vmax.is_some());
    assert!(frame.stats[0].freq.is_none(), "в фикстуре freq = null");
    assert!(frame.stats[0].duty.is_none(), "в фикстуре duty = null");
    // ChannelInfo берёт min/max/pp из stats (там точнее, чем пики meta).
    assert_eq!(frame.channel_meta[0].min, frame.stats[0].vmin);
    assert_eq!(frame.channel_meta[0].max, frame.stats[0].vmax);
    assert_eq!(frame.channel_meta[0].pp, frame.stats[0].vpp);

    // base64: длина строки и распакованный размер сходятся с ответом API.
    let expected_bytes = fx["columns_bytes"].as_u64().unwrap() as usize;
    assert_eq!(frame.columns_bytes, expected_bytes);
    assert_eq!(frame.columns_bytes, 6000);
    assert_eq!(frame.columns_b64.len() * 3 / 4, frame.columns_bytes);

    // trigger — свободный Value: структура у службы меняется, ломать разбор
    // из-за нового поля нельзя.
    assert!(frame.trigger.is_object());
    assert_eq!(frame.trigger["mode"], json!("free"));
    assert!(frame.trigger["level_v"].is_number());
}

#[test]
fn channels_come_back_in_human_numbering() {
    let mock = MockScope::start();
    let cfg = ScopeConfig {
        enabled: true,
        url: mock.url.clone(),
        ..ScopeConfig::default()
    };
    let channels = fetch_channels(&cfg).expect("/api/channels должен разобраться");
    assert_eq!(channels.len(), 8);
    for (index, info) in channels.iter().enumerate() {
        assert_eq!(info.ch, index + 1);
        assert_eq!(info.raw_ch, index);
    }
    // Живая служба отдаёт ch 1..8, контракт обещает 0..7: клиент приводит к
    // CH1..CH8 сам, иначе подписи съехали бы на единицу.
    // Подпись диапазона строится по фактической шкале (`range_v`), а не по
    // строке службы: у CH1/CH2 она «±20 V» при range_v 6 В (docs/14 §2).
    assert_eq!(channels[0].range, "±6 V");
    assert_eq!(channels[0].range_id, 3);
    assert_eq!(channels[0].full_scale_v, 6.0);
    assert_eq!(channels[0].freq, Some(1000.0));
    assert_eq!(channels[0].duty, Some(50.0));
    assert!(channels[0].enabled);
    assert!(!channels[3].enabled, "CH4 в моке выключен");
    assert!(
        channels[3].min.is_none(),
        "у выключенного канала null-измерения"
    );
}

#[test]
fn probe_reports_live_service_and_frame() {
    let mock = MockScope::start();
    let cfg = ScopeConfig {
        enabled: true,
        url: mock.url.clone(),
        width: 500,
        ..ScopeConfig::default()
    };
    let result = probe(&cfg);
    assert!(result.page_ok, "страница службы должна ответить");
    assert!(result.frame_ok, "кадр должен разобраться");
    assert!(result.ok);
    assert_eq!(result.page_status, 200);
    assert!(
        result.error.is_none(),
        "при успехе error пуст: {:?}",
        result.error
    );
    assert_eq!(result.url, mock.url);
    assert_eq!(result.service.as_ref().unwrap()["running"], json!(true));
    assert_eq!(result.channels.len(), 8);
    let frame = result.frame.expect("кадр должен быть в результате probe");
    assert!(!frame.columns_b64.is_empty());
    assert_eq!(frame.channels, vec![1, 2, 3]);
}

#[test]
fn poller_streams_channels_then_frames() {
    let mock = MockScope::start();
    let cfg = ScopeConfig {
        enabled: true,
        url: mock.url.clone(),
        interval_ms: 20,
        width: 500,
        ..ScopeConfig::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let stop = Arc::new(AtomicBool::new(false));
    let handle = spawn_poller(cfg, "sess-poller".to_string(), tx, Arc::clone(&stop));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let messages = runtime.block_on(async {
        let mut out = Vec::new();
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(message)) => out.push(message),
                _ => break,
            }
        }
        out
    });
    stop.store(true, Ordering::Relaxed);
    assert!(handle.join().is_ok(), "поток опроса не должен паниковать");

    assert!(messages.len() >= 2, "ожидали каналы и хотя бы один кадр");
    match &messages[0] {
        PollMsg::Channels(channels) => assert_eq!(channels.len(), 8),
        other => panic!("первым сообщением должны идти каналы, получили {other:?}"),
    }
    let frame = messages
        .iter()
        .find_map(|message| match message {
            PollMsg::Frame { frame, wall, .. } => Some((frame.as_ref(), wall.as_str())),
            _ => None,
        })
        .expect("должен прийти хотя бы один кадр");
    assert_eq!(frame.0.channels, vec![1, 2, 3]);
    assert!(frame.1.ends_with('Z'), "wall должен быть UTC: {}", frame.1);
    // Событие связи шлётся только на переходе «плохо → хорошо»: первый же
    // успешный опрос его не порождает, иначе на каждый кадр уходила бы строка
    // журнала. Успешный опрос не имеет права сообщать о потере связи.
    assert!(
        !messages
            .iter()
            .any(|message| matches!(message, PollMsg::Link { ok: false, .. })),
        "успешный опрос не должен сообщать о потере связи"
    );
    if let Some(PollMsg::Link { page_ok, frame_ok, .. }) = messages
        .iter()
        .find(|message| matches!(message, PollMsg::Link { .. }))
    {
        assert!(*page_ok && *frame_ok);
    }
}

#[test]
fn unreachable_service_is_reported_without_panic() {
    // Порт 9 (discard) на localhost: сеть не нужна. На этой машине Windows
    // молча роняет пакет, поэтому соединение упирается ровно в дедлайн запроса
    // (2 с) — это и проверяем: без паники, с внятной ошибкой и без зависания.
    let cfg = ScopeConfig {
        enabled: true,
        url: "http://127.0.0.1:9".to_string(),
        ..ScopeConfig::default()
    };
    let started = Instant::now();
    let result = probe(&cfg);
    assert!(!result.ok);
    assert!(!result.page_ok);
    assert!(!result.frame_ok);
    assert_eq!(result.page_status, 0);
    assert!(result.service.is_none());
    assert!(result.frame.is_none());
    let error = result.error.as_deref().unwrap_or("");
    assert!(!error.is_empty(), "ошибка обязана быть непустой");
    // probe делает три запроса по 2 с: больше — значит дедлайн не работает.
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "probe не должен ждать дольше трёх таймаутов"
    );

    let single = Instant::now();
    let frame_error = fetch_frame(&cfg).expect_err("кадра быть не может");
    assert!(!frame_error.is_empty());
    assert!(
        single.elapsed() <= Duration::from_secs(3),
        "один запрос обязан укладываться в таймаут 2 с: {:?}",
        single.elapsed()
    );
    // fetch_info/fetch_channels идут тем же путём (http_get → проверка статуса),
    // их падение на живом моке уже проверено выше — здесь не дублируем.
}

#[test]
fn default_url_points_at_local_service() {
    assert_eq!(DEFAULT_URL, "http://127.0.0.1:7411");
    let cfg = ScopeConfig::default();
    assert_eq!(cfg.url, DEFAULT_URL);
    assert!(!cfg.enabled, "по умолчанию осциллограф не опрашивается");
}
