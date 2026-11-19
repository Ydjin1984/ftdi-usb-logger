//! Регрессия «логируется только первый шаг»: перевешивание хуков при
//! перезагрузке адаптерной DLL.
//!
//! Симптом (лог PCMflash, сессия 20261118-171740-pcmflash): шаг 1 «Идентификация»
//! писался полностью (54 посылки), а шаг 2 «Чтение фулл флеш» — ноль строк, хотя
//! процесс жил и сетевые события агента шли. Причина: PCMflash закрывает
//! устройство между действиями (`PassThruClose` → `FreeLibrary(smj2534.dll)`), а
//! для следующего действия грузит DLL снова, и Windows обычно кладёт её по тому же
//! base. Наши патчи исчезают вместе с её кодом, но ключ `j2534Hooked["модуль|base"]`
//! и адреса в `hookedAddrs` оставались — повторный `onAdded` ранне выходил.
//!
//! Здесь два уровня проверки:
//! * `agent_contract_*` — быстрый сторож по исходнику агента (без Frida);
//! * `real_j2534_reload_*` — ручной E2E: поддельная J2534-DLL грузится, вызывается
//!   `PassThruOpen`, DLL выгружается и грузится заново. Нужны frida и карго.
//!
//! Ручной запуск:
//! `cargo test --test agent_reload_hooks -- --ignored --nocapture`

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use ftdi_logger::capture::CaptureManager;
use ftdi_logger::config::Config;
use ftdi_logger::models::ServerMsg;
use ftdi_logger::store::SessionStore;
use tokio::sync::broadcast;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine/ имеет родителя — корень репозитория")
        .to_path_buf()
}

fn agent_source() -> String {
    let path = repo_root()
        .join("sidecar")
        .join("agents")
        .join("universal_capture.js");
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("нет {}: {err}", path.display()))
}

/// Сторож по исходнику агента: без Frida и быстро. Ловит именно тот регресс,
/// который дал пустой второй шаг, — «ключ модуля не снимается никогда».
#[test]
fn agent_contract_reinstalls_hooks_after_module_reload() {
    let js = agent_source();

    // 1. Слушаем именно выгрузку модуля, а не только загрузку.
    assert!(
        js.contains("onRemoved"),
        "агент не подписан на onRemoved: выгрузка DLL не снимает хуки"
    );
    // 2. Ключи и адреса освобождаются при выгрузке/перезагрузке.
    assert!(
        js.contains("function invalidateModule("),
        "нет invalidateModule(): ключ «модуль|base» останется навсегда"
    );
    assert!(
        js.contains("function detachOwner("),
        "нет detachOwner(): адреса не освобождаются, повторная установка не сработает"
    );
    assert!(
        js.contains("hookedAddrs.delete(e.addr)"),
        "detachOwner не освобождает адрес в hookedAddrs — attachHook откажет"
    );
    // 3. Страховка на случай, если onRemoved не пришёл.
    assert!(
        js.contains("function hookDllLoadWatch("),
        "нет сторожа загрузки DLL — перезагрузка мимо onRemoved потеряет второй шаг"
    );
    for name in [
        "LoadLibraryW",
        "LoadLibraryA",
        "LoadLibraryExW",
        "LoadLibraryExA",
    ] {
        assert!(
            js.contains(name),
            "сторож не слушает {name}: загрузка DLL останется незамеченной"
        );
    }
    // 4. Каждый listener помнит владельца — иначе не понять, чьи хуки снимать.
    assert!(
        js.contains("listeners.push({ l: l, addr: key, owner: currentOwner })"),
        "listener без владельца: выгрузку DLL не связать с её хуками"
    );
    for owner in [
        "function hookFtModule(mod) {\n  ftMod = mod;\n  setOwner(modKey(mod));",
        "function hookJ2534Module(mod) {",
        "function hookLanModule(mod) {",
        "function hookWinUsbModule(mod) {",
        "function hookHidModule(mod) {",
        "function hookLibusbModule(mod) {",
    ] {
        assert!(
            js.contains(owner),
            "в {} не проставлен владелец хуков",
            owner.lines().next().unwrap_or(owner)
        );
    }
    // 5. Пауза тоже снимает хуки — записи стали объектами, старый вызов сломался бы.
    assert!(
        js.contains("listeners[i].l.detach()"),
        "pauseHooks обращается к listener как к объекту? проверь .l.detach()"
    );
}

fn python_with_frida() -> Option<PathBuf> {
    let bundled = repo_root().join("python").join("python.exe");
    let mut candidates = vec![bundled];
    for p in [
        r"C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe",
        r"C:\Users\User\AppData\Local\Programs\Python\Python313\python.exe",
        r"C:\Users\User\AppData\Local\Programs\Python\Python311\python.exe",
    ] {
        candidates.push(PathBuf::from(p));
    }
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let ok = Command::new(&path)
            .args(["-c", "import frida"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if ok {
            return Some(path);
        }
    }
    None
}

/// Ручной E2E: две загрузки поддельной J2534-DLL по одному base, оба
/// `PassThruOpen` должны попасть в `raw.log`.
#[test]
#[ignore]
fn real_j2534_reload_logs_both_opens() {
    let Some(python) = python_with_frida() else {
        eprintln!("python с frida не найден — ручной E2E пропущен");
        return;
    };
    let repo = repo_root();
    let target = repo.join("tests").join("e2e").join("j2534_reload_target.py");
    let manifest = repo
        .join("tests")
        .join("e2e")
        .join("fake_j2534")
        .join("Cargo.toml");
    assert!(target.is_file(), "нет {}", target.display());
    assert!(manifest.is_file(), "нет {}", manifest.display());

    let tmp = tempfile::tempdir().expect("tempdir");
    let target_dir = tmp.path().join("fake-target");
    let build = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--manifest-path",
            &manifest.display().to_string(),
            "--target-dir",
            &target_dir.display().to_string(),
        ])
        .output()
        .expect("запустить cargo для fake_j2534");
    assert!(
        build.status.success(),
        "сборка fake_j2534: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let dll = target_dir.join("release").join("fake_j2534.dll");
    assert!(dll.is_file(), "нет {}", dll.display());

    let sessions = tmp.path().join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let cfg = Arc::new(Config {
        root: repo.clone(),
        sessions_dir: sessions,
        ui_dist: repo.join("ui").join("dist"),
        port: 0,
        python: python.clone(),
        sidecar: repo.join("sidecar").join("bridge.py"),
        script: repo
            .join("sidecar")
            .join("agents")
            .join("universal_capture.js"),
        open_ui: false,
        no_bridge: false,
        discovery_ms: 2000,
        max_event_bytes: 64 * 1024,
    });
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).expect("store"));
    let (bus, _) = broadcast::channel::<ServerMsg>(4096);
    let manager = Arc::new(CaptureManager::new(cfg, store, bus));

    let go = tmp.path().join("go.flag");
    let mut host = Command::new(&python)
        .arg(&target)
        .arg(&dll)
        .arg(&go)
        .spawn()
        .expect("запустить j2534_reload_target.py");

    std::thread::sleep(Duration::from_millis(1500));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let meta = rt
        .block_on(async { manager.attach(host.id(), "reload-target".into(), None).await })
        .expect("attach к reload-цели через Frida");
    eprintln!("attach ok: session={} pid={:?}", meta.id, meta.pid);

    std::fs::write(&go, b"go").expect("создать флаг");
    // Цель: load+open, free, load+open, free — по 1.5 с между шагами.
    rt.block_on(async { tokio::time::sleep(Duration::from_secs(9)).await });

    let finished = rt
        .block_on(async { manager.detach().await })
        .expect("detach")
        .expect("мета сессии");
    let _ = host.kill();
    let _ = host.wait();

    let raw_path = Path::new(&finished.dir).join("raw.log");
    let raw = std::fs::read_to_string(&raw_path).expect("raw.log");
    let opens = raw
        .lines()
        .filter(|line| line.contains("J2534 open "))
        .count();
    eprintln!("--- raw.log (J2534/модули) ---");
    for line in raw.lines() {
        if line.contains("J2534 ") || line.contains("MODULE") {
            eprintln!("{line}");
        }
    }
    assert!(
        raw.contains("MODULE ~"),
        "агент не заметил перезагрузку DLL — второй проход снова уйдёт в пустоту"
    );
    assert!(
        opens >= 2,
        "PassThruOpen залогирован {opens} раз из 2 — хуки не перевесились после перезагрузки"
    );
}
