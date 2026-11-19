//! `ftdi-j2534proxy-setup` — регистрация J2534-прокси без запуска движка.
//!
//! Зачем отдельный бинарник: установщик Inno ставится per-user (без прав), а
//! запись J2534-устройства живёт в HKLM. Установщик вызывает этот helper через
//! UAC (`ShellExec('runas', …)`), и отмена запроса не валит установку: прокси
//! включается позже из интерфейса, где движок уже запущен с правами
//! администратора (docs/13-j2534-proxy.md §5, §10).
//!
//! Коды возврата:
//!   0 — успех;
//!   2 — нужны права администратора (отказ доступа, а не поломка);
//!   1 — прочая ошибка (текст в stderr).

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Отказ доступа: установщик по этому коду отличает отменённый UAC от ошибки.
const EXIT_NEED_ADMIN: u8 = 2;

#[cfg(windows)]
extern "system" {
    /// Переключение кодовой страницы консоли на UTF-8 (см. `main`).
    fn SetConsoleOutputCP(code_page: u32) -> i32;
}

#[derive(Parser)]
#[command(
    name = "ftdi-j2534proxy-setup",
    version,
    about = "Регистрация J2534-прокси FTDI/USB Logger (нужны права администратора)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Записать ini и зарегистрировать устройство в PassThruSupport.04.04
    Install {
        /// Каталог установки (внутри него лежит j2534proxy\)
        #[arg(long)]
        app: PathBuf,
        /// Настоящий драйвер; без него путь берётся из реестра J2534
        #[arg(long)]
        real: Option<String>,
    },
    /// Снять регистрацию и вернуть адаптер PCMflash
    Remove {
        #[arg(long)]
        app: PathBuf,
    },
    /// Включить прокси (Enabled=1) без перерегистрации
    Enable {
        #[arg(long)]
        app: PathBuf,
    },
    /// Выключить прокси (Enabled=0) и вернуть адаптер PCMflash
    Disable {
        #[arg(long)]
        app: PathBuf,
    },
    /// Показать состояние
    Status {
        #[arg(long)]
        app: PathBuf,
        /// Печатать JSON (для скриптов и отладки)
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    // Консоль Windows по умолчанию в CP866, а мы печатаем UTF-8: без этого
    // «каталог:» превращается в «╨║╨░╤В╨░╨╗╨╛╨│:». Установщик зовёт helper
    // скрыто, но вручную его запускают из cmd/PowerShell — вывод должен читаться.
    #[cfg(windows)]
    unsafe {
        SetConsoleOutputCP(65001);
    }
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Install { app, real } => {
            let dir = install_dir(&app);
            ftdi_logger::proxy::install(&dir, real.as_deref()).map(|status| print_state(&status))
        }
        Cmd::Remove { app } => {
            let dir = install_dir(&app);
            ftdi_logger::proxy::remove(&dir).map(|status| print_state(&status))
        }
        Cmd::Enable { app } => {
            let dir = install_dir(&app);
            ftdi_logger::proxy::set_enabled(&dir, true).map(|status| print_state(&status))
        }
        Cmd::Disable { app } => {
            let dir = install_dir(&app);
            ftdi_logger::proxy::set_enabled(&dir, false).map(|status| print_state(&status))
        }
        Cmd::Status { app, json } => {
            let dir = install_dir(&app);
            let status = ftdi_logger::proxy::status(&dir);
            if json {
                match serde_json::to_string_pretty(&status) {
                    Ok(text) => {
                        println!("{text}");
                        Ok(())
                    }
                    Err(err) => Err(anyhow::anyhow!("сериализация состояния: {err}")),
                }
            } else {
                print_state(&status);
                Ok(())
            }
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let text = format!("{err:#}");
            eprintln!("{text}");
            // Текст ошибки нужен установщику: по нему он решает, просить ли
            // права ещё раз или показать «включите вручную в настройках».
            if needs_admin(&text) {
                ExitCode::from(EXIT_NEED_ADMIN)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Каталог прокси внутри установки: `<app>\j2534proxy`.
fn install_dir(app: &Path) -> PathBuf {
    app.join("j2534proxy")
}

/// Признак «не хватило прав» в тексте ошибки (Windows отдаёт по-разному:
/// `os error 5`, `Access is denied`, локализованное «Отказано в доступе»).
fn needs_admin(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("требуются права администратора")
        || t.contains("отказано в доступе")
        || t.contains("access is denied")
        || t.contains("os error 5")
}

fn print_state(status: &ftdi_logger::proxy::ProxyStatus) {
    let yes = |b: bool| if b { "есть" } else { "нет" };
    println!("каталог:  {}", status.install_dir);
    println!(
        "DLL:      {} ({}){}",
        yes(status.dll.present),
        status.dll.path,
        if status.dll.version.is_empty() {
            String::new()
        } else {
            format!(", v{}", status.dll.version)
        }
    );
    println!(
        "ini:      {} (Enabled={})",
        yes(status.ini.present),
        if status.ini.enabled { 1 } else { 0 }
    );
    println!(
        "реестр:   {}",
        if status.registry.registered {
            format!("зарегистрировано как «{}»", status.registry.device_name)
        } else {
            "не зарегистрировано".to_string()
        }
    );
    println!(
        "драйвер:  {} ({})",
        if status.real.path.is_empty() {
            "не найден".to_string()
        } else {
            status.real.path.clone()
        },
        status.real.from
    );
    println!("журналы:  {} ({} файлов)", status.log_dir, status.log_files);
    println!(
        "PCMflash: {} ({})",
        if status.pcmflash.adapter.is_empty() {
            "выбор не найден".to_string()
        } else {
            status.pcmflash.adapter.clone()
        },
        if status.pcmflash.proxy_selected {
            "наш адаптер"
        } else {
            "не наш адаптер"
        }
    );
    if !status.elevated {
        println!("права:    без администратора (регистрация невозможна)");
    }
    for note in &status.notes {
        println!("  · {note}");
    }
}
