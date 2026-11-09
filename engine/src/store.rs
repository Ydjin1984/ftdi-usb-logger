//! Хранилище сессий. Владелец: ded-bekend.
//!
//! Каталог сессии (docs/02 §4):
//! ```text
//! <root>/index.json, index.md
//! <root>/<id>/{session.json,state.json,events.jsonl,events.idx,raw.log,
//!              steps/<NN>.json,shots/,reads/,files/,export/,import/,report.txt,report.md}
//! ```
//! `events.jsonl` — append-only канонические события (батчами, flush ≤ 50 мс),
//! `events.idx` — смещения каждые 1000 событий для быстрого seek.

use crate::models::{
    now_rfc3339, util, Event, EventKind, SessionMeta, StepSummary,
};
use anyhow::{anyhow, Context};
use parking_lot::{Mutex, RwLock};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Как часто пишем запись в `events.idx`.
const INDEX_EVERY: u64 = 1000;
/// Сколько событий копим до сброса.
const BATCH_EVENTS: usize = 256;
/// Сколько байт JSONL копим до сброса.
const BATCH_BYTES: usize = 256 * 1024;
/// Предельный интервал между сбросами.
const FLUSH_MS: u128 = 50;

/// Список подкаталогов, которые обязаны существовать в сессии.
const SESSION_SUBDIRS: &[&str] = &["steps", "shots", "reads", "files", "export", "import"];

// ───────────────────────────── атомарная запись ───────────────────────────

fn tmp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    path.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
}

/// Записать JSON/текст во временный файл и переименовать (atomic на одном томе).
pub fn write_json_atomic<T: Serialize + ?Sized>(path: &Path, value: &T) -> anyhow::Result<()> {
    let text = serde_json::to_vec_pretty(value).context("сериализация JSON")?;
    write_bytes_atomic(path, &text)
}

pub fn write_text_atomic(path: &Path, text: &str) -> anyhow::Result<()> {
    write_bytes_atomic(path, text.as_bytes())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("не создать каталог {}", parent.display()))?;
    }
    let tmp = tmp_path(path);
    {
        let mut f = File::create(&tmp).with_context(|| format!("не создать {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("не записать {}", tmp.display()))?;
        f.sync_all().ok();
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(first) => {
            // На некоторых ФС rename поверх существующего файла капризничает.
            let _ = fs::remove_file(path);
            fs::rename(&tmp, path)
                .with_context(|| format!("не заменить {}: {first}", path.display()))
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn load_index(root: &Path) -> Vec<SessionMeta> {
    read_json::<Vec<SessionMeta>>(&root.join("index.json")).unwrap_or_default()
}

/// Прочитать `session.json` всех каталогов сессий (страховка, если индекс потерян).
fn scan_sessions(root: &Path) -> Vec<SessionMeta> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(root) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(mut meta) = read_json::<SessionMeta>(&path.join("session.json")) {
            if meta.dir.is_empty() {
                meta.dir = path.to_string_lossy().to_string();
            }
            out.push(meta);
        }
    }
    out
}

fn sort_sessions(sessions: &mut [SessionMeta]) {
    sessions.sort_by(|a, b| {
        b.started_at
            .cmp(&a.started_at)
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn md_escape(text: &str) -> String {
    text.replace('|', "/").replace('\n', " ")
}

fn render_index_md(sessions: &[SessionMeta]) -> String {
    let mut out = String::new();
    out.push_str("# Сессии FTDI/USB Logger\n\n");
    out.push_str(&format!("Всего: {}\n\n", sessions.len()));
    out.push_str("| id | label | started_at | events | steps | status |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for s in sessions {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            md_escape(&s.id),
            md_escape(&s.label),
            md_escape(&s.started_at),
            s.counts.events,
            s.counts.steps,
            md_escape(&s.status),
        ));
    }
    out
}

fn save_index(root: &Path, sessions: &[SessionMeta]) -> anyhow::Result<()> {
    let mut sorted = sessions.to_vec();
    sort_sessions(&mut sorted);
    write_json_atomic(&root.join("index.json"), &sorted)?;
    write_text_atomic(&root.join("index.md"), &render_index_md(&sorted))?;
    Ok(())
}

fn sanitize_id(id: &str) -> anyhow::Result<String> {
    let id = id.trim();
    if id.is_empty() {
        anyhow::bail!("пустой id сессии");
    }
    if id.contains("..") || id.contains('/') || id.contains('\\') || id.contains(':') {
        anyhow::bail!("недопустимый id сессии: {id}");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!("недопустимый id сессии: {id}");
    }
    Ok(id.to_string())
}

fn default_id(label: &str) -> String {
    let slug = util::slug(label);
    let base = if slug.is_empty() { "session".into() } else { slug };
    format!(
        "{}-{}",
        base,
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    )
}

fn count_events_on_disk(dir: &Path) -> u64 {
    let path = dir.join("events.jsonl");
    let Ok(file) = File::open(&path) else {
        return 0;
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .count() as u64
}

fn state_json(meta: &SessionMeta) -> Value {
    let t0_epoch = chrono::DateTime::parse_from_rfc3339(&meta.started_at)
        .map(|d| d.timestamp())
        .unwrap_or_else(|_| chrono::Utc::now().timestamp());
    json!({
        "t0_epoch": t0_epoch,
        "t0_wall": meta.started_at,
        "log": "raw.log",
        "label": meta.label,
        "exe": meta.tool_path,
        "proc": meta.process,
        "pid": meta.pid,
        "transport": meta.transport,
        "status": meta.status,
    })
}

fn write_state(dir: &Path, meta: &SessionMeta) -> anyhow::Result<()> {
    write_json_atomic(&dir.join("state.json"), &state_json(meta))
}

// ──────────────────────────────── store ──────────────────────────────────

pub struct SessionStore {
    root: PathBuf,
    sessions: Arc<RwLock<Vec<SessionMeta>>>,
    /// Сериализует перезапись index.json/index.md.
    index_lock: Mutex<()>,
}

impl SessionStore {
    pub fn open(root: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(root)
            .with_context(|| format!("не создать каталог сессий {}", root.display()))?;
        let mut sessions = load_index(root);
        // Если индекс пуст/битый — поднимаем из session.json; чистим записи без каталога.
        if sessions.is_empty() {
            sessions = scan_sessions(root);
        } else {
            let known: std::collections::HashSet<String> =
                sessions.iter().map(|s| s.id.clone()).collect();
            for meta in scan_sessions(root) {
                if !known.contains(&meta.id) {
                    sessions.push(meta);
                }
            }
            sessions.retain(|s| root.join(&s.id).is_dir());
        }
        sort_sessions(&mut sessions);
        let store = Self {
            root: root.to_path_buf(),
            sessions: Arc::new(RwLock::new(sessions)),
            index_lock: Mutex::new(()),
        };
        {
            let _g = store.index_lock.lock();
            let list = store.sessions.read().clone();
            save_index(&store.root, &list)?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dir_for(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub fn list(&self) -> Vec<SessionMeta> {
        let mut out = self.sessions.read().clone();
        sort_sessions(&mut out);
        out
    }

    pub fn get(&self, id: &str) -> Option<SessionMeta> {
        self.sessions.read().iter().find(|s| s.id == id).cloned()
    }

    pub fn create(&self, mut meta: SessionMeta) -> anyhow::Result<SessionWriter> {
        let _g = self.index_lock.lock();
        if meta.id.trim().is_empty() {
            meta.id = default_id(&meta.label);
        }
        meta.id = sanitize_id(&meta.id)?;

        // Уникальный id.
        let base = meta.id.clone();
        let mut candidate = base.clone();
        let mut n = 2u32;
        while self.dir_for(&candidate).exists()
            || self.sessions.read().iter().any(|s| s.id == candidate)
        {
            candidate = format!("{base}-{n}");
            n += 1;
            if n > 10_000 {
                anyhow::bail!("не удалось подобрать уникальный id сессии");
            }
        }
        meta.id = candidate;

        let dir = self.dir_for(&meta.id);
        fs::create_dir_all(&dir)
            .with_context(|| format!("не создать каталог сессии {}", dir.display()))?;
        for sub in SESSION_SUBDIRS {
            fs::create_dir_all(dir.join(sub))?;
        }
        if meta.started_at.trim().is_empty() {
            meta.started_at = now_rfc3339();
        }
        meta.dir = dir.to_string_lossy().to_string();
        if meta.engine_version.is_empty() {
            meta.engine_version = env!("CARGO_PKG_VERSION").to_string();
        }
        if meta.status.trim().is_empty() {
            meta.status = "recording".into();
        }
        write_json_atomic(&dir.join("session.json"), &meta)?;
        write_state(&dir, &meta)?;
        for name in ["events.jsonl", "raw.log", "events.idx"] {
            let path = dir.join(name);
            if !path.exists() {
                File::create(&path)?;
            }
        }

        {
            let mut list = self.sessions.write();
            list.retain(|s| s.id != meta.id);
            list.push(meta.clone());
            save_index(&self.root, &list)?;
        }
        SessionWriter::open(
            dir,
            meta,
            self.sessions.clone(),
            self.root.clone(),
            0,
        )
    }

    /// Append в существующую сессию: seq продолжается с последнего события.
    pub fn writer(&self, id: &str) -> anyhow::Result<SessionWriter> {
        let meta = self
            .get(id)
            .ok_or_else(|| anyhow!("сессия {id} не найдена"))?;
        let dir = self.dir_for(id);
        if !dir.is_dir() {
            anyhow::bail!("каталог сессии {} отсутствует", dir.display());
        }
        let next_seq = count_events_on_disk(&dir);
        SessionWriter::open(dir, meta, self.sessions.clone(), self.root.clone(), next_seq)
    }

    pub fn reader(&self, id: &str) -> anyhow::Result<SessionReader> {
        let meta = self
            .get(id)
            .ok_or_else(|| anyhow!("сессия {id} не найдена"))?;
        let dir = self.dir_for(id);
        if !dir.is_dir() {
            anyhow::bail!("каталог сессии {} отсутствует", dir.display());
        }
        Ok(SessionReader {
            dir,
            meta,
            offsets: None,
        })
    }

    pub fn delete(&self, id: &str) -> anyhow::Result<()> {
        let _g = self.index_lock.lock();
        let id = sanitize_id(id)?;
        let dir = self.dir_for(&id);
        if !dir.starts_with(&self.root) {
            anyhow::bail!("недопустимый путь сессии");
        }
        if dir.is_dir() {
            fs::remove_dir_all(&dir)
                .with_context(|| format!("не удалить {}", dir.display()))?;
        }
        {
            let mut list = self.sessions.write();
            list.retain(|s| s.id != id);
            save_index(&self.root, &list)?;
        }
        Ok(())
    }

    pub fn update_meta(&self, meta: &SessionMeta) -> anyhow::Result<()> {
        let id = sanitize_id(&meta.id)?;
        let _g = self.index_lock.lock();
        let dir = self.dir_for(&id);
        if !dir.is_dir() {
            anyhow::bail!("сессия {id} не найдена");
        }
        write_json_atomic(&dir.join("session.json"), meta)?;
        write_state(&dir, meta)?;
        {
            let mut list = self.sessions.write();
            if let Some(slot) = list.iter_mut().find(|s| s.id == id) {
                *slot = meta.clone();
            } else {
                list.push(meta.clone());
            }
            save_index(&self.root, &list)?;
        }
        Ok(())
    }
}

pub type SharedStore = Arc<SessionStore>;

// ─────────────────────────────── writer ──────────────────────────────────

pub struct SessionWriter {
    pub dir: PathBuf,
    pub meta: SessionMeta,
    next_seq: u64,
    sessions: Arc<RwLock<Vec<SessionMeta>>>,
    root: PathBuf,
    events: BufWriter<File>,
    raw: BufWriter<File>,
    idx: BufWriter<File>,
    pending: Vec<String>,
    pending_bytes: usize,
    pending_idx: Vec<(u64, u64)>,
    offset: u64,
    last_flush: Instant,

    finished: bool,
}

impl SessionWriter {
    fn open(
        dir: PathBuf,
        meta: SessionMeta,
        sessions: Arc<RwLock<Vec<SessionMeta>>>,
        root: PathBuf,
        next_seq: u64,
    ) -> anyhow::Result<Self> {
        let events = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.jsonl"))?;
        let raw = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("raw.log"))?;
        let idx = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.idx"))?;
        let offset = fs::metadata(dir.join("events.jsonl"))
            .map(|m| m.len())
            .unwrap_or(0);
        Ok(Self {
            dir,
            meta,
            next_seq,
            sessions,
            root,
            events: BufWriter::new(events),
            raw: BufWriter::new(raw),
            idx: BufWriter::new(idx),
            pending: Vec::new(),
            pending_bytes: 0,
            pending_idx: Vec::new(),
            offset,
            last_flush: Instant::now(),

            finished: false,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn append(&mut self, ev: &mut Event) -> std::io::Result<()> {
        ev.seq = self.next_seq;
        self.next_seq += 1;

        let payload_len = if ev.hex.is_empty() {
            0
        } else {
            util::hex_to_bytes(&ev.hex).len() as u64
        };
        self.meta.counts.events += 1;
        match ev.kind {
            EventKind::Tx => {
                self.meta.counts.tx += 1;
                self.meta.counts.tx_bytes += payload_len;
            }
            EventKind::Rx => {
                self.meta.counts.rx += 1;
                self.meta.counts.rx_bytes += payload_len;
            }
            EventKind::File => self.meta.counts.files += 1,
            EventKind::Error => self.meta.counts.errors += 1,
            _ => {}
        }

        let line = serde_json::to_string(ev)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let line_offset = self.offset + self.pending_bytes as u64;
        if (ev.seq % INDEX_EVERY) == 0 {
            self.pending_idx.push((ev.seq, line_offset));
        }
        self.pending.push(line);
        self.pending_bytes += self
            .pending
            .last()
            .map(|l| l.len() + 1)
            .unwrap_or(0);

        let legacy = ev.to_legacy_line();
        self.write_legacy(&legacy)?;

        let due = self.pending.len() >= BATCH_EVENTS
            || self.pending_bytes >= BATCH_BYTES
            || self.last_flush.elapsed() >= Duration::from_millis(FLUSH_MS as u64);
        if due {
            self.flush()?;
        }
        Ok(())
    }

    pub fn append_many(&mut self, evs: &mut [Event]) -> std::io::Result<()> {
        for ev in evs.iter_mut() {
            self.append(ev)?;
        }
        Ok(())
    }

    /// `raw.log` обязан быть байт-в-байт как старый лог: подряд идущие одинаковые
    /// строки (например, побайтовые RX WinKFP) НЕ дедуплицируются.
    fn write_legacy(&mut self, line: &str) -> std::io::Result<()> {
        if line.is_empty() {
            return Ok(());
        }
        writeln!(self.raw, "{line}")?;
        Ok(())
    }

    /// Дописать строку в `raw.log` напрямую (баннеры, приглашения логера).
    pub fn write_raw_line(&mut self, line: &str) -> std::io::Result<()> {
        if line.is_empty() {
            return Ok(());
        }
        writeln!(self.raw, "{line}")?;
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        for line in self.pending.drain(..) {
            writeln!(self.events, "{line}")?;
        }
        self.offset += self.pending_bytes as u64;
        self.pending_bytes = 0;
        for (seq, off) in self.pending_idx.drain(..) {
            writeln!(self.idx, "{seq}\t{off}")?;
        }
        self.events.flush()?;
        self.raw.flush()?;
        self.idx.flush()?;
        self.last_flush = Instant::now();
        Ok(())
    }

    pub fn save_step(&self, s: &StepSummary) -> std::io::Result<()> {
        let path = self.dir.join("steps").join(format!("{:02}.json", s.idx));
        write_json_atomic(&path, s).map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Сбросить буферы, записать `session.json` и обновить индекс.
    pub fn finish(&mut self, meta: &SessionMeta) -> anyhow::Result<()> {
        self.flush()?;
        self.finished = true;
        let mut meta = meta.clone();
        if meta.counts.events == 0 {
            meta.counts = self.meta.counts.clone();
        }
        if meta.id.is_empty() {
            meta.id = self.meta.id.clone();
        }
        if meta.dir.is_empty() {
            meta.dir = self.dir.to_string_lossy().to_string();
        }
        if meta.ended_at.is_none() {
            meta.ended_at = Some(now_rfc3339());
        }
        write_json_atomic(&self.dir.join("session.json"), &meta)?;
        write_state(&self.dir, &meta)?;
        {
            let mut list = self.sessions.write();
            if let Some(slot) = list.iter_mut().find(|s| s.id == meta.id) {
                *slot = meta.clone();
            } else {
                list.push(meta.clone());
            }
            save_index(&self.root, &list)?;
        }
        self.meta = meta;
        Ok(())
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

impl Drop for SessionWriter {
    fn drop(&mut self) {
        // Последний шанс сохранить буферы при аварийном закрытии сессии.
        let _ = self.flush();
    }
}

// ─────────────────────────────── reader ──────────────────────────────────

pub struct SessionReader {
    dir: PathBuf,
    meta: SessionMeta,
    offsets: Option<Vec<(u64, u64)>>,
}

impl SessionReader {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn meta(&self) -> &SessionMeta {
        &self.meta
    }

    fn load_offsets(&mut self) {
        if self.offsets.is_some() {
            return;
        }
        let mut offsets = Vec::new();
        if let Ok(text) = fs::read_to_string(self.dir.join("events.idx")) {
            for line in text.lines() {
                let mut parts = line.split('\t');
                let (Some(seq), Some(off)) = (parts.next(), parts.next()) else {
                    continue;
                };
                if let (Ok(seq), Ok(off)) = (seq.trim().parse::<u64>(), off.trim().parse::<u64>()) {
                    offsets.push((seq, off));
                }
            }
        }
        offsets.sort_unstable();
        self.offsets = Some(offsets);
    }

    fn start_offset(&mut self, from: Option<u64>) -> u64 {
        self.load_offsets();
        let Some(from) = from else {
            return 0;
        };
        let offsets = self.offsets.as_ref().expect("offsets");
        let mut best = 0u64;
        for (seq, off) in offsets {
            if *seq <= from {
                best = *off;
            } else {
                break;
            }
        }
        best
    }

    /// Страница событий: `from` включительно, `to` исключительно, `limit = 0` — без предела.
    pub fn events(&self, from: Option<u64>, to: Option<u64>, limit: usize) -> Vec<Event> {
        let mut me = Self {
            dir: self.dir.clone(),
            meta: self.meta.clone(),
            offsets: self.offsets.clone(),
        };
        let offset = me.start_offset(from);
        let Ok(file) = File::open(self.dir.join("events.jsonl")) else {
            return Vec::new();
        };
        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(offset)).is_err() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            if line.trim().is_empty() {
                continue;
            }
            let Ok(ev) = serde_json::from_str::<Event>(&line) else {
                continue;
            };
            if let Some(f) = from {
                if ev.seq < f {
                    continue;
                }
            }
            if let Some(t) = to {
                if ev.seq >= t {
                    break;
                }
            }
            out.push(ev);
            if limit > 0 && out.len() >= limit {
                break;
            }
        }
        out
    }

    pub fn all_events(&self) -> Vec<Event> {
        self.events(None, None, 0)
    }

    pub fn steps(&self) -> Vec<StepSummary> {
        let dir = self.dir.join("steps");
        let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        paths.retain(|p| p.extension().map(|e| e == "json").unwrap_or(false));
        paths.sort();
        paths
            .iter()
            .filter_map(|p| read_json::<StepSummary>(p))
            .collect()
    }

    pub fn count_events(&self) -> u64 {
        if self.meta.counts.events > 0 {
            return self.meta.counts.events;
        }
        count_events_on_disk(&self.dir)
    }

    /// Закрыть незакрытые шаги (аварийное завершение): дописать `StepEnd`,
    /// пересобрать сводки, поставить `status:"aborted"`.
    pub fn repair(&mut self) -> anyhow::Result<()> {
        let events = self.all_events();
        let mut open: Vec<(u32, String)> = Vec::new();
        for ev in &events {
            let idx = ev
                .meta
                .get("idx")
                .and_then(Value::as_u64)
                .map(|v| v as u32);
            match ev.kind {
                EventKind::StepStart => {
                    let idx = idx.unwrap_or(0);
                    let title = ev.text.clone().unwrap_or_default();
                    open.retain(|(i, _)| *i != idx);
                    open.push((idx, title));
                }
                EventKind::StepEnd => {
                    if let Some(idx) = idx {
                        open.retain(|(i, _)| *i != idx);
                    }
                }
                _ => {}
            }
        }
        if open.is_empty() {
            return Ok(());
        }

        let mut appended = 0u64;
        let mut next_seq = events.last().map(|e| e.seq + 1).unwrap_or(0);
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("events.jsonl"))?;
        let mut raw_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("raw.log"))?;
        let last_t = events.last().map(|e| e.t).unwrap_or(0.0);

        for (idx, title) in open {
            let mut summary = crate::decode::summarize_step(&events, idx, &title, 0.0, None);
            summary.ended_at = now_rfc3339();
            if summary.title.is_empty() {
                summary.title = title.clone();
            }
            write_json_atomic(
                &self.dir.join("steps").join(format!("{idx:02}.json")),
                &summary,
            )?;

            let mut ev = Event::new(EventKind::StepEnd, crate::models::Transport::None, last_t, "");
            ev.seq = next_seq;
            ev.api = "MARK".into();
            ev.kind = EventKind::StepEnd;
            ev.text = Some(title.clone());
            ev.step = Some(idx);
            ev.meta = json!({"action": "end", "idx": idx, "title": title, "repaired": true});
            let line = serde_json::to_string(&ev)?;
            writeln!(events_file, "{line}")?;
            writeln!(raw_file, "{}", ev.to_legacy_line())?;
            next_seq += 1;
            appended += 1;
        }
        events_file.flush()?;
        raw_file.flush()?;

        self.meta.counts.events = next_seq;
        self.meta.counts.steps = self
            .steps()
            .len()
            .max(open_steps_count(&events) as usize) as u64;
        if self.meta.status == "recording" || self.meta.status.is_empty() {
            self.meta.status = "aborted".into();
        }
        self.meta.ended_at.get_or_insert_with(now_rfc3339);
        write_json_atomic(&self.dir.join("session.json"), &self.meta)?;
        write_state(&self.dir, &self.meta)?;

        // Индекс лежит в каталоге-родителе (sessions/).
        if let Some(root) = self.dir.parent() {
            let mut list = load_index(root);
            if let Some(slot) = list.iter_mut().find(|s| s.id == self.meta.id) {
                *slot = self.meta.clone();
            } else {
                list.push(self.meta.clone());
            }
            save_index(root, &list)?;
        }
        tracing::warn!(
            session = %self.meta.id,
            appended,
            "repair: закрыты незакрытые шаги"
        );
        Ok(())
    }
}

fn open_steps_count(events: &[Event]) -> u32 {
    let mut started = std::collections::BTreeSet::new();
    let mut ended = std::collections::BTreeSet::new();
    for ev in events {
        let idx = ev
            .meta
            .get("idx")
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        if let Some(idx) = idx {
            match ev.kind {
                EventKind::StepStart => {
                    started.insert(idx);
                }
                EventKind::StepEnd => {
                    ended.insert(idx);
                }
                _ => {}
            }
        }
    }
    started.union(&ended).count() as u32
}

