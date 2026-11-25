//! Разбор записанных кадров осциллографа: события сигналов и покрытие.
//!
//! Вход — `scope/frames.jsonl` (docs/14 §4), выход — `scope/analysis.json`:
//! компактная выжимка, по которой отчёт и интерфейс отвечают на вопросы
//! «когда появился PWM», «когда выросла амплитуда», «когда поднялось питание»
//! и «между какими кадрами это произошло».
//!
//! Почему отдельный проход, а не события в реальном времени: переразбор
//! существующей сессии (ZIP без `analysis.json`) обязан давать тот же результат.
//! Живой захват тоже зовёт `analyze` при финализации — один код, один ответ.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::SessionMeta;
use crate::scope::{ChannelInfo, Stat};
use crate::textfix;

pub const ANALYSIS_FORMAT: &str = "scope-analysis/1";
pub const ANALYSIS_FILE: &str = "scope/analysis.json";

/// Роль канала стенда. Пустая роль — канал не участвует в сводке.
pub const ROLE_GPT1: &str = "gpt1";
pub const ROLE_GPT2: &str = "gpt2";
pub const ROLE_POWER: &str = "power";

/// Профиль стенда по умолчанию: CH1 GPT1, CH2 GPT2, CH3 питание.
pub const PROFILE_BENCH_GPT: &str = "bench-gpt";

/// Канал с ролью: по ней строятся события, а не по номеру.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelRole {
    pub ch: usize,
    pub role: String,
    pub name: String,
}

/// Отсчёты одного канала в одном кадре (подмножество `stats`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Sample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmin: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmax: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpp: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duty: Option<f64>,
}

impl Sample {
    fn from_stat(s: &Stat) -> Self {
        Self {
            vmin: s.vmin,
            vmax: s.vmax,
            vpp: s.vpp,
            mean: s.mean,
            freq: s.freq,
            duty: s.duty,
        }
    }

    fn vpp_or_zero(&self) -> f64 {
        self.vpp.unwrap_or(0.0)
    }
}

/// Событие сигнала: переход состояния между двумя соседними кадрами.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignalEvent {
    /// `pwm_on`, `pwm_off`, `amp_rise`, `amp_fall`, `power_on`, `power_off`.
    pub kind: String,
    pub ch: usize,
    pub role: String,
    pub name: String,
    /// Кадр до перехода; `None` — переход виден на первом кадре сессии.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t_before: Option<f64>,
    pub t_after: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_before: Option<u64>,
    pub frame_after: u64,
    /// Ширина интервала между кадрами, мс. Это НЕ точность фронта: фронт мог
    /// быть в любой точке между кадрами.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Sample>,
    pub after: Sample,
    /// `low` / `mid` / `high` для PWM; `on` / `off` для питания.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_after: Option<String>,
    /// Готовая строка для отчёта и карточки.
    pub text: String,
}

/// Интервал, в котором сигнал не наблюдался (кадров нет).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gap {
    pub t0: f64,
    pub t1: f64,
    pub interval_ms: f64,
    /// Сколько публикаций служба сделала мимо логгера (`gap_blocks`).
    #[serde(default)]
    pub blocks: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub session_s: f64,
    pub frames: u64,
    /// Сумма длительностей окон кадров, с.
    pub signal_s: f64,
    pub pct: f64,
    pub interval_p50_ms: f64,
    pub interval_p95_ms: f64,
    pub interval_max_ms: f64,
}

/// Выжимка по сигналам всей сессии.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeAnalysis {
    pub format: String,
    pub session_id: String,
    /// Имя профиля (`bench-gpt`, `saved`, `none`).
    pub profile: String,
    /// `true` — роли не были записаны в сессии и применён профиль по умолчанию:
    /// это предположение, а не паспорт стенда.
    pub profile_assumed: bool,
    pub channels: Vec<ChannelRole>,
    pub coverage: Coverage,
    pub events: Vec<SignalEvent>,
    pub gaps: Vec<Gap>,
    pub gap_count: u64,
    pub gap_blocks: u64,
    pub generated_at: String,
    pub notes: Vec<String>,
}

impl ScopeAnalysis {
    pub fn empty(session_id: &str) -> Self {
        Self {
            format: ANALYSIS_FORMAT.into(),
            session_id: session_id.to_string(),
            profile: "none".into(),
            profile_assumed: false,
            channels: Vec::new(),
            coverage: Coverage::default(),
            events: Vec::new(),
            gaps: Vec::new(),
            gap_count: 0,
            gap_blocks: 0,
            generated_at: now_rfc3339(),
            notes: vec!["кадры осциллографа не записаны".into()],
        }
    }

    pub fn events_between(&self, t0: f64, t1: f64) -> Vec<&SignalEvent> {
        self.events
            .iter()
            .filter(|e| e.t_after >= t0 && e.t_after <= t1)
            .collect()
    }

    pub fn role_name(&self, role: &str) -> String {
        self.channels
            .iter()
            .find(|c| c.role == role)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| role.to_string())
    }
}

/// Чтение строки `frames.jsonl`. `columns_b64` намеренно не десериализуется:
/// для анализа нужны только `t` и измерения кадра.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FrameRow {
    t: f64,
    frame_id: u64,
    wall: String,
    rcv_epoch: f64,
    accuracy_ms: u64,
    segment: u32,
    gap_blocks: u64,
    window_s: f64,
    held: bool,
    stats: Vec<Stat>,
    channel_meta: Vec<ChannelInfo>,
}

/// Прочитать кадры из файла (потоково, без `columns_b64`).
fn read_frames(path: &Path) -> anyhow::Result<Vec<FrameRow>> {
    let file = File::open(path)
        .with_context(|| format!("не открыть кадры осциллографа {}", path.display()))?;
    let reader = BufReader::with_capacity(1 << 20, file);
    // `from_reader` вместо `lines()` + `from_str`: на сессии
    // 20261122-183516-pcmflash (129 МБ, 5951 кадр) это убирает копию строки
    // на кадр; `columns_b64` в структуру не входит и не аллоцируется.
    let stream = serde_json::Deserializer::from_reader(reader).into_iter::<FrameRow>();
    let mut out = Vec::new();
    for (idx, item) in stream.enumerate() {
        let row = item.with_context(|| {
            format!("кадр {}: элемент {} не разобран", path.display(), idx + 1)
        })?;
        out.push(row);
    }
    Ok(out)
}

/// Роли каналов: из `scope/channels.json`, иначе профиль стенда по умолчанию.
fn resolve_profile(dir: &Path) -> (String, bool, Vec<ChannelRole>, Vec<usize>) {
    let path = dir.join("scope/channels.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            if let Some(list) = value.get("channels").and_then(Value::as_array) {
                let mut roles = Vec::new();
                let mut enabled = Vec::new();
                for item in list {
                    let ch = item.get("ch").and_then(Value::as_u64).unwrap_or(0) as usize;
                    let role = item
                        .get("role")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let name = item
                        .get("name")
                        .and_then(Value::as_str)
                        .map(textfix::clean)
                        .unwrap_or_default();
                    if item.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
                        enabled.push(ch);
                    }
                    if !role.is_empty() {
                        let display = if name.is_empty() {
                            default_name(&role, ch)
                        } else {
                            name
                        };
                        roles.push(ChannelRole {
                            ch,
                            role,
                            name: display,
                        });
                    }
                }
                if !roles.is_empty() {
                    return ("saved".into(), false, roles, enabled);
                }
            }
        }
    }
    // Профиль по умолчанию: стенд «Хелтег да Винчи» — CH1 GPT1, CH2 GPT2, CH3 питание.
    let roles = vec![
        ChannelRole {
            ch: 1,
            role: ROLE_GPT1.into(),
            name: "GPT1".into(),
        },
        ChannelRole {
            ch: 2,
            role: ROLE_GPT2.into(),
            name: "GPT2".into(),
        },
        ChannelRole {
            ch: 3,
            role: ROLE_POWER.into(),
            name: "Питание".into(),
        },
    ];
    (PROFILE_BENCH_GPT.into(), true, roles, vec![1, 2, 3])
}

fn default_name(role: &str, ch: usize) -> String {
    match role {
        ROLE_GPT1 => "GPT1".into(),
        ROLE_GPT2 => "GPT2".into(),
        ROLE_POWER => "Питание".into(),
        _ => format!("CH{ch}"),
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Уровень амплитуды PWM по размаху.
///
/// Границы выбраны по живому стенду: 1.7–2.1 В — ранний PWM (GPT работает,
/// питание ещё не подано), 3.5–5 В — после подачи питания. Это эвристика, и в
/// отчёте она названа эвристикой: абсолютные вольты зависят от щупов.
fn level_of(vpp: f64) -> &'static str {
    if vpp < 2.6 {
        "low"
    } else if vpp < 4.2 {
        "mid"
    } else {
        "high"
    }
}

fn level_ru(level: &str) -> &'static str {
    match level {
        "low" => "низкая (1.7–2.6 В)",
        "mid" => "средняя (2.6–4.2 В)",
        "high" => "высокая (от 4.2 В)",
        "on" => "включено",
        "off" => "выключено",
        _ => "—",
    }
}

fn fmt_v(v: f64) -> String {
    if v.abs() >= 100.0 {
        format!("{v:.0} В")
    } else {
        format!("{v:.2} В")
    }
}

struct ChannelState {
    pwm: bool,
    level: String,
    power: bool,
    last: Option<(f64, u64, Sample)>,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            pwm: false,
            level: String::new(),
            power: false,
            last: None,
        }
    }
}

/// Собрать события сигналов и покрытие из кадров.
pub fn analyze(dir: &Path, meta: &SessionMeta) -> anyhow::Result<ScopeAnalysis> {
    let frames_path = dir.join("scope/frames.jsonl");
    if !frames_path.is_file() {
        return Ok(ScopeAnalysis::empty(&meta.id));
    }
    let frames = read_frames(&frames_path)?;
    if frames.is_empty() {
        return Ok(ScopeAnalysis::empty(&meta.id));
    }
    let (profile, assumed, roles, enabled) = resolve_profile(dir);
    let mut notes = Vec::new();
    if assumed {
        notes.push(
            "роли каналов в сессии не записаны: применён профиль стенда по умолчанию \
             (CH1 GPT1, CH2 GPT2, CH3 питание) — это предположение"
                .to_string(),
        );
    }
    let session_s = session_seconds(dir, meta, &frames);

    // Интервалы публикаций — по ним видно, что между кадрами сигнал не наблюдался.
    let intervals: Vec<f64> = frames
        .windows(2)
        .map(|pair| (pair[1].t - pair[0].t).max(0.0) * 1000.0)
        .collect();
    let mut intervals_sorted = intervals.clone();
    intervals_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = percentile(&intervals_sorted, 0.50);
    let mut gaps: Vec<Gap> = Vec::new();
    let mut gap_blocks = 0u64;
    let threshold = (p50 * 3.0).max(150.0);
    {
        let mut open: Option<(f64, f64, u64)> = None;
        for (i, pair) in frames.windows(2).enumerate() {
            let dt_ms = intervals.get(i).copied().unwrap_or(0.0);
            let blocks = pair[1].gap_blocks;
            gap_blocks = gap_blocks.saturating_add(blocks);
            if dt_ms > threshold || blocks > 0 {
                let end = pair[1].t;
                match open.as_mut() {
                    Some((_, e, b)) => {
                        *e = end;
                        *b = b.saturating_add(blocks);
                    }
                    None => open = Some((pair[0].t, end, blocks)),
                }
            } else if let Some((t0, t1, b)) = open.take() {
                gaps.push(Gap {
                    t0,
                    t1,
                    interval_ms: (t1 - t0) * 1000.0,
                    blocks: b,
                });
            }
        }
        if let Some((t0, t1, b)) = open {
            gaps.push(Gap {
                t0,
                t1,
                interval_ms: (t1 - t0) * 1000.0,
                blocks: b,
            });
        }
    }
    // Самые длинные — первыми; в отчёт идут первые пять, полный список — в JSON.
    gaps.sort_by(|a, b| {
        b.interval_ms
            .partial_cmp(&a.interval_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut events: Vec<SignalEvent> = Vec::new();
    let mut states: Vec<ChannelState> = (0..roles.len()).map(|_| ChannelState::default()).collect();

    for frame in &frames {
        for (ri, role) in roles.iter().enumerate() {
            if !enabled.contains(&role.ch) {
                continue;
            }
            let Some(stat) = frame.stats.iter().find(|s| s.ch == role.ch) else {
                continue;
            };
            let sample = Sample::from_stat(stat);
            let state = &mut states[ri];
            let before = state.last.clone();
            let width_ms = before
                .as_ref()
                .map(|(t, _, _)| ((frame.t - *t) * 1000.0).max(0.0));

            match role.role.as_str() {
                ROLE_GPT1 | ROLE_GPT2 => {
                    let vpp = sample.vpp_or_zero();
                    // Гистерезис: включение от 1.0 В, выключение ниже 0.6 В.
                    // Одиночный всплеск шума 0.1–0.2 В не должен давать событие.
                    let pwm = if state.pwm {
                        vpp >= 0.6
                    } else {
                        vpp >= 1.0
                    };
                    if pwm && !state.pwm {
                        let level = level_of(vpp).to_string();
                        events.push(SignalEvent {
                            kind: "pwm_on".into(),
                            ch: role.ch,
                            role: role.role.clone(),
                            name: role.name.clone(),
                            t_before: before.as_ref().map(|(t, _, _)| *t),
                            t_after: frame.t,
                            frame_before: before.as_ref().map(|(_, id, _)| *id),
                            frame_after: frame.frame_id,
                            width_ms,
                            before: before.as_ref().map(|(_, _, s)| s.clone()),
                            after: sample.clone(),
                            level_before: None,
                            level_after: Some(level.clone()),
                            text: format!(
                                "появление PWM: размах {} (уровень {}, частота {})",
                                fmt_v(vpp),
                                level_ru(&level),
                                sample
                                    .freq
                                    .map(|f| format!("{:.1} кГц", f / 1000.0))
                                    .unwrap_or_else(|| "не измерена".into())
                            ),
                        });
                        state.level = level;
                    } else if !pwm && state.pwm {
                        events.push(SignalEvent {
                            kind: "pwm_off".into(),
                            ch: role.ch,
                            role: role.role.clone(),
                            name: role.name.clone(),
                            t_before: before.as_ref().map(|(t, _, _)| *t),
                            t_after: frame.t,
                            frame_before: before.as_ref().map(|(_, id, _)| *id),
                            frame_after: frame.frame_id,
                            width_ms,
                            before: before.as_ref().map(|(_, _, s)| s.clone()),
                            after: sample.clone(),
                            level_before: if state.level.is_empty() {
                                None
                            } else {
                                Some(state.level.clone())
                            },
                            level_after: None,
                            text: format!(
                                "PWM пропал: размах {} → {}",
                                before
                                    .as_ref()
                                    .map(|(_, _, s)| fmt_v(s.vpp_or_zero()))
                                    .unwrap_or_else(|| "?".into()),
                                fmt_v(vpp)
                            ),
                        });
                        state.level.clear();
                    } else if pwm {
                        let level = level_of(vpp).to_string();
                        if !state.level.is_empty() && state.level != level {
                            let rising = matches!(
                                (state.level.as_str(), level.as_str()),
                                ("low", "mid") | ("low", "high") | ("mid", "high")
                            );
                            events.push(SignalEvent {
                                kind: if rising { "amp_rise" } else { "amp_fall" }.into(),
                                ch: role.ch,
                                role: role.role.clone(),
                                name: role.name.clone(),
                                t_before: before.as_ref().map(|(t, _, _)| *t),
                                t_after: frame.t,
                                frame_before: before.as_ref().map(|(_, id, _)| *id),
                                frame_after: frame.frame_id,
                                width_ms,
                                before: before.as_ref().map(|(_, _, s)| s.clone()),
                                after: sample.clone(),
                                level_before: Some(state.level.clone()),
                                level_after: Some(level.clone()),
                                text: format!(
                                    "амплитуда PWM {}: {} → {} ({})",
                                    if rising { "выросла" } else { "упала" },
                                    fmt_v(
                                        before
                                            .as_ref()
                                            .map(|(_, _, s)| s.vpp_or_zero())
                                            .unwrap_or(0.0)
                                    ),
                                    fmt_v(vpp),
                                    level_ru(&level)
                                ),
                            });
                            state.level = level;
                        }
                    }
                    state.pwm = pwm;
                }
                ROLE_POWER => {
                    let vmax = sample.vmax.unwrap_or(0.0);
                    let mean = sample.mean.unwrap_or(0.0);
                    // Питание: подъём от ~0 до 12–14 В виден по vmax; среднее
                    // подтверждает, что канал не просто поймал импульс.
                    let on = if state.power {
                        vmax >= 2.0 && mean >= 1.0
                    } else {
                        vmax >= 6.0 || mean >= 3.0
                    };
                    if on && !state.power {
                        events.push(SignalEvent {
                            kind: "power_on".into(),
                            ch: role.ch,
                            role: role.role.clone(),
                            name: role.name.clone(),
                            t_before: before.as_ref().map(|(t, _, _)| *t),
                            t_after: frame.t,
                            frame_before: before.as_ref().map(|(_, id, _)| *id),
                            frame_after: frame.frame_id,
                            width_ms,
                            before: before.as_ref().map(|(_, _, s)| s.clone()),
                            after: sample.clone(),
                            level_before: Some("off".into()),
                            level_after: Some("on".into()),
                            text: format!(
                                "питание поднялось: {} → {} (по пику кадра)",
                                fmt_v(
                                    before
                                        .as_ref()
                                        .and_then(|(_, _, s)| s.vmax)
                                        .unwrap_or(0.0)
                                ),
                                fmt_v(vmax)
                            ),
                        });
                    } else if !on && state.power {
                        events.push(SignalEvent {
                            kind: "power_off".into(),
                            ch: role.ch,
                            role: role.role.clone(),
                            name: role.name.clone(),
                            t_before: before.as_ref().map(|(t, _, _)| *t),
                            t_after: frame.t,
                            frame_before: before.as_ref().map(|(_, id, _)| *id),
                            frame_after: frame.frame_id,
                            width_ms,
                            before: before.as_ref().map(|(_, _, s)| s.clone()),
                            after: sample.clone(),
                            level_before: Some("on".into()),
                            level_after: Some("off".into()),
                            text: format!(
                                "питание пропало: {} → {} (по пику кадра)",
                                fmt_v(
                                    before
                                        .as_ref()
                                        .and_then(|(_, _, s)| s.vmax)
                                        .unwrap_or(0.0)
                                ),
                                fmt_v(vmax)
                            ),
                        });
                    }
                    state.power = on;
                }
                _ => {}
            }
            state.last = Some((frame.t, frame.frame_id, sample));
        }
    }
    events.sort_by(|a, b| {
        a.t_after
            .partial_cmp(&b.t_after)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut sorted_intervals = intervals.clone();
    sorted_intervals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let signal_s: f64 = frames.iter().map(|f| f.window_s).sum();
    let frames_n = frames.len() as u64;
    let coverage = Coverage {
        session_s,
        frames: frames_n,
        signal_s,
        pct: if session_s > 0.0 {
            signal_s / session_s * 100.0
        } else {
            0.0
        },
        interval_p50_ms: percentile(&sorted_intervals, 0.50),
        interval_p95_ms: percentile(&sorted_intervals, 0.95),
        interval_max_ms: sorted_intervals.last().copied().unwrap_or(0.0),
    };
    let gap_count = gaps.len() as u64;
    Ok(ScopeAnalysis {
        format: ANALYSIS_FORMAT.into(),
        session_id: meta.id.clone(),
        profile,
        profile_assumed: assumed,
        channels: roles,
        coverage,
        events,
        gaps,
        gap_count,
        gap_blocks,
        generated_at: now_rfc3339(),
        notes,
    })
}

/// Длительность сессии: `scope/summary.json` (`t_stop`) точнее метаданных.
fn session_seconds(dir: &Path, meta: &SessionMeta, frames: &[FrameRow]) -> f64 {
    if let Ok(text) = std::fs::read_to_string(dir.join("scope/summary.json")) {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            if let Some(t) = value.get("t_stop").and_then(Value::as_f64) {
                if t > 0.0 {
                    return t;
                }
            }
        }
    }
    if let (Ok(start), Some(end)) = (
        chrono::DateTime::parse_from_rfc3339(&meta.started_at),
        meta.ended_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()),
    ) {
        let d = (end - start).num_milliseconds() as f64 / 1000.0;
        if d > 0.0 {
            return d;
        }
    }
    frames.last().map(|f| f.t).unwrap_or(0.0)
}

/// Прочитать готовый анализ, если он есть и относится к этой сессии.
pub fn load(dir: &Path, session_id: &str) -> Option<ScopeAnalysis> {
    let text = std::fs::read_to_string(dir.join(ANALYSIS_FILE)).ok()?;
    let value: ScopeAnalysis = serde_json::from_str(&text).ok()?;
    if value.format != ANALYSIS_FORMAT || value.session_id != session_id {
        return None;
    }
    Some(value)
}

/// Записать анализ в `scope/analysis.json`.
pub fn save(dir: &Path, analysis: &ScopeAnalysis) -> anyhow::Result<()> {
    let path = dir.join(ANALYSIS_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::store::write_json_atomic(&path, analysis)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(t: f64, id: u64, vpp: f64, vmax: f64, mean: f64) -> FrameRow {
        FrameRow {
            t,
            frame_id: id,
            window_s: 0.001665,
            stats: vec![
                Stat {
                    ch: 1,
                    vpp: Some(vpp),
                    vmax: Some(vmax),
                    mean: Some(mean),
                    freq: Some(15_789.0),
                    ..Default::default()
                },
                Stat {
                    ch: 2,
                    vpp: Some(vpp),
                    vmax: Some(vmax),
                    mean: Some(mean),
                    freq: Some(10_000.0),
                    ..Default::default()
                },
                Stat {
                    ch: 3,
                    vpp: Some(0.05),
                    vmax: Some(vmax),
                    mean: Some(mean),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    fn write_frames(dir: &Path, rows: &[FrameRow]) {
        let path = dir.join("scope/frames.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut text = String::new();
        for r in rows {
            text.push_str(&serde_json::json!({
                "t": r.t, "frame_id": r.frame_id, "window_s": r.window_s,
                "gap_blocks": r.gap_blocks, "segment": r.segment,
                "stats": r.stats.iter().map(|s| serde_json::json!({
                    "ch": s.ch, "vmin": s.vmin, "vmax": s.vmax, "vpp": s.vpp,
                    "mean": s.mean, "freq": s.freq, "duty": s.duty,
                })).collect::<Vec<_>>(),
            }).to_string());
            text.push('\n');
        }
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn detects_pwm_power_and_bracket() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path();
        let meta = SessionMeta::new("t1", "test");
        let mut rows = vec![
            frame(0.0, 1, 0.05, -0.35, -0.37),
            frame(0.052, 2, 0.06, -0.33, -0.37),
            frame(0.104, 3, 1.82, 4.93, 0.99), // PWM на обоих GPT
            frame(0.156, 4, 4.87, 4.93, 2.31),
            frame(0.208, 5, 4.87, 13.99, 13.93), // питание
        ];
        rows[4].stats[2].vmax = Some(13.99);
        rows[4].stats[2].mean = Some(13.93);
        write_frames(dir, &rows);
        let a = analyze(dir, &meta).unwrap();
        assert_eq!(a.profile, PROFILE_BENCH_GPT);
        assert!(a.profile_assumed);
        let pwm: Vec<_> = a.events.iter().filter(|e| e.kind == "pwm_on").collect();
        assert_eq!(pwm.len(), 2, "{:?}", a.events);
        assert_eq!(pwm[0].t_before, Some(0.052));
        assert_eq!(pwm[0].t_after, 0.104);
        assert_eq!(pwm[0].frame_before, Some(2));
        assert_eq!(pwm[0].frame_after, 3);
        assert!((pwm[0].width_ms.unwrap() - 52.0).abs() < 0.1);
        let rise: Vec<_> = a.events.iter().filter(|e| e.kind == "amp_rise").collect();
        assert_eq!(rise.len(), 2, "рост амплитуды отдельно: {:?}", a.events);
        let power: Vec<_> = a.events.iter().filter(|e| e.kind == "power_on").collect();
        assert_eq!(power.len(), 1);
        assert_eq!(power[0].t_before, Some(0.156));
        assert_eq!(power[0].t_after, 0.208);
    }

    #[test]
    fn noise_does_not_create_pwm() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path();
        let meta = SessionMeta::new("t2", "test");
        let mut rows = Vec::new();
        for i in 0..10 {
            let mut f = frame(i as f64 * 0.05, i, 0.12, 0.1, -0.3);
            f.stats[0].freq = Some(75_000.0); // шумовой «частотный» отсчёт
            rows.push(f);
        }
        write_frames(dir, &rows);
        let a = analyze(dir, &meta).unwrap();
        assert!(a.events.is_empty(), "{:?}", a.events);
    }

    #[test]
    fn gaps_and_coverage_are_reported() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path();
        let meta = SessionMeta::new("t3", "test");
        let mut rows: Vec<FrameRow> = (0..20)
            .map(|i| frame(i as f64 * 0.052, i, 0.05, -0.35, -0.37))
            .collect();
        // пропуск 0.4 с и метка службы о пропущенной публикации
        rows[10].t += 0.4;
        rows[10].gap_blocks = 7;
        write_frames(dir, &rows);
        let a = analyze(dir, &meta).unwrap();
        assert_eq!(a.gap_count, 1, "{:?}", a.gaps);
        assert_eq!(a.gap_blocks, 7);
        assert!(a.gaps[0].interval_ms > 400.0);
        assert!(a.coverage.frames == 20);
        assert!(a.coverage.signal_s > 0.0);
    }
}
