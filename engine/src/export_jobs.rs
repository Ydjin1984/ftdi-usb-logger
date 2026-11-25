//! Фоновые задания экспорта: состояние для прогресс-бара в интерфейсе.
//!
//! `POST /api/sessions/:id/export/jobs` запускает задачу и сразу отвечает её id,
//! UI опрашивает `GET .../export/jobs/:job`. Синхронный `POST /export` остаётся
//! для скриптов и e2e — контракт не меняется.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Сколько держим завершённые задания: UI должен успеть забрать результат.
const JOB_TTL: Duration = Duration::from_secs(3600);

/// Состояние одного задания экспорта (ответ API).
#[derive(Clone, Debug, Serialize)]
pub struct ExportJob {
    pub id: String,
    pub format: String,
    /// `queued` | `running` | `done` | `error`.
    pub state: String,
    /// Человекочитаемая стадия: «снимок сессии», «упаковка файлов», …
    pub stage: String,
    /// 0..100. До финиша не доходит до 100, чтобы «готово» не показывалось раньше.
    pub percent: f64,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Entry {
    job: ExportJob,
    updated: Instant,
}

/// Общий реестр заданий; ключ — `сессия/задание`, чтобы чужой id не открыл статус.
#[derive(Default)]
pub struct ExportJobs {
    jobs: Mutex<HashMap<String, Entry>>,
}

fn key(session: &str, id: &str) -> String {
    format!("{session}/{id}")
}

impl ExportJobs {
    /// Зарегистрировать задание в состоянии `queued` и вернуть его описание.
    pub fn create(&self, session: &str, format: &str) -> ExportJob {
        let job = ExportJob {
            id: uuid::Uuid::new_v4().to_string(),
            format: format.to_string(),
            state: "queued".into(),
            stage: "в очереди".into(),
            percent: 0.0,
            files_done: 0,
            files_total: 0,
            bytes_done: 0,
            bytes_total: 0,
            path: None,
            error: None,
        };
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.retain(|_, e| e.updated.elapsed() < JOB_TTL);
            jobs.insert(
                key(session, &job.id),
                Entry {
                    job: job.clone(),
                    updated: Instant::now(),
                },
            );
        }
        job
    }

    /// Обновить задание. Проценты зажимаются в 0..100, чтобы UI не рисовал
    /// полосу за границей из-за округлений размера файлов.
    pub fn update(&self, session: &str, id: &str, f: impl FnOnce(&mut ExportJob)) {
        if let Ok(mut jobs) = self.jobs.lock() {
            if let Some(entry) = jobs.get_mut(&key(session, id)) {
                f(&mut entry.job);
                if !entry.job.percent.is_finite() {
                    entry.job.percent = 0.0;
                }
                entry.job.percent = entry.job.percent.clamp(0.0, 100.0);
                entry.updated = Instant::now();
            }
        }
    }

    /// Готовое задание: 100 % и путь к файлу.
    pub fn finish(&self, session: &str, id: &str, path: String) {
        self.update(session, id, |job| {
            job.state = "done".into();
            job.stage = "готово".into();
            job.percent = 100.0;
            job.bytes_done = job.bytes_total.max(job.bytes_done);
            job.files_done = job.files_total.max(job.files_done);
            job.path = Some(path);
        });
    }

    /// Ошибка задания: текст для интерфейса, без «готово».
    pub fn fail(&self, session: &str, id: &str, error: String) {
        self.update(session, id, |job| {
            job.state = "error".into();
            job.stage = "ошибка".into();
            job.error = Some(error);
        });
    }

    /// Текущее состояние задания; `None` — нет такого (или истёк TTL).
    pub fn get(&self, session: &str, id: &str) -> Option<ExportJob> {
        let jobs = self.jobs.lock().ok()?;
        jobs.get(&key(session, id))
            .filter(|e| e.updated.elapsed() < JOB_TTL)
            .map(|e| e.job.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_lifecycle_is_scoped_to_session() {
        let jobs = ExportJobs::default();
        let job = jobs.create("s1", "zip");
        assert_eq!(job.state, "queued");
        assert!(jobs.get("s1", &job.id).is_some());
        assert!(jobs.get("s2", &job.id).is_none(), "чужая сессия не видит задание");

        jobs.update("s1", &job.id, |j| {
            j.state = "running".into();
            j.percent = 42.5;
        });
        let running = jobs.get("s1", &job.id).unwrap();
        assert_eq!(running.state, "running");
        assert!((running.percent - 42.5).abs() < f64::EPSILON);

        jobs.finish("s1", &job.id, "C:/out.zip".into());
        let done = jobs.get("s1", &job.id).unwrap();
        assert_eq!(done.state, "done");
        assert_eq!(done.percent, 100.0);
        assert_eq!(done.path.as_deref(), Some("C:/out.zip"));
    }

    #[test]
    fn percent_is_clamped() {
        let jobs = ExportJobs::default();
        let job = jobs.create("s", "csv");
        jobs.update("s", &job.id, |j| j.percent = 180.0);
        assert_eq!(jobs.get("s", &job.id).unwrap().percent, 100.0);
        jobs.update("s", &job.id, |j| j.percent = -5.0);
        assert_eq!(jobs.get("s", &job.id).unwrap().percent, 0.0);
    }
}
