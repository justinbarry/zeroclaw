use crate::config::Config;
use anyhow::{Context, bail};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SEARCH_LIMIT: usize = 50;
const DEFAULT_RECENT_LIMIT: usize = 10;
const DEFAULT_TRANSCRIPT_LIMIT: usize = 50;
const INLINE_TRANSCRIPT_LIMIT: usize = 100;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BluedotImportStats {
    pub files_scanned: usize,
    pub payloads_scanned: usize,
    pub created: usize,
    pub updated: usize,
    pub ignored: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum BluedotAttendee {
    Email(String),
    Object {
        email: Option<String>,
        name: Option<String>,
    },
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TranscriptEntry {
    pub speaker: String,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BluedotWebhookPayload {
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    #[serde(rename = "videoId")]
    pub video_id: String,
    #[serde(rename = "meetingId")]
    pub meeting_id: Option<String>,
    pub title: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<Value>,
    pub duration: Option<Value>,
    #[serde(default)]
    pub(crate) attendees: Vec<BluedotAttendee>,
    pub summary: Option<String>,
    #[serde(rename = "summaryV2")]
    pub summary_v2: Option<String>,
    #[serde(default)]
    pub(crate) transcript: Vec<RawTranscriptEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RawTranscriptEntry {
    pub(crate) speaker: Option<String>,
    pub(crate) text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeetingRecord {
    pub video_id: String,
    pub meeting_id: Option<String>,
    pub title: String,
    pub created_at: i64,
    pub duration_secs: Option<f64>,
    pub attendees: Vec<String>,
    pub summary: Option<String>,
    pub transcript: Vec<TranscriptEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeetingSearchResult {
    pub meeting: MeetingRecord,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TranscriptPage {
    pub video_id: String,
    pub title: String,
    pub total: usize,
    pub offset: usize,
    pub count: usize,
    pub has_more: bool,
    pub next_offset: Option<usize>,
    pub transcript: String,
}

#[derive(Clone)]
pub struct BluedotMeetingStore {
    conn: Arc<Mutex<Connection>>,
    retention_days: u32,
    max_meetings: usize,
}

impl BluedotWebhookPayload {
    pub fn is_supported_event_type(&self) -> bool {
        self.event_type
            .as_deref()
            .map(str::trim)
            .is_some_and(|event_type| {
                matches!(
                    event_type,
                    "video.summary.created"
                        | "video.transcript.created"
                        | "meeting.summary.created"
                        | "meeting.transcript.created"
                )
            })
    }

    pub fn is_transcript_ready_event(&self) -> bool {
        self.event_type
            .as_deref()
            .map(str::trim)
            .is_some_and(|event_type| {
                matches!(
                    event_type,
                    "video.transcript.created" | "meeting.transcript.created"
                )
            })
    }

    pub fn summary_text(&self) -> Option<String> {
        trimmed_owned(self.summary.as_deref()).or_else(|| trimmed_owned(self.summary_v2.as_deref()))
    }

    pub fn normalized_attendees(&self) -> Vec<String> {
        self.attendees
            .iter()
            .filter_map(|attendee| match attendee {
                BluedotAttendee::Email(value) => trimmed_owned(Some(value.as_str())),
                BluedotAttendee::Object { email, name } => {
                    trimmed_owned(email.as_deref()).or_else(|| trimmed_owned(name.as_deref()))
                }
            })
            .collect()
    }

    pub fn normalized_transcript(&self) -> Vec<TranscriptEntry> {
        self.transcript
            .iter()
            .filter_map(|entry| {
                let text = trimmed_owned(entry.text.as_deref())?;
                let speaker =
                    trimmed_owned(entry.speaker.as_deref()).unwrap_or_else(|| "Unknown".into());
                Some(TranscriptEntry { speaker, text })
            })
            .collect()
    }

    pub fn created_at_secs(&self) -> i64 {
        parse_integer_timestamp(self.created_at.as_ref())
            .unwrap_or_else(current_unix_timestamp_secs)
    }

    pub fn duration_secs(&self) -> Option<f64> {
        parse_duration_seconds(self.duration.as_ref())
    }

    pub fn title_text(&self) -> String {
        trimmed_owned(self.title.as_deref()).unwrap_or_else(|| "Untitled Meeting".into())
    }
}

impl BluedotMeetingStore {
    pub fn new(db_path: &str, retention_days: u32, max_meetings: usize) -> anyhow::Result<Self> {
        let db_path = expand_db_path(db_path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create Bluedot database parent directory {}",
                    parent.display()
                )
            })?;
        }

        let conn = Connection::open(&db_path)
            .with_context(|| format!("failed to open Bluedot database {}", db_path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA mmap_size = 8388608;
             PRAGMA cache_size = -2000;
             PRAGMA temp_store = MEMORY;",
        )?;
        init_schema(&conn)?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            retention_days,
            max_meetings: max_meetings.max(1),
        };
        store.prune()?;
        Ok(store)
    }

    pub fn upsert_webhook_payload(
        &self,
        payload: &BluedotWebhookPayload,
    ) -> anyhow::Result<MeetingRecord> {
        let attendees = payload.normalized_attendees();
        let transcript = payload.normalized_transcript();
        let transcript_json = serde_json::to_string(&transcript)?;
        let attendee_json = serde_json::to_string(&attendees)?;
        let attendee_text = attendees.join(" ");
        let summary = payload.summary_text().unwrap_or_default();
        let now = current_unix_timestamp_secs();

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO bluedot_meetings (
                video_id,
                meeting_id,
                title,
                created_at,
                duration_secs,
                attendees_json,
                attendee_text,
                summary,
                transcript_json,
                transcript_text,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(video_id) DO UPDATE SET
                meeting_id = COALESCE(NULLIF(excluded.meeting_id, ''), bluedot_meetings.meeting_id),
                title = COALESCE(NULLIF(excluded.title, ''), bluedot_meetings.title),
                created_at = CASE
                    WHEN bluedot_meetings.created_at <= 0 THEN excluded.created_at
                    ELSE bluedot_meetings.created_at
                END,
                duration_secs = COALESCE(excluded.duration_secs, bluedot_meetings.duration_secs),
                attendees_json = CASE
                    WHEN length(excluded.attendees_json) > 2 THEN excluded.attendees_json
                    ELSE bluedot_meetings.attendees_json
                END,
                attendee_text = CASE
                    WHEN length(excluded.attendee_text) > 0 THEN excluded.attendee_text
                    ELSE bluedot_meetings.attendee_text
                END,
                summary = COALESCE(NULLIF(excluded.summary, ''), bluedot_meetings.summary),
                transcript_json = CASE
                    WHEN json_array_length(excluded.transcript_json) > 0 THEN excluded.transcript_json
                    ELSE bluedot_meetings.transcript_json
                END,
                transcript_text = CASE
                    WHEN length(excluded.transcript_text) > 0 THEN excluded.transcript_text
                    ELSE bluedot_meetings.transcript_text
                END,
                updated_at = excluded.updated_at",
            params![
                payload.video_id,
                payload.meeting_id.as_deref().unwrap_or_default(),
                payload.title_text(),
                payload.created_at_secs(),
                payload.duration_secs(),
                attendee_json,
                attendee_text,
                summary,
                transcript_json,
                flatten_transcript(&transcript),
                now,
            ],
        )?;
        drop(conn);

        self.prune()?;
        self.get(&payload.video_id)?
            .ok_or_else(|| anyhow::anyhow!("meeting disappeared after upsert"))
    }

    pub fn get(&self, video_id: &str) -> anyhow::Result<Option<MeetingRecord>> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT video_id, meeting_id, title, created_at, duration_secs, attendees_json, summary, transcript_json
             FROM bluedot_meetings WHERE video_id = ?1",
            params![video_id],
            map_meeting_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn recent(&self, limit: usize) -> anyhow::Result<Vec<MeetingRecord>> {
        let limit = clamp_limit(limit, DEFAULT_RECENT_LIMIT);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT video_id, meeting_id, title, created_at, duration_secs, attendees_json, summary, transcript_json
             FROM bluedot_meetings
             ORDER BY created_at DESC, updated_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![i64::try_from(limit)?], map_meeting_row)?;
        let mut meetings = Vec::new();
        for row in rows {
            meetings.push(row?);
        }
        Ok(meetings)
    }

    pub fn search(&self, query: &str, limit: usize) -> anyhow::Result<Vec<MeetingSearchResult>> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(Vec::new());
        }

        let limit = clamp_limit(limit, DEFAULT_RECENT_LIMIT);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT
                m.video_id,
                m.meeting_id,
                m.title,
                m.created_at,
                m.duration_secs,
                m.attendees_json,
                m.summary,
                m.transcript_json,
                snippet(bluedot_meetings_fts, -1, '>>>', '<<<', '...', 24) AS snippet
             FROM bluedot_meetings_fts
             JOIN bluedot_meetings m ON m.rowid = bluedot_meetings_fts.rowid
             WHERE bluedot_meetings_fts MATCH ?1
             ORDER BY bm25(bluedot_meetings_fts)
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![fts_escape(query), i64::try_from(limit)?],
            |row| -> rusqlite::Result<MeetingSearchResult> {
                Ok(MeetingSearchResult {
                    meeting: map_meeting_row(row)?,
                    snippet: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
                })
            },
        )?;
        let mut matches = Vec::new();
        for row in rows {
            matches.push(row?);
        }
        Ok(matches)
    }

    pub fn transcript_page(
        &self,
        video_id: &str,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<Option<TranscriptPage>> {
        let Some(meeting) = self.get(video_id)? else {
            return Ok(None);
        };

        let offset = offset.min(meeting.transcript.len());
        let limit = clamp_limit(limit, DEFAULT_TRANSCRIPT_LIMIT);
        let slice = &meeting.transcript[offset..meeting.transcript.len().min(offset + limit)];
        let has_more = offset + slice.len() < meeting.transcript.len();

        Ok(Some(TranscriptPage {
            video_id: meeting.video_id,
            title: meeting.title,
            total: meeting.transcript.len(),
            offset,
            count: slice.len(),
            has_more,
            next_offset: has_more.then_some(offset + slice.len()),
            transcript: flatten_transcript(slice),
        }))
    }

    pub fn inline_transcript_preview(meeting: &MeetingRecord) -> (Option<String>, bool) {
        if meeting.transcript.is_empty() {
            return (None, false);
        }

        let truncated = meeting.transcript.len() > INLINE_TRANSCRIPT_LIMIT;
        let slice = if truncated {
            &meeting.transcript[..INLINE_TRANSCRIPT_LIMIT]
        } else {
            &meeting.transcript[..]
        };
        (Some(flatten_transcript(slice)), truncated)
    }

    fn prune(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let cutoff = current_unix_timestamp_secs()
            - i64::from(self.retention_days.max(1)).saturating_mul(86_400);
        conn.execute(
            "DELETE FROM bluedot_meetings WHERE updated_at < ?1",
            params![cutoff],
        )?;

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM bluedot_meetings", [], |row| {
            row.get(0)
        })?;
        if usize::try_from(count).unwrap_or(0) > self.max_meetings {
            conn.execute(
                "DELETE FROM bluedot_meetings
                 WHERE video_id IN (
                    SELECT video_id
                    FROM bluedot_meetings
                    ORDER BY updated_at ASC, created_at ASC
                    LIMIT ?1
                 )",
                params![i64::try_from(
                    usize::try_from(count).unwrap_or(0) - self.max_meetings
                )?],
            )?;
        }

        Ok(())
    }
}

pub fn import_payloads_from_path(
    config: &Config,
    source: &Path,
    dry_run: bool,
    fail_fast: bool,
) -> anyhow::Result<BluedotImportStats> {
    if !source.exists() {
        bail!("Bluedot import source not found: {}", source.display());
    }

    let files = collect_import_files(source)?;
    if files.is_empty() {
        println!("No files found to import from {}", source.display());
        return Ok(BluedotImportStats::default());
    }

    let expanded_db_path = expand_db_path(&config.bluedot.db_path);
    let store = if dry_run && !expanded_db_path.exists() {
        None
    } else {
        Some(BluedotMeetingStore::new(
            &config.bluedot.db_path,
            config.bluedot.retention_days,
            config.bluedot.max_meetings,
        )?)
    };
    let mut stats = BluedotImportStats::default();

    for file in files {
        stats.files_scanned += 1;
        let payloads = match read_payloads_from_file(&file) {
            Ok(payloads) => payloads,
            Err(error) => {
                stats.failed += 1;
                eprintln!("Failed to read {}: {error}", file.display());
                if fail_fast {
                    return Err(error);
                }
                continue;
            }
        };

        for payload in payloads {
            stats.payloads_scanned += 1;

            if !payload.is_supported_event_type() {
                stats.ignored += 1;
                continue;
            }

            let existed = if let Some(store) = store.as_ref() {
                store.get(&payload.video_id)?.is_some()
            } else {
                false
            };
            if dry_run {
                if existed {
                    stats.updated += 1;
                } else {
                    stats.created += 1;
                }
                continue;
            }

            if let Err(error) = store
                .as_ref()
                .expect("write mode always initializes a Bluedot store")
                .upsert_webhook_payload(&payload)
            {
                stats.failed += 1;
                eprintln!(
                    "Failed to import payload for video {} from {}: {error}",
                    payload.video_id,
                    file.display()
                );
                if fail_fast {
                    return Err(error);
                }
                continue;
            }

            if existed {
                stats.updated += 1;
            } else {
                stats.created += 1;
            }
        }
    }

    print_import_summary(source, &config.bluedot.db_path, &stats, dry_run);
    Ok(stats)
}

pub fn flatten_transcript(entries: &[TranscriptEntry]) -> String {
    let mut lines = Vec::new();
    let mut current_speaker = String::new();
    let mut current_text = Vec::new();

    for entry in entries {
        if entry.speaker == current_speaker {
            current_text.push(entry.text.clone());
        } else {
            if !current_text.is_empty() {
                lines.push(format!("{current_speaker}: {}", current_text.join(" ")));
            }
            current_speaker = entry.speaker.clone();
            current_text = vec![entry.text.clone()];
        }
    }

    if !current_text.is_empty() {
        lines.push(format!("{current_speaker}: {}", current_text.join(" ")));
    }

    lines.join("\n")
}

fn current_unix_timestamp_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}

fn parse_integer_timestamp(value: Option<&Value>) -> Option<i64> {
    let raw = match value? {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|v| i64::try_from(v).ok())),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }?;

    Some(if raw > 1_000_000_000_000 {
        raw / 1000
    } else {
        raw
    })
}

fn parse_duration_seconds(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn trimmed_owned(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn collect_import_files(source: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![source.to_path_buf()];

    while let Some(path) = stack.pop() {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to inspect import path {}", path.display()))?;
        if metadata.is_file() {
            files.push(path);
            continue;
        }

        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .with_context(|| format!("failed to read directory {}", path.display()))?
            {
                let entry = entry?;
                stack.push(entry.path());
            }
        }
    }

    files.sort();
    Ok(files)
}

fn read_payloads_from_file(path: &Path) -> anyhow::Result<Vec<BluedotWebhookPayload>> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read payload file {}", path.display()))?;
    let json: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse JSON from {}", path.display()))?;

    match json {
        Value::Array(values) => values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<BluedotWebhookPayload>, _>>()
            .with_context(|| format!("failed to decode payload array from {}", path.display())),
        Value::Object(_) => serde_json::from_value(json)
            .map(|payload| vec![payload])
            .with_context(|| format!("failed to decode payload object from {}", path.display())),
        _ => bail!(
            "expected a JSON object or array of objects in {}",
            path.display()
        ),
    }
}

fn print_import_summary(source: &Path, db_path: &str, stats: &BluedotImportStats, dry_run: bool) {
    if dry_run {
        println!("🔎 Bluedot import dry run");
    } else {
        println!("✅ Bluedot import complete");
    }
    println!("  Source: {}", source.display());
    println!("  Database: {}", expand_db_path(db_path).display());
    println!("  Files scanned: {}", stats.files_scanned);
    println!("  Payloads scanned: {}", stats.payloads_scanned);
    if dry_run {
        println!("  Would create: {}", stats.created);
        println!("  Would update: {}", stats.updated);
    } else {
        println!("  Created: {}", stats.created);
        println!("  Updated: {}", stats.updated);
    }
    println!("  Ignored unsupported: {}", stats.ignored);
    println!("  Failed: {}", stats.failed);
}

fn expand_db_path(path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(path).into_owned())
}

fn clamp_limit(limit: usize, default_limit: usize) -> usize {
    let limit = if limit == 0 { default_limit } else { limit };
    limit.clamp(1, MAX_SEARCH_LIMIT)
}

fn fts_escape(query: &str) -> String {
    let tokens = query.split_whitespace().filter(|token| !token.is_empty());
    let escaped = tokens
        .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
        .collect::<Vec<_>>();
    if escaped.is_empty() {
        "\"\"".into()
    } else {
        escaped.join(" OR ")
    }
}

fn init_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS bluedot_meetings (
            video_id TEXT PRIMARY KEY,
            meeting_id TEXT,
            title TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT 0,
            duration_secs REAL,
            attendees_json TEXT NOT NULL DEFAULT '[]',
            attendee_text TEXT NOT NULL DEFAULT '',
            summary TEXT,
            transcript_json TEXT NOT NULL DEFAULT '[]',
            transcript_text TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_bluedot_meetings_created_at ON bluedot_meetings(created_at);
        CREATE VIRTUAL TABLE IF NOT EXISTS bluedot_meetings_fts USING fts5(
            video_id UNINDEXED,
            title,
            summary,
            transcript_text,
            attendee_text,
            content='bluedot_meetings',
            content_rowid='rowid',
            tokenize='porter unicode61'
        );
        CREATE TRIGGER IF NOT EXISTS bluedot_meetings_ai AFTER INSERT ON bluedot_meetings BEGIN
            INSERT INTO bluedot_meetings_fts(rowid, video_id, title, summary, transcript_text, attendee_text)
            VALUES (new.rowid, new.video_id, new.title, new.summary, new.transcript_text, new.attendee_text);
        END;
        CREATE TRIGGER IF NOT EXISTS bluedot_meetings_ad AFTER DELETE ON bluedot_meetings BEGIN
            INSERT INTO bluedot_meetings_fts(bluedot_meetings_fts, rowid, video_id, title, summary, transcript_text, attendee_text)
            VALUES ('delete', old.rowid, old.video_id, old.title, old.summary, old.transcript_text, old.attendee_text);
        END;
        CREATE TRIGGER IF NOT EXISTS bluedot_meetings_au AFTER UPDATE ON bluedot_meetings BEGIN
            INSERT INTO bluedot_meetings_fts(bluedot_meetings_fts, rowid, video_id, title, summary, transcript_text, attendee_text)
            VALUES ('delete', old.rowid, old.video_id, old.title, old.summary, old.transcript_text, old.attendee_text);
            INSERT INTO bluedot_meetings_fts(rowid, video_id, title, summary, transcript_text, attendee_text)
            VALUES (new.rowid, new.video_id, new.title, new.summary, new.transcript_text, new.attendee_text);
        END;
        INSERT INTO bluedot_meetings_fts(bluedot_meetings_fts) VALUES('rebuild');",
    )?;
    Ok(())
}

fn map_meeting_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MeetingRecord> {
    let attendees_json: String = row.get(5)?;
    let transcript_json: String = row.get(7)?;
    let attendees = serde_json::from_str::<Vec<String>>(&attendees_json).unwrap_or_default();
    let transcript =
        serde_json::from_str::<Vec<TranscriptEntry>>(&transcript_json).unwrap_or_default();
    Ok(MeetingRecord {
        video_id: row.get(0)?,
        meeting_id: row.get::<_, Option<String>>(1)?,
        title: row.get(2)?,
        created_at: row.get(3)?,
        duration_secs: row.get(4)?,
        attendees,
        summary: row.get(6)?,
        transcript,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store() -> (TempDir, BluedotMeetingStore) {
        let dir = TempDir::new().unwrap();
        let store =
            BluedotMeetingStore::new(&dir.path().join("bluedot.db").to_string_lossy(), 365, 100)
                .unwrap();
        (dir, store)
    }

    fn summary_payload() -> BluedotWebhookPayload {
        BluedotWebhookPayload {
            event_type: Some("video.summary.created".into()),
            video_id: "vid-1".into(),
            meeting_id: Some("meet-1".into()),
            title: Some("Planning".into()),
            created_at: Some(Value::from(1_710_000_000_i64)),
            duration: Some(Value::from(1800)),
            attendees: vec![
                BluedotAttendee::Email("alice@example.com".into()),
                BluedotAttendee::Object {
                    email: Some("bob@example.com".into()),
                    name: Some("Bob".into()),
                },
            ],
            summary: Some("Shipped the webhook plan.".into()),
            summary_v2: None,
            transcript: Vec::new(),
        }
    }

    fn transcript_payload() -> BluedotWebhookPayload {
        BluedotWebhookPayload {
            event_type: Some("video.transcript.created".into()),
            video_id: "vid-1".into(),
            meeting_id: Some("meet-1".into()),
            title: Some("Planning".into()),
            created_at: Some(Value::from(1_710_000_000_i64)),
            duration: Some(Value::from(1800)),
            attendees: Vec::new(),
            summary: None,
            summary_v2: None,
            transcript: vec![
                RawTranscriptEntry {
                    speaker: Some("Alice".into()),
                    text: Some("We should wire the webhook.".into()),
                },
                RawTranscriptEntry {
                    speaker: Some("Alice".into()),
                    text: Some("Then store the transcript.".into()),
                },
                RawTranscriptEntry {
                    speaker: Some("Bob".into()),
                    text: Some("Agreed.".into()),
                },
            ],
        }
    }

    fn write_payload_file(path: &Path, payload: &BluedotWebhookPayload) {
        fs::write(path, serde_json::to_vec(payload).unwrap()).unwrap();
    }

    #[test]
    fn webhook_payload_normalizes_attendees_and_transcript() {
        let payload = transcript_payload();
        assert_eq!(payload.normalized_attendees(), Vec::<String>::new());
        assert_eq!(
            payload.normalized_transcript(),
            vec![
                TranscriptEntry {
                    speaker: "Alice".into(),
                    text: "We should wire the webhook.".into(),
                },
                TranscriptEntry {
                    speaker: "Alice".into(),
                    text: "Then store the transcript.".into(),
                },
                TranscriptEntry {
                    speaker: "Bob".into(),
                    text: "Agreed.".into(),
                }
            ]
        );
    }

    #[test]
    fn upsert_merges_summary_and_transcript() {
        let (_dir, store) = test_store();
        store.upsert_webhook_payload(&summary_payload()).unwrap();
        let merged = store.upsert_webhook_payload(&transcript_payload()).unwrap();

        assert_eq!(merged.video_id, "vid-1");
        assert_eq!(merged.summary.as_deref(), Some("Shipped the webhook plan."));
        assert_eq!(merged.transcript.len(), 3);
        assert_eq!(merged.attendees.len(), 2);
    }

    #[test]
    fn search_matches_transcript_text() {
        let (_dir, store) = test_store();
        store.upsert_webhook_payload(&summary_payload()).unwrap();
        store.upsert_webhook_payload(&transcript_payload()).unwrap();

        let results = store.search("webhook", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].meeting.video_id, "vid-1");
        assert!(!results[0].snippet.is_empty());
    }

    #[test]
    fn transcript_page_paginates_segments() {
        let (_dir, store) = test_store();
        store.upsert_webhook_payload(&summary_payload()).unwrap();
        store.upsert_webhook_payload(&transcript_payload()).unwrap();

        let page = store.transcript_page("vid-1", 1, 1).unwrap().unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 1);
        assert_eq!(page.count, 1);
        assert!(page.has_more);
        assert_eq!(page.next_offset, Some(2));
        assert!(
            page.transcript
                .contains("Alice: Then store the transcript.")
        );
    }

    #[test]
    fn supported_event_filter_is_exact() {
        let mut payload = summary_payload();
        assert!(payload.is_supported_event_type());
        payload.event_type = Some("video.deleted".into());
        assert!(!payload.is_supported_event_type());
    }

    #[test]
    fn import_payloads_from_directory_merges_records() {
        let dir = TempDir::new().unwrap();
        let payload_dir = dir.path().join("payloads");
        fs::create_dir_all(payload_dir.join("nested")).unwrap();
        write_payload_file(&payload_dir.join("summary.json"), &summary_payload());
        write_payload_file(
            &payload_dir.join("nested").join("transcript.json"),
            &transcript_payload(),
        );

        let mut config = Config::default();
        config.bluedot.db_path = dir.path().join("bluedot.db").to_string_lossy().to_string();

        let stats = import_payloads_from_path(&config, &payload_dir, false, true).unwrap();
        assert_eq!(stats.files_scanned, 2);
        assert_eq!(stats.payloads_scanned, 2);
        assert_eq!(stats.created, 1);
        assert_eq!(stats.updated, 1);
        assert_eq!(stats.failed, 0);

        let store = BluedotMeetingStore::new(&config.bluedot.db_path, 365, 100).unwrap();
        let meeting = store.get("vid-1").unwrap().unwrap();
        assert_eq!(
            meeting.summary.as_deref(),
            Some("Shipped the webhook plan.")
        );
        assert_eq!(meeting.transcript.len(), 3);
    }

    #[test]
    fn import_payloads_dry_run_leaves_store_unchanged() {
        let dir = TempDir::new().unwrap();
        let payload_path = dir.path().join("payload.json");
        write_payload_file(&payload_path, &summary_payload());
        let db_path = dir.path().join("bluedot.db");

        let mut config = Config::default();
        config.bluedot.db_path = db_path.to_string_lossy().to_string();

        let stats = import_payloads_from_path(&config, &payload_path, true, true).unwrap();
        assert_eq!(stats.files_scanned, 1);
        assert_eq!(stats.created, 1);
        assert!(!db_path.exists());

        let store = BluedotMeetingStore::new(&config.bluedot.db_path, 365, 100).unwrap();
        assert!(store.get("vid-1").unwrap().is_none());
    }

    #[test]
    fn import_payloads_fail_fast_returns_first_error() {
        let dir = TempDir::new().unwrap();
        let payload_path = dir.path().join("broken.json");
        fs::write(&payload_path, b"{not-json").unwrap();

        let mut config = Config::default();
        config.bluedot.db_path = dir.path().join("bluedot.db").to_string_lossy().to_string();

        let error = import_payloads_from_path(&config, &payload_path, false, true).unwrap_err();
        assert!(error.to_string().contains("failed to parse JSON"));
    }
}
