use super::traits::{Tool, ToolResult};
use crate::bluedot::{BluedotMeetingStore, MeetingRecord};
use crate::security::{SecurityPolicy, policy::ToolOperation};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

const DEFAULT_LIMIT: usize = 10;
const DEFAULT_TRANSCRIPT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 50;

pub struct BluedotMeetingTool {
    store: BluedotMeetingStore,
    allowed_actions: Vec<String>,
    security: Arc<SecurityPolicy>,
}

impl BluedotMeetingTool {
    pub fn new(
        db_path: String,
        allowed_actions: Vec<String>,
        security: Arc<SecurityPolicy>,
        retention_days: u32,
        max_meetings: usize,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            store: BluedotMeetingStore::new(&db_path, retention_days, max_meetings)?,
            allowed_actions,
            security,
        })
    }

    fn is_action_allowed(&self, action: &str) -> bool {
        self.allowed_actions
            .iter()
            .any(|candidate| candidate == action)
    }

    fn recent(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64), DEFAULT_LIMIT);
        let meetings = self.store.recent(limit)?;
        json_tool_result(&json!({
            "count": meetings.len(),
            "meetings": meetings.iter().map(summarize_meeting).collect::<Vec<_>>(),
        }))
    }

    fn get(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let video_id = required_trimmed(args, "video_id", "get requires video_id")?;
        let Some(meeting) = self.store.get(video_id)? else {
            anyhow::bail!("Meeting not found: {video_id}");
        };

        let (transcript_preview, truncated) =
            BluedotMeetingStore::inline_transcript_preview(&meeting);

        json_tool_result(&json!({
            "meeting": {
                "video_id": meeting.video_id,
                "meeting_id": meeting.meeting_id,
                "title": meeting.title,
                "created_at": meeting.created_at,
                "date": iso_timestamp(meeting.created_at),
                "duration_secs": meeting.duration_secs,
                "duration_minutes": meeting.duration_secs.map(|secs| (secs / 60.0_f64).round()),
                "attendees": meeting.attendees,
                "summary": meeting.summary,
                "has_transcript": !meeting.transcript.is_empty(),
                "transcript_segments": meeting.transcript.len(),
                "transcript": transcript_preview,
                "transcript_truncated": truncated,
            }
        }))
    }

    fn search(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let query = required_trimmed(args, "query", "search requires query")?;
        let limit = clamp_limit(args.get("limit").and_then(Value::as_u64), DEFAULT_LIMIT);
        let matches = self.store.search(query, limit)?;
        json_tool_result(&json!({
            "query": query,
            "count": matches.len(),
            "meetings": matches.into_iter().map(|result| json!({
                "video_id": result.meeting.video_id,
                "meeting_id": result.meeting.meeting_id,
                "title": result.meeting.title,
                "date": iso_timestamp(result.meeting.created_at),
                "duration_minutes": result.meeting.duration_secs.map(|secs| (secs / 60.0_f64).round()),
                "attendees": result.meeting.attendees,
                "has_summary": result.meeting.summary.is_some(),
                "has_transcript": !result.meeting.transcript.is_empty(),
                "snippet": result.snippet,
            })).collect::<Vec<_>>(),
        }))
    }

    fn transcript(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let video_id = required_trimmed(args, "video_id", "transcript requires video_id")?;
        let offset = args
            .get("offset")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0);
        let limit = clamp_limit(
            args.get("limit").and_then(Value::as_u64),
            DEFAULT_TRANSCRIPT_LIMIT,
        );

        let Some(page) = self.store.transcript_page(video_id, offset, limit)? else {
            anyhow::bail!("Meeting not found: {video_id}");
        };

        json_tool_result(&serde_json::to_value(&page)?)
    }
}

#[async_trait]
impl Tool for BluedotMeetingTool {
    fn name(&self) -> &str {
        "bluedot_meeting"
    }

    fn description(&self) -> &str {
        "Query stored Bluedot meeting summaries and transcripts."
    }

    fn parameters_schema(&self) -> Value {
        serde_json::from_str(
            r#"{
              "type": "object",
              "properties": {
                "action": {
                  "type": "string",
                  "enum": ["recent", "get", "search", "transcript"],
                  "description": "Action to perform."
                },
                "video_id": {
                  "type": "string",
                  "description": "Bluedot video ID for get or transcript."
                },
                "query": {
                  "type": "string",
                  "description": "Search query for meeting title, summary, transcript, or attendee text."
                },
                "limit": {
                  "type": "integer",
                  "description": "Maximum number of results (default 10, max 50). For transcript, this is the number of transcript chunks."
                },
                "offset": {
                  "type": "integer",
                  "description": "Transcript segment offset for transcript pagination."
                }
              },
              "required": ["action"]
            }"#,
        )
        .expect("bluedot_meeting schema must be valid JSON")
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let Some(action) = args.get("action").and_then(Value::as_str) else {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Missing required parameter: action".into()),
            });
        };

        if !matches!(action, "recent" | "get" | "search" | "transcript") {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action: '{action}'. Valid actions: recent, get, search, transcript"
                )),
            });
        }

        if !self.is_action_allowed(action) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Action '{action}' is not enabled. Add it to bluedot.allowed_actions in config.toml. Currently allowed: {}",
                    self.allowed_actions.join(", ")
                )),
            });
        }

        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Read, "bluedot_meeting")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        let result = match action {
            "recent" => self.recent(&args),
            "get" => self.get(&args),
            "search" => self.search(&args),
            "transcript" => self.transcript(&args),
            _ => unreachable!(),
        };

        match result {
            Ok(tool_result) => Ok(tool_result),
            Err(error) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error.to_string()),
            }),
        }
    }
}

fn summarize_meeting(meeting: &MeetingRecord) -> Value {
    json!({
        "video_id": meeting.video_id,
        "meeting_id": meeting.meeting_id,
        "title": meeting.title,
        "date": iso_timestamp(meeting.created_at),
        "duration_minutes": meeting.duration_secs.map(|secs| (secs / 60.0_f64).round()),
        "attendees": meeting.attendees,
        "has_summary": meeting.summary.is_some(),
        "has_transcript": !meeting.transcript.is_empty(),
    })
}

fn required_trimmed<'a>(args: &'a Value, key: &str, message: &str) -> anyhow::Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

fn clamp_limit(limit: Option<u64>, default_limit: usize) -> usize {
    limit
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default_limit)
        .clamp(1, MAX_LIMIT)
}

fn iso_timestamp(timestamp: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(timestamp, 0).map(|value| value.to_rfc3339())
}

fn json_tool_result<T: serde::Serialize>(value: &T) -> anyhow::Result<ToolResult> {
    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(value)?,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluedot::BluedotWebhookPayload;
    use tempfile::TempDir;

    fn tool_with_store() -> (TempDir, BluedotMeetingTool) {
        let dir = TempDir::new().unwrap();
        let tool = BluedotMeetingTool::new(
            dir.path().join("bluedot.db").to_string_lossy().to_string(),
            vec![
                "recent".into(),
                "get".into(),
                "search".into(),
                "transcript".into(),
            ],
            Arc::new(SecurityPolicy::default()),
            365,
            100,
        )
        .unwrap();
        (dir, tool)
    }

    fn seeded_tool() -> (TempDir, BluedotMeetingTool) {
        let (dir, tool) = tool_with_store();
        tool.store
            .upsert_webhook_payload(&BluedotWebhookPayload {
                event_type: Some("video.summary.created".into()),
                video_id: "vid-1".into(),
                meeting_id: Some("meet-1".into()),
                title: Some("Planning".into()),
                created_at: Some(Value::from(1_710_000_000_i64)),
                duration: Some(Value::from(1800)),
                attendees: Vec::new(),
                summary: Some("Webhook rollout".into()),
                summary_v2: None,
                transcript: Vec::new(),
            })
            .unwrap();
        tool.store
            .upsert_webhook_payload(&BluedotWebhookPayload {
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
                    crate::bluedot::RawTranscriptEntry {
                        speaker: Some("Alice".into()),
                        text: Some("Ship the integration.".into()),
                    },
                    crate::bluedot::RawTranscriptEntry {
                        speaker: Some("Bob".into()),
                        text: Some("Then document it.".into()),
                    },
                ],
            })
            .unwrap();
        (dir, tool)
    }

    #[test]
    fn schema_lists_supported_actions() {
        let (_dir, tool) = tool_with_store();
        let schema = tool.parameters_schema();
        let actions = schema["properties"]["action"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();

        assert!(actions.contains(&"recent"));
        assert!(actions.contains(&"get"));
        assert!(actions.contains(&"search"));
        assert!(actions.contains(&"transcript"));
    }

    #[tokio::test]
    async fn get_requires_video_id() {
        let (_dir, tool) = tool_with_store();
        let result = tool.execute(json!({"action": "get"})).await.unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("video_id")
        );
    }

    #[tokio::test]
    async fn search_returns_snippet() {
        let (_dir, tool) = seeded_tool();
        let result = tool
            .execute(json!({"action": "search", "query": "integration"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("snippet"));
    }

    #[tokio::test]
    async fn transcript_returns_paginated_output() {
        let (_dir, tool) = seeded_tool();
        let result = tool
            .execute(json!({"action": "transcript", "video_id": "vid-1", "limit": 1}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("\"has_more\": true"));
    }
}
