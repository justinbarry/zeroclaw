//! Axum-based HTTP gateway with proper HTTP/1.1 compliance, body limits, and timeouts.
//!
//! This module replaces the raw TCP implementation with axum for:
//! - Proper HTTP/1.1 parsing and compliance
//! - Content-Length validation (handled by hyper)
//! - Request body size limits (64KB max)
//! - Request timeouts (30s) to prevent slow-loris attacks
//! - Header sanitization (handled by axum/hyper)

pub mod api;
pub mod api_pairing;
#[cfg(feature = "plugins-wasm")]
pub mod api_plugins;
#[cfg(feature = "webauthn")]
pub mod api_webauthn;
pub mod auth_rate_limit;
pub mod canvas;
pub mod nodes;
pub mod session_queue;
pub mod sse;
pub mod static_files;
pub mod tls;
pub mod ws;

use crate::bluedot::{BluedotMeetingStore, BluedotWebhookPayload};
use crate::channels::{
    Channel, GmailPushChannel, LinqChannel, NextcloudTalkChannel, SendMessage, WatiChannel,
    WhatsAppChannel, session_backend::SessionBackend, session_sqlite::SqliteSessionBackend,
};
use crate::config::Config;
use crate::cost::CostTracker;
use crate::memory::{self, Memory, MemoryCategory};
use crate::providers::{self, ChatMessage, Provider};
use crate::runtime;
use crate::security::SecurityPolicy;
use crate::security::pairing::{PairingGuard, constant_time_eq, is_public_bind};
use crate::tools;
use crate::tools::canvas::CanvasStore;
use crate::tools::traits::{Tool, ToolSpec};
use crate::util::truncate_with_ellipsis;
use anyhow::{Context, Result};
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

/// Maximum request body size (64KB) — prevents memory exhaustion
pub const MAX_BODY_SIZE: usize = 65_536;
/// Default request timeout (30s) — prevents slow-loris attacks.
pub const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Read gateway request timeout from `ZEROCLAW_GATEWAY_TIMEOUT_SECS` env var
/// at runtime, falling back to [`REQUEST_TIMEOUT_SECS`].
///
/// Agentic workloads with tool use (web search, MCP tools, sub-agent
/// delegation) regularly exceed 30 seconds. This allows operators to
/// increase the timeout without recompiling.
pub fn gateway_request_timeout_secs() -> u64 {
    std::env::var("ZEROCLAW_GATEWAY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(REQUEST_TIMEOUT_SECS)
}
/// Sliding window used by gateway rate limiting.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Fallback max distinct client keys tracked in gateway rate limiter.
pub const RATE_LIMIT_MAX_KEYS_DEFAULT: usize = 10_000;
/// Fallback max distinct idempotency keys retained in gateway memory.
pub const IDEMPOTENCY_MAX_KEYS_DEFAULT: usize = 10_000;

fn webhook_memory_key() -> String {
    format!("webhook_msg_{}", Uuid::new_v4())
}

fn whatsapp_memory_key(msg: &crate::channels::traits::ChannelMessage) -> String {
    format!("whatsapp_{}_{}", msg.sender, msg.id)
}

fn linq_memory_key(msg: &crate::channels::traits::ChannelMessage) -> String {
    format!("linq_{}_{}", msg.sender, msg.id)
}

fn wati_memory_key(msg: &crate::channels::traits::ChannelMessage) -> String {
    format!("wati_{}_{}", msg.sender, msg.id)
}

fn nextcloud_talk_memory_key(msg: &crate::channels::traits::ChannelMessage) -> String {
    format!("nextcloud_talk_{}_{}", msg.sender, msg.id)
}

fn linear_webhook_memory_key(delivery_id: Option<&str>) -> String {
    match delivery_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(delivery_id) => format!("linear_webhook_{delivery_id}"),
        None => format!("linear_webhook_{}", Uuid::new_v4()),
    }
}

fn sender_session_id(channel: &str, msg: &crate::channels::traits::ChannelMessage) -> String {
    match &msg.thread_ts {
        Some(thread_id) => format!("{channel}_{thread_id}_{}", msg.sender),
        None => format!("{channel}_{}", msg.sender),
    }
}

fn webhook_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn hash_webhook_secret(value: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

fn current_unix_timestamp_millis() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

fn bluedot_webhook_enabled(config: &Config) -> bool {
    config.bluedot.webhook_enabled
}

fn resolve_bluedot_webhook_secret(config: &Config) -> Option<String> {
    std::env::var("BLUEDOT_WEBHOOK_SECRET")
        .ok()
        .and_then(|secret| {
            let secret = secret.trim();
            (!secret.is_empty()).then(|| secret.to_owned())
        })
        .or_else(|| {
            config
                .bluedot
                .webhook_secret
                .as_deref()
                .map(str::trim)
                .filter(|secret| !secret.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn bluedot_webhook_timestamp_is_fresh(timestamp_secs: i64) -> bool {
    let now_secs = current_unix_timestamp_millis() / 1000;
    (now_secs - timestamp_secs).abs() <= 300
}

fn verify_bluedot_signature(
    secret: &str,
    svix_id: &str,
    svix_timestamp: &str,
    body: &[u8],
    svix_signature: &str,
) -> bool {
    use base64::Engine as _;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let svix_id = svix_id.trim();
    let svix_timestamp = svix_timestamp.trim();
    let svix_signature = svix_signature.trim();
    if svix_id.is_empty() || svix_timestamp.is_empty() || svix_signature.is_empty() {
        return false;
    }

    let timestamp = match svix_timestamp.parse::<i64>() {
        Ok(timestamp) if bluedot_webhook_timestamp_is_fresh(timestamp) => timestamp,
        _ => return false,
    };
    let _ = timestamp;

    let secret = secret.trim();
    let secret = secret.strip_prefix("whsec_").unwrap_or(secret);
    let secret_bytes = match base64::engine::general_purpose::STANDARD.decode(secret) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(&secret_bytes) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    let mut signed_content =
        String::with_capacity(svix_id.len() + svix_timestamp.len() + body.len() + 2);
    signed_content.push_str(svix_id);
    signed_content.push('.');
    signed_content.push_str(svix_timestamp);
    signed_content.push('.');
    signed_content.push_str(&String::from_utf8_lossy(body));
    mac.update(signed_content.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    svix_signature.split_whitespace().any(|candidate| {
        let mut parts = candidate.splitn(2, ',');
        matches!(
            (parts.next(), parts.next()),
            (Some("v1"), Some(value)) if value == expected
        )
    })
}

fn linear_webhook_enabled(config: &Config) -> bool {
    config.linear.webhook_enabled
}

fn bluedot_webhook_memory_key(delivery_id: Option<&str>) -> String {
    match delivery_id.filter(|value| !value.trim().is_empty()) {
        Some(delivery_id) => format!("bluedot_webhook_{delivery_id}"),
        None => format!("bluedot_webhook_{}", Uuid::new_v4()),
    }
}

fn bluedot_webhook_automation_enabled(config: &Config) -> bool {
    config.bluedot.webhook_automation_enabled
}

fn normalize_automation_keyword(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

fn normalize_automation_email(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

fn normalize_webhook_automation_agent(agent_name: Option<&str>) -> Option<String> {
    agent_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
}

fn linear_webhook_automation_enabled(config: &Config) -> bool {
    config.linear.webhook_automation_enabled
}

fn normalize_linear_issue_prefix(prefix: &str) -> Option<String> {
    let prefix = prefix.trim().trim_end_matches('-').trim();
    (!prefix.is_empty()).then(|| format!("{}-", prefix.to_ascii_uppercase()))
}

fn resolve_linear_webhook_secret(config: &Config) -> Option<String> {
    std::env::var("LINEAR_WEBHOOK_SECRET")
        .ok()
        .and_then(|secret| {
            let secret = secret.trim();
            (!secret.is_empty()).then(|| secret.to_owned())
        })
        .or_else(|| {
            config
                .linear
                .webhook_secret
                .as_deref()
                .map(str::trim)
                .filter(|secret| !secret.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn linear_webhook_timestamp_is_fresh(webhook_timestamp: i64) -> bool {
    (current_unix_timestamp_millis() - webhook_timestamp).abs() <= 60_000
}

fn linear_webhook_automation_matches(
    filters: &[String],
    issue_prefixes: &[String],
    linear_event: Option<&str>,
    payload: &LinearWebhookPayload,
) -> bool {
    if filters.is_empty() {
        return false;
    }

    let action = payload
        .action
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let event_candidates = [
        linear_event
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        payload
            .event_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    ];

    let event_match = filters.iter().map(|value| value.trim()).any(|filter| {
        if filter.is_empty() {
            return false;
        }

        event_candidates.iter().flatten().any(|event| {
            filter.eq_ignore_ascii_case(event)
                || action
                    .is_some_and(|action| filter.eq_ignore_ascii_case(&format!("{event}:{action}")))
        })
    });

    if !event_match {
        return false;
    }

    if issue_prefixes.is_empty() {
        return true;
    }

    let Some(identifier) = linear_webhook_issue_identifier(payload) else {
        return false;
    };
    let identifier = identifier.to_ascii_uppercase();
    issue_prefixes
        .iter()
        .filter_map(|prefix| normalize_linear_issue_prefix(prefix))
        .any(|prefix| identifier.starts_with(&prefix))
}

fn bluedot_webhook_automation_matches(
    title_keywords: &[String],
    attendee_emails: &[String],
    meeting: &crate::bluedot::MeetingRecord,
) -> bool {
    let normalized_keywords: Vec<String> = title_keywords
        .iter()
        .filter_map(|value| normalize_automation_keyword(value))
        .collect();
    let normalized_attendees: Vec<String> = attendee_emails
        .iter()
        .filter_map(|value| normalize_automation_email(value))
        .collect();

    if !normalized_keywords.is_empty() {
        let title = meeting.title.trim().to_ascii_lowercase();
        if !normalized_keywords
            .iter()
            .any(|keyword| title.contains(keyword))
        {
            return false;
        }
    }

    if normalized_attendees.is_empty() {
        return true;
    }

    let meeting_attendees: Vec<String> = meeting
        .attendees
        .iter()
        .filter_map(|value| normalize_automation_email(value))
        .collect();

    normalized_attendees
        .iter()
        .any(|attendee| meeting_attendees.iter().any(|value| value == attendee))
}

fn linear_webhook_issue_identifier(payload: &LinearWebhookPayload) -> Option<String> {
    if let Some(identifier) = payload
        .data
        .get("identifier")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(identifier.to_string());
    }

    let url = payload.url.as_deref()?.trim();
    let marker = "/issue/";
    let start = url.find(marker)? + marker.len();
    let remainder = &url[start..];
    let identifier = remainder
        .split(['/', '#', '?'])
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(identifier.to_string())
}

fn build_linear_webhook_automation_message(
    delivery_id: Option<&str>,
    linear_event: Option<&str>,
    payload: &LinearWebhookPayload,
) -> String {
    let normalized = serde_json::json!({
        "source": "linear",
        "delivery_id": delivery_id,
        "event": linear_event,
        "action": payload.action,
        "type": payload.event_type,
        "created_at": payload.created_at,
        "organization_id": payload.organization_id,
        "webhook_id": payload.webhook_id,
        "url": payload.url,
        "webhook_timestamp": payload.webhook_timestamp,
        "updated_from": payload.updated_from,
        "data": payload.data,
    });

    format!(
        "A verified Linear webhook event matched the configured automation filters.\n\
         Analyze the event and take any configured follow-up actions using available tools.\n\
         If no action is warranted, summarize that briefly.\n\n{}",
        serde_json::to_string_pretty(&normalized)
            .unwrap_or_else(|_| "{\"source\":\"linear\"}".to_string())
    )
}

fn build_bluedot_webhook_automation_message(
    delivery_id: Option<&str>,
    payload: &BluedotWebhookPayload,
    meeting: &crate::bluedot::MeetingRecord,
) -> String {
    let normalized = serde_json::json!({
        "source": "bluedot",
        "delivery_id": delivery_id,
        "event": payload.event_type,
        "video_id": meeting.video_id,
        "meeting_id": meeting.meeting_id,
        "title": meeting.title,
        "created_at": meeting.created_at,
        "duration_secs": meeting.duration_secs,
        "attendees": meeting.attendees,
        "summary_present": meeting.summary.as_ref().is_some_and(|value| !value.trim().is_empty()),
        "transcript_entries": meeting.transcript.len(),
    });

    format!(
        "A verified Bluedot transcript webhook was received.\n\
         Use the bluedot_meeting tool to inspect the meeting for video_id `{}`.\n\
         Look for related Linear issues or projects using the available Linear tools.\n\
         Prefer read-only Linear lookups such as search_issues, get_issue, search_projects, and get_project.\n\
         Respond with five short sections titled exactly: Likely Project, Related Issues, Risks/Blockers, Suggested Follow-up, Write Recommendation.\n\
         In Write Recommendation, state whether a Linear comment, document update, issue update, or no write is warranted.\n\
         If nothing relevant is found, say that explicitly in Likely Project and Related Issues.\n\
         Do not create or modify Linear data unless a later step explicitly asks for it and approval allows it.\n\n{}",
        meeting.video_id,
        serde_json::to_string_pretty(&normalized)
            .unwrap_or_else(|_| "{\"source\":\"bluedot\"}".to_string())
    )
}

pub fn verify_linear_signature(secret: &str, body: &[u8], signature_header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let signature = signature_header.trim();
    if signature.is_empty() {
        return false;
    }

    let Ok(signature_bytes) = hex::decode(signature) else {
        return false;
    };

    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&signature_bytes).is_ok()
}

/// How often the rate limiter sweeps stale IP entries from its map.
const RATE_LIMITER_SWEEP_INTERVAL_SECS: u64 = 300; // 5 minutes

#[derive(Debug)]
struct SlidingWindowRateLimiter {
    limit_per_window: u32,
    window: Duration,
    max_keys: usize,
    requests: Mutex<(HashMap<String, Vec<Instant>>, Instant)>,
}

impl SlidingWindowRateLimiter {
    fn new(limit_per_window: u32, window: Duration, max_keys: usize) -> Self {
        Self {
            limit_per_window,
            window,
            max_keys: max_keys.max(1),
            requests: Mutex::new((HashMap::new(), Instant::now())),
        }
    }

    fn prune_stale(requests: &mut HashMap<String, Vec<Instant>>, cutoff: Instant) {
        requests.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }

    fn allow(&self, key: &str) -> bool {
        if self.limit_per_window == 0 {
            return true;
        }

        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or_else(Instant::now);

        let mut guard = self.requests.lock();
        let (requests, last_sweep) = &mut *guard;

        // Periodic sweep: remove keys with no recent requests
        if last_sweep.elapsed() >= Duration::from_secs(RATE_LIMITER_SWEEP_INTERVAL_SECS) {
            Self::prune_stale(requests, cutoff);
            *last_sweep = now;
        }

        if !requests.contains_key(key) && requests.len() >= self.max_keys {
            // Opportunistic stale cleanup before eviction under cardinality pressure.
            Self::prune_stale(requests, cutoff);
            *last_sweep = now;

            if requests.len() >= self.max_keys {
                let evict_key = requests
                    .iter()
                    .min_by_key(|(_, timestamps)| timestamps.last().copied().unwrap_or(cutoff))
                    .map(|(k, _)| k.clone());
                if let Some(evict_key) = evict_key {
                    requests.remove(&evict_key);
                }
            }
        }

        let entry = requests.entry(key.to_owned()).or_default();
        entry.retain(|instant| *instant > cutoff);

        if entry.len() >= self.limit_per_window as usize {
            return false;
        }

        entry.push(now);
        true
    }
}

#[derive(Debug)]
pub struct GatewayRateLimiter {
    pair: SlidingWindowRateLimiter,
    webhook: SlidingWindowRateLimiter,
}

impl GatewayRateLimiter {
    fn new(pair_per_minute: u32, webhook_per_minute: u32, max_keys: usize) -> Self {
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        Self {
            pair: SlidingWindowRateLimiter::new(pair_per_minute, window, max_keys),
            webhook: SlidingWindowRateLimiter::new(webhook_per_minute, window, max_keys),
        }
    }

    fn allow_pair(&self, key: &str) -> bool {
        self.pair.allow(key)
    }

    fn allow_webhook(&self, key: &str) -> bool {
        self.webhook.allow(key)
    }
}

#[derive(Debug)]
pub struct IdempotencyStore {
    ttl: Duration,
    max_keys: usize,
    keys: Mutex<HashMap<String, Instant>>,
}

impl IdempotencyStore {
    fn new(ttl: Duration, max_keys: usize) -> Self {
        Self {
            ttl,
            max_keys: max_keys.max(1),
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if this key is new and is now recorded.
    fn record_if_new(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut keys = self.keys.lock();

        keys.retain(|_, seen_at| now.duration_since(*seen_at) < self.ttl);

        if keys.contains_key(key) {
            return false;
        }

        if keys.len() >= self.max_keys {
            let evict_key = keys
                .iter()
                .min_by_key(|(_, seen_at)| *seen_at)
                .map(|(k, _)| k.clone());
            if let Some(evict_key) = evict_key {
                keys.remove(&evict_key);
            }
        }

        keys.insert(key.to_owned(), now);
        true
    }
}

fn parse_client_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"').trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip());
    }

    let value = value.trim_matches(['[', ']']);
    value.parse::<IpAddr>().ok()
}

fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        for candidate in xff.split(',') {
            if let Some(ip) = parse_client_ip(candidate) {
                return Some(ip);
            }
        }
    }

    headers
        .get("X-Real-IP")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_client_ip)
}

fn client_key_from_request(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trust_forwarded_headers: bool,
) -> String {
    if trust_forwarded_headers {
        if let Some(ip) = forwarded_client_ip(headers) {
            return ip.to_string();
        }
    }

    peer_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn normalize_max_keys(configured: usize, fallback: usize) -> usize {
    if configured == 0 {
        fallback.max(1)
    } else {
        configured
    }
}

/// Shared state for all axum handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Mutex<Config>>,
    pub provider: Arc<dyn Provider>,
    pub model: String,
    pub temperature: f64,
    pub mem: Arc<dyn Memory>,
    pub auto_save: bool,
    /// SHA-256 hash of `X-Webhook-Secret` (hex-encoded), never plaintext.
    pub webhook_secret_hash: Option<Arc<str>>,
    pub pairing: Arc<PairingGuard>,
    pub trust_forwarded_headers: bool,
    pub rate_limiter: Arc<GatewayRateLimiter>,
    pub auth_limiter: Arc<auth_rate_limit::AuthRateLimiter>,
    pub idempotency_store: Arc<IdempotencyStore>,
    pub whatsapp: Option<Arc<WhatsAppChannel>>,
    /// `WhatsApp` app secret for webhook signature verification (`X-Hub-Signature-256`)
    pub whatsapp_app_secret: Option<Arc<str>>,
    pub linq: Option<Arc<LinqChannel>>,
    /// Linq webhook signing secret for signature verification
    pub linq_signing_secret: Option<Arc<str>>,
    pub nextcloud_talk: Option<Arc<NextcloudTalkChannel>>,
    /// Nextcloud Talk webhook secret for signature verification
    pub nextcloud_talk_webhook_secret: Option<Arc<str>>,
    pub wati: Option<Arc<WatiChannel>>,
    /// Gmail Pub/Sub push notification channel
    pub gmail_push: Option<Arc<GmailPushChannel>>,
    /// Observability backend for metrics scraping
    pub observer: Arc<dyn crate::observability::Observer>,
    /// Registered tool specs (for web dashboard tools page)
    pub tools_registry: Arc<Vec<ToolSpec>>,
    /// Cost tracker (optional, for web dashboard cost page)
    pub cost_tracker: Option<Arc<CostTracker>>,
    /// SSE broadcast channel for real-time events
    pub event_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// Ring buffer of recent events for history replay
    pub event_buffer: Arc<sse::EventBuffer>,
    /// Shutdown signal sender for graceful shutdown
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Registry of dynamically connected nodes
    pub node_registry: Arc<nodes::NodeRegistry>,
    /// Path prefix for reverse-proxy deployments (empty string = no prefix)
    pub path_prefix: String,
    /// Session backend for persisting gateway WS chat sessions
    pub session_backend: Option<Arc<dyn SessionBackend>>,
    /// Per-session actor queue for serializing concurrent turns
    pub session_queue: Arc<session_queue::SessionActorQueue>,
    /// Device registry for paired device management
    pub device_registry: Option<Arc<api_pairing::DeviceRegistry>>,
    /// Pending pairing request store
    pub pending_pairings: Option<Arc<api_pairing::PairingStore>>,
    /// Shared canvas store for Live Canvas (A2UI) system
    pub canvas_store: CanvasStore,
    /// Concurrency limit for webhook-triggered automation spawns.
    pub webhook_automation_semaphore: Arc<tokio::sync::Semaphore>,
    /// WebAuthn state for hardware key authentication (optional, requires `webauthn` feature)
    #[cfg(feature = "webauthn")]
    pub webauthn: Option<Arc<api_webauthn::WebAuthnState>>,
}

/// Run the HTTP gateway using axum with proper HTTP/1.1 compliance.
#[allow(clippy::too_many_lines)]
pub async fn run_gateway(
    host: &str,
    port: u16,
    config: Config,
    external_event_tx: Option<tokio::sync::broadcast::Sender<serde_json::Value>>,
) -> Result<()> {
    // ── Security: warn on public bind without tunnel or explicit opt-in ──
    if is_public_bind(host) && config.tunnel.provider == "none" && !config.gateway.allow_public_bind
    {
        tracing::warn!(
            "⚠️  Binding to {host} — gateway will be exposed to all network interfaces.\n\
             Suggestion: use --host 127.0.0.1 (default), configure a tunnel, or set\n\
             [gateway] allow_public_bind = true in config.toml to silence this warning.\n\n\
             Docker/VM: if you are running inside a container or VM, this is expected."
        );
    }
    let config_state = Arc::new(Mutex::new(config.clone()));

    // ── Hooks ──────────────────────────────────────────────────────
    let hooks: Option<std::sync::Arc<crate::hooks::HookRunner>> = if config.hooks.enabled {
        Some(std::sync::Arc::new(crate::hooks::HookRunner::new()))
    } else {
        None
    };

    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual_port = listener.local_addr()?.port();
    let display_addr = format!("{host}:{actual_port}");

    let provider: Arc<dyn Provider> = Arc::from(providers::create_resilient_provider_with_options(
        config.default_provider.as_deref().unwrap_or("openrouter"),
        config.api_key.as_deref(),
        config.api_url.as_deref(),
        &config.reliability,
        &providers::provider_runtime_options_from_config(&config),
    )?);
    let model = config
        .default_model
        .clone()
        .unwrap_or_else(|| "anthropic/claude-sonnet-4".into());
    let temperature = config.default_temperature;
    let mem: Arc<dyn Memory> = Arc::from(memory::create_memory_with_storage_and_routes(
        &config.memory,
        &config.embedding_routes,
        Some(&config.storage.provider.config),
        &config.workspace_dir,
        config.api_key.as_deref(),
    )?);
    let runtime: Arc<dyn runtime::RuntimeAdapter> =
        Arc::from(runtime::create_runtime(&config.runtime)?);
    let security = Arc::new(SecurityPolicy::from_config(
        &config.autonomy,
        &config.workspace_dir,
    ));

    let (composio_key, composio_entity_id) = if config.composio.enabled {
        (
            config.composio.api_key.as_deref(),
            Some(config.composio.entity_id.as_str()),
        )
    } else {
        (None, None)
    };

    let canvas_store = tools::CanvasStore::new();

    let (
        mut tools_registry_raw,
        delegate_handle_gw,
        _reaction_handle_gw,
        _channel_map_handle,
        _ask_user_handle_gw,
        _escalate_handle_gw,
    ) = tools::all_tools_with_runtime(
        Arc::new(config.clone()),
        &security,
        runtime,
        Arc::clone(&mem),
        composio_key,
        composio_entity_id,
        &config.browser,
        &config.http_request,
        &config.web_fetch,
        &config.workspace_dir,
        &config.agents,
        config.api_key.as_deref(),
        &config,
        Some(canvas_store.clone()),
    );

    // ── Wire MCP tools into the gateway tool registry (non-fatal) ───
    // Without this, the `/api/tools` endpoint misses MCP tools.
    if config.mcp.enabled && !config.mcp.servers.is_empty() {
        tracing::info!(
            "Gateway: initializing MCP client — {} server(s) configured",
            config.mcp.servers.len()
        );
        match tools::McpRegistry::connect_all(&config.mcp.servers).await {
            Ok(registry) => {
                let registry = std::sync::Arc::new(registry);
                if config.mcp.deferred_loading {
                    let deferred_set =
                        tools::DeferredMcpToolSet::from_registry(std::sync::Arc::clone(&registry))
                            .await;
                    tracing::info!(
                        "Gateway MCP deferred: {} tool stub(s) from {} server(s)",
                        deferred_set.len(),
                        registry.server_count()
                    );
                    let activated =
                        std::sync::Arc::new(std::sync::Mutex::new(tools::ActivatedToolSet::new()));
                    tools_registry_raw.push(Box::new(tools::ToolSearchTool::new(
                        deferred_set,
                        activated,
                    )));
                } else {
                    let names = registry.tool_names();
                    let mut registered = 0usize;
                    for name in names {
                        if let Some(def) = registry.get_tool_def(&name).await {
                            let wrapper: std::sync::Arc<dyn tools::Tool> =
                                std::sync::Arc::new(tools::McpToolWrapper::new(
                                    name,
                                    def,
                                    std::sync::Arc::clone(&registry),
                                ));
                            if let Some(ref handle) = delegate_handle_gw {
                                handle.write().push(std::sync::Arc::clone(&wrapper));
                            }
                            tools_registry_raw.push(Box::new(tools::ArcToolRef(wrapper)));
                            registered += 1;
                        }
                    }
                    tracing::info!(
                        "Gateway MCP: {} tool(s) registered from {} server(s)",
                        registered,
                        registry.server_count()
                    );
                }
            }
            Err(e) => {
                tracing::error!("Gateway MCP registry failed to initialize: {e:#}");
            }
        }
    }

    let tools_registry: Arc<Vec<ToolSpec>> =
        Arc::new(tools_registry_raw.iter().map(|t| t.spec()).collect());

    // Cost tracker — process-global singleton so channels share the same instance
    let cost_tracker = CostTracker::get_or_init_global(config.cost.clone(), &config.workspace_dir);

    // SSE broadcast channel for real-time events.
    // Use an externally provided sender (e.g. from the daemon) so that other
    // components (cron, heartbeat) can publish events to the same bus.
    let event_tx = external_event_tx.unwrap_or_else(|| {
        let (tx, _rx) = tokio::sync::broadcast::channel::<serde_json::Value>(256);
        tx
    });
    let event_buffer = Arc::new(sse::EventBuffer::new(500));
    // Extract webhook secret for authentication
    let webhook_secret_hash: Option<Arc<str>> =
        config.channels_config.webhook.as_ref().and_then(|webhook| {
            webhook.secret.as_ref().and_then(|raw_secret| {
                let trimmed_secret = raw_secret.trim();
                (!trimmed_secret.is_empty())
                    .then(|| Arc::<str>::from(hash_webhook_secret(trimmed_secret)))
            })
        });

    // WhatsApp channel (if configured)
    let whatsapp_channel: Option<Arc<WhatsAppChannel>> = config
        .channels_config
        .whatsapp
        .as_ref()
        .filter(|wa| wa.is_cloud_config())
        .map(|wa| {
            Arc::new(WhatsAppChannel::new(
                wa.access_token.clone().unwrap_or_default(),
                wa.phone_number_id.clone().unwrap_or_default(),
                wa.verify_token.clone().unwrap_or_default(),
                wa.allowed_numbers.clone(),
            ))
        });

    // WhatsApp app secret for webhook signature verification
    // Priority: environment variable > config file
    let whatsapp_app_secret: Option<Arc<str>> = std::env::var("ZEROCLAW_WHATSAPP_APP_SECRET")
        .ok()
        .and_then(|secret| {
            let secret = secret.trim();
            (!secret.is_empty()).then(|| secret.to_owned())
        })
        .or_else(|| {
            config.channels_config.whatsapp.as_ref().and_then(|wa| {
                wa.app_secret
                    .as_deref()
                    .map(str::trim)
                    .filter(|secret| !secret.is_empty())
                    .map(ToOwned::to_owned)
            })
        })
        .map(Arc::from);

    // Linq channel (if configured)
    let linq_channel: Option<Arc<LinqChannel>> = config.channels_config.linq.as_ref().map(|lq| {
        Arc::new(LinqChannel::new(
            lq.api_token.clone(),
            lq.from_phone.clone(),
            lq.allowed_senders.clone(),
        ))
    });

    // Linq signing secret for webhook signature verification
    // Priority: environment variable > config file
    let linq_signing_secret: Option<Arc<str>> = std::env::var("ZEROCLAW_LINQ_SIGNING_SECRET")
        .ok()
        .and_then(|secret| {
            let secret = secret.trim();
            (!secret.is_empty()).then(|| secret.to_owned())
        })
        .or_else(|| {
            config.channels_config.linq.as_ref().and_then(|lq| {
                lq.signing_secret
                    .as_deref()
                    .map(str::trim)
                    .filter(|secret| !secret.is_empty())
                    .map(ToOwned::to_owned)
            })
        })
        .map(Arc::from);

    // WATI channel (if configured)
    let wati_channel: Option<Arc<WatiChannel>> =
        config.channels_config.wati.as_ref().map(|wati_cfg| {
            Arc::new(
                WatiChannel::new(
                    wati_cfg.api_token.clone(),
                    wati_cfg.api_url.clone(),
                    wati_cfg.tenant_id.clone(),
                    wati_cfg.allowed_numbers.clone(),
                )
                .with_transcription(config.transcription.clone()),
            )
        });

    // Nextcloud Talk channel (if configured)
    let nextcloud_talk_channel: Option<Arc<NextcloudTalkChannel>> =
        config.channels_config.nextcloud_talk.as_ref().map(|nc| {
            Arc::new(NextcloudTalkChannel::new(
                nc.base_url.clone(),
                nc.app_token.clone(),
                nc.bot_name.clone().unwrap_or_default(),
                nc.allowed_users.clone(),
            ))
        });

    // Nextcloud Talk webhook secret for signature verification
    // Priority: environment variable > config file
    let nextcloud_talk_webhook_secret: Option<Arc<str>> =
        std::env::var("ZEROCLAW_NEXTCLOUD_TALK_WEBHOOK_SECRET")
            .ok()
            .and_then(|secret| {
                let secret = secret.trim();
                (!secret.is_empty()).then(|| secret.to_owned())
            })
            .or_else(|| {
                config
                    .channels_config
                    .nextcloud_talk
                    .as_ref()
                    .and_then(|nc| {
                        nc.webhook_secret
                            .as_deref()
                            .map(str::trim)
                            .filter(|secret| !secret.is_empty())
                            .map(ToOwned::to_owned)
                    })
            })
            .map(Arc::from);

    // Gmail Push channel (if configured and enabled)
    let gmail_push_channel: Option<Arc<GmailPushChannel>> = config
        .channels_config
        .gmail_push
        .as_ref()
        .filter(|gp| gp.enabled)
        .map(|gp| Arc::new(GmailPushChannel::new(gp.clone())));

    // ── Session persistence for WS chat ─────────────────────
    let session_backend: Option<Arc<dyn SessionBackend>> = if config.gateway.session_persistence {
        match SqliteSessionBackend::new(&config.workspace_dir) {
            Ok(b) => {
                tracing::info!("Gateway session persistence enabled (SQLite)");
                if config.gateway.session_ttl_hours > 0 {
                    if let Ok(cleaned) = b.cleanup_stale(config.gateway.session_ttl_hours) {
                        if cleaned > 0 {
                            tracing::info!("Cleaned up {cleaned} stale gateway sessions");
                        }
                    }
                }
                Some(Arc::new(b))
            }
            Err(e) => {
                tracing::warn!("Session persistence disabled: {e}");
                None
            }
        }
    } else {
        None
    };

    // ── Pairing guard ──────────────────────────────────────
    let pairing = Arc::new(PairingGuard::new(
        config.gateway.require_pairing,
        &config.gateway.paired_tokens,
    ));
    let rate_limit_max_keys = normalize_max_keys(
        config.gateway.rate_limit_max_keys,
        RATE_LIMIT_MAX_KEYS_DEFAULT,
    );
    let rate_limiter = Arc::new(GatewayRateLimiter::new(
        config.gateway.pair_rate_limit_per_minute,
        config.gateway.webhook_rate_limit_per_minute,
        rate_limit_max_keys,
    ));
    let idempotency_max_keys = normalize_max_keys(
        config.gateway.idempotency_max_keys,
        IDEMPOTENCY_MAX_KEYS_DEFAULT,
    );
    let idempotency_store = Arc::new(IdempotencyStore::new(
        Duration::from_secs(config.gateway.idempotency_ttl_secs.max(1)),
        idempotency_max_keys,
    ));

    // Resolve optional path prefix for reverse-proxy deployments.
    let path_prefix: Option<&str> = config
        .gateway
        .path_prefix
        .as_deref()
        .filter(|p| !p.is_empty());

    // ── Tunnel ────────────────────────────────────────────────
    let tunnel = crate::tunnel::create_tunnel(&config.tunnel)?;
    let mut tunnel_url: Option<String> = None;

    if let Some(ref tun) = tunnel {
        println!("🔗 Starting {} tunnel...", tun.name());
        match tun.start(host, actual_port).await {
            Ok(url) => {
                println!("🌐 Tunnel active: {url}");
                tunnel_url = Some(url);
            }
            Err(e) => {
                println!("⚠️  Tunnel failed to start: {e}");
                println!("   Falling back to local-only mode.");
            }
        }
    }

    let pfx = path_prefix.unwrap_or("");
    println!("🦀 ZeroClaw Gateway listening on http://{display_addr}{pfx}");
    if let Some(ref url) = tunnel_url {
        println!("  🌐 Public URL: {url}");
    }
    println!("  🌐 Web Dashboard: http://{display_addr}{pfx}/");
    if let Some(code) = pairing.pairing_code() {
        println!();
        println!("  🔐 PAIRING REQUIRED — use this one-time code:");
        println!("     ┌──────────────┐");
        println!("     │  {code}  │");
        println!("     └──────────────┘");
        println!("     Send: POST {pfx}/pair with header X-Pairing-Code: {code}");
    } else if pairing.require_pairing() {
        println!("  🔒 Pairing: ACTIVE (bearer token required)");
        println!("     To pair a new device: zeroclaw gateway get-paircode --new");
        println!();
    } else {
        println!("  ⚠️  Pairing: DISABLED (all requests accepted)");
        println!();
    }
    println!("  POST {pfx}/pair      — pair a new client (X-Pairing-Code header)");
    println!("  POST {pfx}/webhook   — {{\"message\": \"your prompt\"}}");
    if whatsapp_channel.is_some() {
        println!("  GET  {pfx}/whatsapp  — Meta webhook verification");
        println!("  POST {pfx}/whatsapp  — WhatsApp message webhook");
    }
    if linq_channel.is_some() {
        println!("  POST {pfx}/linq      — Linq message webhook (iMessage/RCS/SMS)");
    }
    if wati_channel.is_some() {
        println!("  GET  {pfx}/wati      — WATI webhook verification");
        println!("  POST {pfx}/wati      — WATI message webhook");
    }
    if nextcloud_talk_channel.is_some() {
        println!("  POST {pfx}/nextcloud-talk — Nextcloud Talk bot webhook");
    }
    if config.linear.webhook_enabled {
        println!("  POST {pfx}/linear    — Linear webhook (signed event ingestion)");
    }
    if config.bluedot.webhook_enabled {
        println!("  POST {pfx}/bluedot   — Bluedot webhook (Svix-signed meeting ingestion)");
    }
    println!("  GET  {pfx}/api/*     — REST API (bearer token required)");
    println!("  GET  {pfx}/ws/chat   — WebSocket agent chat");
    if config.nodes.enabled {
        println!("  GET  {pfx}/ws/nodes  — WebSocket node discovery");
    }
    println!("  GET  {pfx}/health    — health check");
    println!("  GET  {pfx}/metrics   — Prometheus metrics");
    println!("  Press Ctrl+C to stop.\n");

    crate::health::mark_component_ok("gateway");

    // Fire gateway start hook
    if let Some(ref hooks) = hooks {
        hooks.fire_gateway_start(host, actual_port).await;
    }

    // Wrap observer with broadcast capability for SSE
    let broadcast_observer: Arc<dyn crate::observability::Observer> =
        Arc::new(sse::BroadcastObserver::new(
            crate::observability::create_observer(&config.observability),
            event_tx.clone(),
            event_buffer.clone(),
        ));

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Node registry for dynamic node discovery
    let node_registry = Arc::new(nodes::NodeRegistry::new(config.nodes.max_nodes));

    // Device registry and pairing store (only when pairing is required)
    let device_registry = if config.gateway.require_pairing {
        Some(Arc::new(api_pairing::DeviceRegistry::new(
            &config.workspace_dir,
        )))
    } else {
        None
    };
    let pending_pairings = if config.gateway.require_pairing {
        Some(Arc::new(api_pairing::PairingStore::new(
            config.gateway.pairing_dashboard.max_pending_codes,
        )))
    } else {
        None
    };

    let state = AppState {
        config: config_state,
        provider,
        model,
        temperature,
        mem,
        auto_save: config.memory.auto_save,
        webhook_secret_hash,
        pairing,
        trust_forwarded_headers: config.gateway.trust_forwarded_headers,
        rate_limiter,
        auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
        idempotency_store,
        whatsapp: whatsapp_channel,
        whatsapp_app_secret,
        linq: linq_channel,
        linq_signing_secret,
        nextcloud_talk: nextcloud_talk_channel,
        nextcloud_talk_webhook_secret,
        wati: wati_channel,
        gmail_push: gmail_push_channel,
        observer: broadcast_observer,
        tools_registry,
        cost_tracker,
        event_tx,
        event_buffer,
        shutdown_tx,
        node_registry,
        session_backend,
        session_queue: Arc::new(session_queue::SessionActorQueue::new(8, 30, 600)),
        device_registry,
        pending_pairings,
        path_prefix: path_prefix.unwrap_or("").to_string(),
        canvas_store,
        webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        #[cfg(feature = "webauthn")]
        webauthn: if config.security.webauthn.enabled {
            let secret_store = Arc::new(crate::security::SecretStore::new(
                &config.workspace_dir,
                true,
            ));
            let wa_config = crate::security::webauthn::WebAuthnConfig {
                enabled: true,
                rp_id: config.security.webauthn.rp_id.clone(),
                rp_origin: config.security.webauthn.rp_origin.clone(),
                rp_name: config.security.webauthn.rp_name.clone(),
            };
            Some(Arc::new(api_webauthn::WebAuthnState {
                manager: crate::security::webauthn::WebAuthnManager::new(
                    wa_config,
                    secret_store,
                    &config.workspace_dir,
                ),
                pending_registrations: parking_lot::Mutex::new(std::collections::HashMap::new()),
                pending_authentications: parking_lot::Mutex::new(std::collections::HashMap::new()),
            }))
        } else {
            None
        },
    };

    // Config PUT needs larger body limit (1MB)
    let config_put_router = Router::new()
        .route("/api/config", put(api::handle_api_config_put))
        .layer(RequestBodyLimitLayer::new(1_048_576));

    // Build router with middleware
    let inner = Router::new()
        // ── Admin routes (for CLI management) ──
        .route("/admin/shutdown", post(handle_admin_shutdown))
        .route("/admin/paircode", get(handle_admin_paircode))
        .route("/admin/paircode/new", post(handle_admin_paircode_new))
        // ── Existing routes ──
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .route("/pair", post(handle_pair))
        .route("/pair/code", get(handle_pair_code))
        .route("/webhook", post(handle_webhook))
        .route("/whatsapp", get(handle_whatsapp_verify))
        .route("/whatsapp", post(handle_whatsapp_message))
        .route("/linq", post(handle_linq_webhook))
        .route("/wati", get(handle_wati_verify))
        .route("/wati", post(handle_wati_webhook))
        .route("/nextcloud-talk", post(handle_nextcloud_talk_webhook))
        .route("/linear", post(handle_linear_webhook))
        .route("/bluedot", post(handle_bluedot_webhook))
        .route("/webhook/gmail", post(handle_gmail_push_webhook))
        // ── Claude Code runner hooks ──
        .route("/hooks/claude-code", post(api::handle_claude_code_hook))
        // ── Web Dashboard API routes ──
        .route("/api/status", get(api::handle_api_status))
        .route("/api/config", get(api::handle_api_config_get))
        .route("/api/tools", get(api::handle_api_tools))
        .route("/api/cron", get(api::handle_api_cron_list))
        .route("/api/cron", post(api::handle_api_cron_add))
        .route(
            "/api/cron/settings",
            get(api::handle_api_cron_settings_get).patch(api::handle_api_cron_settings_patch),
        )
        .route(
            "/api/cron/{id}",
            delete(api::handle_api_cron_delete).patch(api::handle_api_cron_patch),
        )
        .route("/api/cron/{id}/runs", get(api::handle_api_cron_runs))
        .route("/api/integrations", get(api::handle_api_integrations))
        .route(
            "/api/integrations/settings",
            get(api::handle_api_integrations_settings),
        )
        .route(
            "/api/doctor",
            get(api::handle_api_doctor).post(api::handle_api_doctor),
        )
        .route("/api/memory", get(api::handle_api_memory_list))
        .route("/api/memory", post(api::handle_api_memory_store))
        .route("/api/memory/{key}", delete(api::handle_api_memory_delete))
        .route("/api/cost", get(api::handle_api_cost))
        .route("/api/cli-tools", get(api::handle_api_cli_tools))
        .route("/api/health", get(api::handle_api_health))
        .route("/api/sessions", get(api::handle_api_sessions_list))
        .route("/api/sessions/running", get(api::handle_api_sessions_running))
        .route(
            "/api/sessions/{id}/messages",
            get(api::handle_api_session_messages),
        )
        .route("/api/sessions/{id}", delete(api::handle_api_session_delete).put(api::handle_api_session_rename))
        .route("/api/sessions/{id}/state", get(api::handle_api_session_state))
        // ── Pairing + Device management API ──
        .route("/api/pairing/initiate", post(api_pairing::initiate_pairing))
        .route("/api/pair", post(api_pairing::submit_pairing_enhanced))
        .route("/api/devices", get(api_pairing::list_devices))
        .route("/api/devices/{id}", delete(api_pairing::revoke_device))
        .route(
            "/api/devices/{id}/token/rotate",
            post(api_pairing::rotate_token),
        )
        // ── Live Canvas (A2UI) routes ──
        .route("/api/canvas", get(canvas::handle_canvas_list))
        .route(
            "/api/canvas/{id}",
            get(canvas::handle_canvas_get)
                .post(canvas::handle_canvas_post)
                .delete(canvas::handle_canvas_clear),
        )
        .route(
            "/api/canvas/{id}/history",
            get(canvas::handle_canvas_history),
        );

    // ── WebAuthn hardware key authentication API (requires webauthn feature) ──
    #[cfg(feature = "webauthn")]
    let inner = inner
        .route(
            "/api/webauthn/register/start",
            post(api_webauthn::handle_register_start),
        )
        .route(
            "/api/webauthn/register/finish",
            post(api_webauthn::handle_register_finish),
        )
        .route(
            "/api/webauthn/auth/start",
            post(api_webauthn::handle_auth_start),
        )
        .route(
            "/api/webauthn/auth/finish",
            post(api_webauthn::handle_auth_finish),
        )
        .route(
            "/api/webauthn/credentials",
            get(api_webauthn::handle_list_credentials),
        )
        .route(
            "/api/webauthn/credentials/{id}",
            delete(api_webauthn::handle_delete_credential),
        );

    // ── Plugin management API (requires plugins-wasm feature) ──
    #[cfg(feature = "plugins-wasm")]
    let inner = inner.route(
        "/api/plugins",
        get(api_plugins::plugin_routes::list_plugins),
    );

    let inner = inner
        // ── SSE event stream ──
        .route("/api/events", get(sse::handle_sse_events))
        .route("/api/events/history", get(sse::handle_events_history))
        // ── WebSocket agent chat ──
        .route("/ws/chat", get(ws::handle_ws_chat))
        // ── WebSocket canvas updates ──
        .route("/ws/canvas/{id}", get(canvas::handle_ws_canvas))
        // ── WebSocket node discovery ──
        .route("/ws/nodes", get(nodes::handle_ws_nodes))
        // ── Static assets (web dashboard) ──
        .route("/_app/{*path}", get(static_files::handle_static))
        // ── Config PUT with larger body limit ──
        .merge(config_put_router)
        // ── SPA fallback: non-API GET requests serve index.html ──
        .fallback(get(static_files::handle_spa_fallback))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(gateway_request_timeout_secs()),
        ));

    // Nest under path prefix when configured (axum strips prefix before routing).
    // nest() at "/prefix" handles both "/prefix" and "/prefix/*" but not "/prefix/"
    // with a trailing slash, so we add a fallback redirect for that case.
    let app = if let Some(prefix) = path_prefix {
        let redirect_target = prefix.to_string();
        Router::new().nest(prefix, inner).route(
            &format!("{prefix}/"),
            get(|| async move { axum::response::Redirect::permanent(&redirect_target) }),
        )
    } else {
        inner
    };

    // ── TLS / mTLS setup ───────────────────────────────────────────
    let tls_acceptor = match &config.gateway.tls {
        Some(tls_cfg) if tls_cfg.enabled => {
            let has_mtls = tls_cfg.client_auth.as_ref().is_some_and(|ca| ca.enabled);
            if has_mtls {
                tracing::info!("TLS enabled with mutual TLS (mTLS) client verification");
            } else {
                tracing::info!("TLS enabled (no client certificate requirement)");
            }
            Some(tls::build_tls_acceptor(tls_cfg)?)
        }
        _ => None,
    };

    if let Some(tls_acceptor) = tls_acceptor {
        // Manual TLS accept loop — serves each connection via hyper.
        let app = app.into_make_service_with_connect_info::<SocketAddr>();
        let mut app = app;

        let mut shutdown_signal = shutdown_rx;
        loop {
            tokio::select! {
                conn = listener.accept() => {
                    let (tcp_stream, remote_addr) = conn?;
                    let tls_acceptor = tls_acceptor.clone();
                    let svc = tower::MakeService::<
                        SocketAddr,
                        hyper::Request<hyper::body::Incoming>,
                    >::make_service(&mut app, remote_addr)
                    .await
                    .expect("infallible make_service");

                    tokio::spawn(async move {
                        let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::debug!("TLS handshake failed from {remote_addr}: {e}");
                                return;
                            }
                        };
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        let hyper_svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let mut svc = svc.clone();
                            async move {
                                tower::Service::call(&mut svc, req).await
                            }
                        });
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, hyper_svc)
                        .await
                        {
                            tracing::debug!("connection error from {remote_addr}: {e}");
                        }
                    });
                }
                _ = shutdown_signal.changed() => {
                    tracing::info!("🦀 ZeroClaw Gateway shutting down...");
                    break;
                }
            }
        }
    } else {
        // Plain TCP — use axum's built-in serve.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
            tracing::info!("🦀 ZeroClaw Gateway shutting down...");
        })
        .await?;
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// AXUM HANDLERS
// ══════════════════════════════════════════════════════════════════════════════

/// GET /health — always public (no secrets leaked)
async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let body = serde_json::json!({
        "status": "ok",
        "paired": state.pairing.is_paired(),
        "require_pairing": state.pairing.require_pairing(),
        "runtime": crate::health::snapshot_json(),
    });
    Json(body)
}

/// Prometheus content type for text exposition format.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

fn prometheus_disabled_hint() -> String {
    String::from(
        "# Prometheus backend not enabled. Set [observability] backend = \"prometheus\" in config.\n",
    )
}

#[cfg(feature = "observability-prometheus")]
fn prometheus_observer_from_state(
    observer: &dyn crate::observability::Observer,
) -> Option<&crate::observability::PrometheusObserver> {
    observer
        .as_any()
        .downcast_ref::<crate::observability::PrometheusObserver>()
        .or_else(|| {
            observer
                .as_any()
                .downcast_ref::<sse::BroadcastObserver>()
                .and_then(|broadcast| {
                    broadcast
                        .inner()
                        .as_any()
                        .downcast_ref::<crate::observability::PrometheusObserver>()
                })
        })
}

/// GET /metrics — Prometheus text exposition format
async fn handle_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = {
        #[cfg(feature = "observability-prometheus")]
        {
            if let Some(prom) = prometheus_observer_from_state(state.observer.as_ref()) {
                prom.encode()
            } else {
                prometheus_disabled_hint()
            }
        }
        #[cfg(not(feature = "observability-prometheus"))]
        {
            let _ = &state;
            prometheus_disabled_hint()
        }
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        body,
    )
}

/// POST /pair — exchange one-time code for bearer token
#[axum::debug_handler]
async fn handle_pair(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let rate_key =
        client_key_from_request(Some(peer_addr), &headers, state.trust_forwarded_headers);
    if !state.rate_limiter.allow_pair(&rate_key) {
        tracing::warn!("/pair rate limit exceeded");
        let err = serde_json::json!({
            "error": "Too many pairing requests. Please retry later.",
            "retry_after": RATE_LIMIT_WINDOW_SECS,
        });
        return (StatusCode::TOO_MANY_REQUESTS, Json(err));
    }

    // ── Auth rate limiting (brute-force protection) ──
    if let Err(e) = state.auth_limiter.check_rate_limit(&rate_key) {
        tracing::warn!("🔐 Pairing auth rate limit exceeded for {rate_key}");
        let err = serde_json::json!({
            "error": format!("Too many auth attempts. Try again in {}s.", e.retry_after_secs),
            "retry_after": e.retry_after_secs,
        });
        return (StatusCode::TOO_MANY_REQUESTS, Json(err));
    }

    let code = headers
        .get("X-Pairing-Code")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    match state.pairing.try_pair(code, &rate_key).await {
        Ok(Some(token)) => {
            tracing::info!("🔐 New client paired successfully");
            if let Err(err) =
                Box::pin(persist_pairing_tokens(state.config.clone(), &state.pairing)).await
            {
                tracing::error!("🔐 Pairing succeeded but token persistence failed: {err:#}");
                let body = serde_json::json!({
                    "paired": true,
                    "persisted": false,
                    "token": token,
                    "message": "Paired for this process, but failed to persist token to config.toml. Check config path and write permissions.",
                });
                return (StatusCode::OK, Json(body));
            }

            let body = serde_json::json!({
                "paired": true,
                "persisted": true,
                "token": token,
                "message": "Save this token — use it as Authorization: Bearer <token>"
            });
            (StatusCode::OK, Json(body))
        }
        Ok(None) => {
            state.auth_limiter.record_attempt(&rate_key);
            tracing::warn!("🔐 Pairing attempt with invalid code");
            let err = serde_json::json!({"error": "Invalid pairing code"});
            (StatusCode::FORBIDDEN, Json(err))
        }
        Err(lockout_secs) => {
            tracing::warn!(
                "🔐 Pairing locked out — too many failed attempts ({lockout_secs}s remaining)"
            );
            let err = serde_json::json!({
                "error": format!("Too many failed attempts. Try again in {lockout_secs}s."),
                "retry_after": lockout_secs
            });
            (StatusCode::TOO_MANY_REQUESTS, Json(err))
        }
    }
}

async fn persist_pairing_tokens(config: Arc<Mutex<Config>>, pairing: &PairingGuard) -> Result<()> {
    let paired_tokens = pairing.tokens();
    // This is needed because parking_lot's guard is not Send so we clone the inner
    // this should be removed once async mutexes are used everywhere
    let mut updated_cfg = { config.lock().clone() };
    updated_cfg.gateway.paired_tokens = paired_tokens;
    updated_cfg
        .save()
        .await
        .context("Failed to persist paired tokens to config.toml")?;

    // Keep shared runtime config in sync with persisted tokens.
    *config.lock() = updated_cfg;
    Ok(())
}

/// Simple chat for webhook endpoint (no tools, for backward compatibility and testing).
async fn run_gateway_chat_simple(state: &AppState, message: &str) -> anyhow::Result<String> {
    let user_messages = vec![ChatMessage::user(message)];

    // Keep webhook/gateway prompts aligned with channel behavior by injecting
    // workspace-aware system context before model invocation.
    let system_prompt = {
        let config_guard = state.config.lock();
        crate::channels::build_system_prompt(
            &config_guard.workspace_dir,
            &state.model,
            &[], // tools - empty for simple chat
            &[], // skills
            Some(&config_guard.identity),
            None, // bootstrap_max_chars - use default
        )
    };

    let mut messages = Vec::with_capacity(1 + user_messages.len());
    messages.push(ChatMessage::system(system_prompt));
    messages.extend(user_messages);

    let multimodal_config = state.config.lock().multimodal.clone();
    let prepared =
        crate::multimodal::prepare_messages_for_provider(&messages, &multimodal_config).await?;

    state
        .provider
        .chat_with_history(&prepared.messages, &state.model, state.temperature)
        .await
}

/// Full-featured chat with tools for channel handlers (WhatsApp, Linq, Nextcloud Talk).
async fn run_gateway_chat_with_tools(
    state: &AppState,
    message: &str,
    session_id: Option<&str>,
) -> anyhow::Result<String> {
    let config = state.config.lock().clone();
    Box::pin(crate::agent::process_message(config, message, session_id)).await
}

async fn run_gateway_named_agent(
    state: &AppState,
    agent_name: &str,
    message: &str,
) -> anyhow::Result<String> {
    let config = state.config.lock().clone();
    let security = Arc::new(SecurityPolicy::from_config(
        &config.autonomy,
        &config.workspace_dir,
    ));
    let runtime: Arc<dyn runtime::RuntimeAdapter> =
        Arc::from(runtime::create_runtime(&config.runtime)?);
    let (composio_key, composio_entity_id) = if config.composio.enabled {
        (
            config.composio.api_key.as_deref(),
            Some(config.composio.entity_id.as_str()),
        )
    } else {
        (None, None)
    };
    let config_arc = Arc::new(config.clone());
    let resolved_agents = config.resolve_delegate_agents_map(&config.agents)?;
    let (_, delegate_handle, _, _, _, _) = tools::all_tools_with_runtime(
        Arc::clone(&config_arc),
        &security,
        runtime,
        state.mem.clone(),
        composio_key,
        composio_entity_id,
        &config.browser,
        &config.http_request,
        &config.web_fetch,
        &config.workspace_dir,
        &resolved_agents,
        config.api_key.as_deref(),
        &config,
        Some(state.canvas_store.clone()),
    );
    let parent_tools = delegate_handle
        .with_context(|| format!("No delegate agent registry is available for '{agent_name}'"))?;
    let fallback_credential = config.api_key.as_deref().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    });
    let provider_runtime_options = providers::provider_runtime_options_from_config(&config);
    let delegate_tool = tools::DelegateTool::new_with_options(
        resolved_agents,
        fallback_credential,
        security,
        provider_runtime_options,
    )
    .with_parent_tools(parent_tools)
    .with_multimodal_config(config.multimodal.clone())
    .with_delegate_config(config.delegate.clone())
    .with_workspace_dir(config.workspace_dir.clone())
    .with_memory(state.mem.clone());

    let result = delegate_tool
        .execute(serde_json::json!({
            "agent": agent_name,
            "prompt": message,
        }))
        .await?;

    if result.success {
        Ok(result.output)
    } else {
        anyhow::bail!(
            "{}",
            result
                .error
                .unwrap_or_else(|| format!("Named agent '{agent_name}' failed"))
        );
    }
}

/// Webhook request body
#[derive(serde::Deserialize)]
pub struct WebhookBody {
    pub message: String,
}

/// POST /webhook — main webhook endpoint
async fn handle_webhook(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<WebhookBody>, axum::extract::rejection::JsonRejection>,
) -> impl IntoResponse {
    let rate_key =
        client_key_from_request(Some(peer_addr), &headers, state.trust_forwarded_headers);
    if !state.rate_limiter.allow_webhook(&rate_key) {
        tracing::warn!("/webhook rate limit exceeded");
        let err = serde_json::json!({
            "error": "Too many webhook requests. Please retry later.",
            "retry_after": RATE_LIMIT_WINDOW_SECS,
        });
        return (StatusCode::TOO_MANY_REQUESTS, Json(err));
    }

    // ── Bearer token auth (pairing) with auth rate limiting ──
    if state.pairing.require_pairing() {
        if let Err(e) = state.auth_limiter.check_rate_limit(&rate_key) {
            tracing::warn!("Webhook: auth rate limit exceeded for {rate_key}");
            let err = serde_json::json!({
                "error": format!("Too many auth attempts. Try again in {}s.", e.retry_after_secs),
                "retry_after": e.retry_after_secs,
            });
            return (StatusCode::TOO_MANY_REQUESTS, Json(err));
        }
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = auth.strip_prefix("Bearer ").unwrap_or("");
        if !state.pairing.is_authenticated(token) {
            state.auth_limiter.record_attempt(&rate_key);
            tracing::warn!("Webhook: rejected — not paired / invalid bearer token");
            let err = serde_json::json!({
                "error": "Unauthorized — pair first via POST /pair, then send Authorization: Bearer <token>"
            });
            return (StatusCode::UNAUTHORIZED, Json(err));
        }
    }

    // ── Webhook secret auth (optional, additional layer) ──
    if let Some(ref secret_hash) = state.webhook_secret_hash {
        let header_hash = headers
            .get("X-Webhook-Secret")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(hash_webhook_secret);
        match header_hash {
            Some(val) if constant_time_eq(&val, secret_hash.as_ref()) => {}
            _ => {
                tracing::warn!("Webhook: rejected request — invalid or missing X-Webhook-Secret");
                let err = serde_json::json!({"error": "Unauthorized — invalid or missing X-Webhook-Secret header"});
                return (StatusCode::UNAUTHORIZED, Json(err));
            }
        }
    }

    // ── Parse body ──
    let Json(webhook_body) = match body {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("Webhook JSON parse error: {e}");
            let err = serde_json::json!({
                "error": "Invalid JSON body. Expected: {\"message\": \"...\"}"
            });
            return (StatusCode::BAD_REQUEST, Json(err));
        }
    };

    // ── Idempotency (optional) ──
    if let Some(idempotency_key) = headers
        .get("X-Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !state.idempotency_store.record_if_new(idempotency_key) {
            tracing::info!("Webhook duplicate ignored (idempotency key: {idempotency_key})");
            let body = serde_json::json!({
                "status": "duplicate",
                "idempotent": true,
                "message": "Request already processed for this idempotency key"
            });
            return (StatusCode::OK, Json(body));
        }
    }

    let message = &webhook_body.message;
    let session_id = webhook_session_id(&headers);

    if state.auto_save && !memory::should_skip_autosave_content(message) {
        let key = webhook_memory_key();
        let _ = state
            .mem
            .store(
                &key,
                message,
                MemoryCategory::Conversation,
                session_id.as_deref(),
            )
            .await;
    }

    let provider_label = state
        .config
        .lock()
        .default_provider
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let model_label = state.model.clone();
    let started_at = Instant::now();

    state
        .observer
        .record_event(&crate::observability::ObserverEvent::AgentStart {
            provider: provider_label.clone(),
            model: model_label.clone(),
        });
    state
        .observer
        .record_event(&crate::observability::ObserverEvent::LlmRequest {
            provider: provider_label.clone(),
            model: model_label.clone(),
            messages_count: 1,
        });

    match run_gateway_chat_simple(&state, message).await {
        Ok(response) => {
            let duration = started_at.elapsed();
            state
                .observer
                .record_event(&crate::observability::ObserverEvent::LlmResponse {
                    provider: provider_label.clone(),
                    model: model_label.clone(),
                    duration,
                    success: true,
                    error_message: None,
                    input_tokens: None,
                    output_tokens: None,
                });
            state.observer.record_metric(
                &crate::observability::traits::ObserverMetric::RequestLatency(duration),
            );
            state
                .observer
                .record_event(&crate::observability::ObserverEvent::AgentEnd {
                    provider: provider_label,
                    model: model_label,
                    duration,
                    tokens_used: None,
                    cost_usd: None,
                });

            let body = serde_json::json!({"response": response, "model": state.model});
            (StatusCode::OK, Json(body))
        }
        Err(e) => {
            let duration = started_at.elapsed();
            let sanitized = providers::sanitize_api_error(&e.to_string());

            state
                .observer
                .record_event(&crate::observability::ObserverEvent::LlmResponse {
                    provider: provider_label.clone(),
                    model: model_label.clone(),
                    duration,
                    success: false,
                    error_message: Some(sanitized.clone()),
                    input_tokens: None,
                    output_tokens: None,
                });
            state.observer.record_metric(
                &crate::observability::traits::ObserverMetric::RequestLatency(duration),
            );
            state
                .observer
                .record_event(&crate::observability::ObserverEvent::Error {
                    component: "gateway".to_string(),
                    message: sanitized.clone(),
                });
            state
                .observer
                .record_event(&crate::observability::ObserverEvent::AgentEnd {
                    provider: provider_label,
                    model: model_label,
                    duration,
                    tokens_used: None,
                    cost_usd: None,
                });

            tracing::error!("Webhook provider error: {}", sanitized);
            let err = serde_json::json!({"error": "LLM request failed"});
            (StatusCode::INTERNAL_SERVER_ERROR, Json(err))
        }
    }
}

/// `WhatsApp` verification query params
#[derive(serde::Deserialize)]
pub struct WhatsAppVerifyQuery {
    #[serde(rename = "hub.mode")]
    pub mode: Option<String>,
    #[serde(rename = "hub.verify_token")]
    pub verify_token: Option<String>,
    #[serde(rename = "hub.challenge")]
    pub challenge: Option<String>,
}

/// GET /whatsapp — Meta webhook verification
async fn handle_whatsapp_verify(
    State(state): State<AppState>,
    Query(params): Query<WhatsAppVerifyQuery>,
) -> impl IntoResponse {
    let Some(ref wa) = state.whatsapp else {
        return (StatusCode::NOT_FOUND, "WhatsApp not configured".to_string());
    };

    // Verify the token matches (constant-time comparison to prevent timing attacks)
    let token_matches = params
        .verify_token
        .as_deref()
        .is_some_and(|t| constant_time_eq(t, wa.verify_token()));
    if params.mode.as_deref() == Some("subscribe") && token_matches {
        if let Some(ch) = params.challenge {
            tracing::info!("WhatsApp webhook verified successfully");
            return (StatusCode::OK, ch);
        }
        return (StatusCode::BAD_REQUEST, "Missing hub.challenge".to_string());
    }

    tracing::warn!("WhatsApp webhook verification failed — token mismatch");
    (StatusCode::FORBIDDEN, "Forbidden".to_string())
}

/// Verify `WhatsApp` webhook signature (`X-Hub-Signature-256`).
/// Returns true if the signature is valid, false otherwise.
/// See: <https://developers.facebook.com/docs/graph-api/webhooks/getting-started#verification-requests>
pub fn verify_whatsapp_signature(app_secret: &str, body: &[u8], signature_header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Signature format: "sha256=<hex_signature>"
    let Some(hex_sig) = signature_header.strip_prefix("sha256=") else {
        return false;
    };

    // Decode hex signature
    let Ok(expected) = hex::decode(hex_sig) else {
        return false;
    };

    // Compute HMAC-SHA256
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()) else {
        return false;
    };
    mac.update(body);

    // Constant-time comparison
    mac.verify_slice(&expected).is_ok()
}

/// POST /whatsapp — incoming message webhook
async fn handle_whatsapp_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(ref wa) = state.whatsapp else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "WhatsApp not configured"})),
        );
    };

    // ── Security: Verify X-Hub-Signature-256 if app_secret is configured ──
    if let Some(ref app_secret) = state.whatsapp_app_secret {
        let signature = headers
            .get("X-Hub-Signature-256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !verify_whatsapp_signature(app_secret, &body, signature) {
            tracing::warn!(
                "WhatsApp webhook signature verification failed (signature: {})",
                if signature.is_empty() {
                    "missing"
                } else {
                    "invalid"
                }
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid signature"})),
            );
        }
    }

    // Parse JSON body
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid JSON payload"})),
        );
    };

    // Parse messages from the webhook payload
    let messages = wa.parse_webhook_payload(&payload);

    if messages.is_empty() {
        // Acknowledge the webhook even if no messages (could be status updates)
        return (StatusCode::OK, Json(serde_json::json!({"status": "ok"})));
    }

    // Process each message
    for msg in &messages {
        tracing::info!(
            "WhatsApp message from {}: {}",
            msg.sender,
            truncate_with_ellipsis(&msg.content, 50)
        );
        let session_id = sender_session_id("whatsapp", msg);

        // Auto-save to memory
        if state.auto_save && !memory::should_skip_autosave_content(&msg.content) {
            let key = whatsapp_memory_key(msg);
            let _ = state
                .mem
                .store(
                    &key,
                    &msg.content,
                    MemoryCategory::Conversation,
                    Some(&session_id),
                )
                .await;
        }

        match Box::pin(run_gateway_chat_with_tools(
            &state,
            &msg.content,
            Some(&session_id),
        ))
        .await
        {
            Ok(response) => {
                // Send reply via WhatsApp
                if let Err(e) = wa
                    .send(&SendMessage::new(response, &msg.reply_target))
                    .await
                {
                    tracing::error!("Failed to send WhatsApp reply: {e}");
                }
            }
            Err(e) => {
                tracing::error!("LLM error for WhatsApp message: {e:#}");
                let _ = wa
                    .send(&SendMessage::new(
                        "Sorry, I couldn't process your message right now.",
                        &msg.reply_target,
                    ))
                    .await;
            }
        }
    }

    // Acknowledge the webhook
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// POST /linq — incoming message webhook (iMessage/RCS/SMS via Linq)
async fn handle_linq_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(ref linq) = state.linq else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Linq not configured"})),
        );
    };

    let body_str = String::from_utf8_lossy(&body);

    // ── Security: Verify X-Webhook-Signature if signing_secret is configured ──
    if let Some(ref signing_secret) = state.linq_signing_secret {
        let timestamp = headers
            .get("X-Webhook-Timestamp")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let signature = headers
            .get("X-Webhook-Signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !crate::channels::linq::verify_linq_signature(
            signing_secret,
            &body_str,
            timestamp,
            signature,
        ) {
            tracing::warn!(
                "Linq webhook signature verification failed (signature: {})",
                if signature.is_empty() {
                    "missing"
                } else {
                    "invalid"
                }
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid signature"})),
            );
        }
    }

    // Parse JSON body
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid JSON payload"})),
        );
    };

    // Parse messages from the webhook payload
    let messages = linq.parse_webhook_payload(&payload);

    if messages.is_empty() {
        // Acknowledge the webhook even if no messages (could be status/delivery events)
        return (StatusCode::OK, Json(serde_json::json!({"status": "ok"})));
    }

    // Process each message
    for msg in &messages {
        tracing::info!(
            "Linq message from {}: {}",
            msg.sender,
            truncate_with_ellipsis(&msg.content, 50)
        );
        let session_id = sender_session_id("linq", msg);

        // Auto-save to memory
        if state.auto_save && !memory::should_skip_autosave_content(&msg.content) {
            let key = linq_memory_key(msg);
            let _ = state
                .mem
                .store(
                    &key,
                    &msg.content,
                    MemoryCategory::Conversation,
                    Some(&session_id),
                )
                .await;
        }

        // Call the LLM
        match Box::pin(run_gateway_chat_with_tools(
            &state,
            &msg.content,
            Some(&session_id),
        ))
        .await
        {
            Ok(response) => {
                // Send reply via Linq
                if let Err(e) = linq
                    .send(&SendMessage::new(response, &msg.reply_target))
                    .await
                {
                    tracing::error!("Failed to send Linq reply: {e}");
                }
            }
            Err(e) => {
                tracing::error!("LLM error for Linq message: {e:#}");
                let _ = linq
                    .send(&SendMessage::new(
                        "Sorry, I couldn't process your message right now.",
                        &msg.reply_target,
                    ))
                    .await;
            }
        }
    }

    // Acknowledge the webhook
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// GET /wati — WATI webhook verification (echoes hub.challenge)
async fn handle_wati_verify(
    State(state): State<AppState>,
    Query(params): Query<WatiVerifyQuery>,
) -> impl IntoResponse {
    if state.wati.is_none() {
        return (StatusCode::NOT_FOUND, "WATI not configured".to_string());
    }

    // WATI may use Meta-style webhook verification; echo the challenge
    if let Some(challenge) = params.challenge {
        tracing::info!("WATI webhook verified successfully");
        return (StatusCode::OK, challenge);
    }

    (StatusCode::BAD_REQUEST, "Missing hub.challenge".to_string())
}

#[derive(Debug, serde::Deserialize)]
pub struct WatiVerifyQuery {
    #[serde(rename = "hub.challenge")]
    pub challenge: Option<String>,
}

/// POST /wati — incoming WATI WhatsApp message webhook
async fn handle_wati_webhook(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let Some(ref wati) = state.wati else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "WATI not configured"})),
        );
    };

    // Parse JSON body
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid JSON payload"})),
        );
    };

    // Detect audio before the synchronous parse
    let msg_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let messages = if matches!(msg_type, "audio" | "voice") {
        // Build a synthetic ChannelMessage from the audio transcript
        if let Some(transcript) = wati.try_transcribe_audio(&payload).await {
            wati.parse_audio_as_message(&payload, transcript)
        } else {
            vec![]
        }
    } else {
        wati.parse_webhook_payload(&payload)
    };

    if messages.is_empty() {
        return (StatusCode::OK, Json(serde_json::json!({"status": "ok"})));
    }

    // Process each message
    for msg in &messages {
        tracing::info!(
            "WATI message from {}: {}",
            msg.sender,
            truncate_with_ellipsis(&msg.content, 50)
        );
        let session_id = sender_session_id("wati", msg);

        // Auto-save to memory
        if state.auto_save && !memory::should_skip_autosave_content(&msg.content) {
            let key = wati_memory_key(msg);
            let _ = state
                .mem
                .store(
                    &key,
                    &msg.content,
                    MemoryCategory::Conversation,
                    Some(&session_id),
                )
                .await;
        }

        // Call the LLM
        match Box::pin(run_gateway_chat_with_tools(
            &state,
            &msg.content,
            Some(&session_id),
        ))
        .await
        {
            Ok(response) => {
                // Send reply via WATI
                if let Err(e) = wati
                    .send(&SendMessage::new(response, &msg.reply_target))
                    .await
                {
                    tracing::error!("Failed to send WATI reply: {e}");
                }
            }
            Err(e) => {
                tracing::error!("LLM error for WATI message: {e:#}");
                let _ = wati
                    .send(&SendMessage::new(
                        "Sorry, I couldn't process your message right now.",
                        &msg.reply_target,
                    ))
                    .await;
            }
        }
    }

    // Acknowledge the webhook
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// POST /nextcloud-talk — incoming message webhook (Nextcloud Talk bot API)
async fn handle_nextcloud_talk_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(ref nextcloud_talk) = state.nextcloud_talk else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Nextcloud Talk not configured"})),
        );
    };

    let body_str = String::from_utf8_lossy(&body);

    // ── Security: Verify Nextcloud Talk HMAC signature if secret is configured ──
    if let Some(ref webhook_secret) = state.nextcloud_talk_webhook_secret {
        let random = headers
            .get("X-Nextcloud-Talk-Random")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let signature = headers
            .get("X-Nextcloud-Talk-Signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !crate::channels::nextcloud_talk::verify_nextcloud_talk_signature(
            webhook_secret,
            random,
            &body_str,
            signature,
        ) {
            tracing::warn!(
                "Nextcloud Talk webhook signature verification failed (signature: {})",
                if signature.is_empty() {
                    "missing"
                } else {
                    "invalid"
                }
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid signature"})),
            );
        }
    }

    // Parse JSON body
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid JSON payload"})),
        );
    };

    // Parse messages from webhook payload
    let messages = nextcloud_talk.parse_webhook_payload(&payload);
    if messages.is_empty() {
        // Acknowledge webhook even if payload does not contain actionable user messages.
        return (StatusCode::OK, Json(serde_json::json!({"status": "ok"})));
    }

    for msg in &messages {
        tracing::info!(
            "Nextcloud Talk message from {}: {}",
            msg.sender,
            truncate_with_ellipsis(&msg.content, 50)
        );
        let session_id = sender_session_id("nextcloud_talk", msg);

        if state.auto_save && !memory::should_skip_autosave_content(&msg.content) {
            let key = nextcloud_talk_memory_key(msg);
            let _ = state
                .mem
                .store(
                    &key,
                    &msg.content,
                    MemoryCategory::Conversation,
                    Some(&session_id),
                )
                .await;
        }

        match Box::pin(run_gateway_chat_with_tools(
            &state,
            &msg.content,
            Some(&session_id),
        ))
        .await
        {
            Ok(response) => {
                if let Err(e) = nextcloud_talk
                    .send(&SendMessage::new(response, &msg.reply_target))
                    .await
                {
                    tracing::error!("Failed to send Nextcloud Talk reply: {e}");
                }
            }
            Err(e) => {
                tracing::error!("LLM error for Nextcloud Talk message: {e:#}");
                let _ = nextcloud_talk
                    .send(&SendMessage::new(
                        "Sorry, I couldn't process your message right now.",
                        &msg.reply_target,
                    ))
                    .await;
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// POST /bluedot — incoming Bluedot webhook (passive transcript ingestion)
async fn handle_bluedot_webhook(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let rate_key =
        client_key_from_request(Some(peer_addr), &headers, state.trust_forwarded_headers);
    if !state.rate_limiter.allow_webhook(&rate_key) {
        tracing::warn!("/bluedot rate limit exceeded");
        let err = serde_json::json!({
            "error": "Too many webhook requests. Please retry later.",
            "retry_after": RATE_LIMIT_WINDOW_SECS,
        });
        return (StatusCode::TOO_MANY_REQUESTS, Json(err));
    }

    let (
        enabled,
        webhook_secret,
        automation_enabled,
        automation_agent,
        automation_title_keywords,
        automation_attendee_emails,
        db_path,
        retention_days,
        max_meetings,
    ) = {
        let config = state.config.lock();
        (
            bluedot_webhook_enabled(&config),
            resolve_bluedot_webhook_secret(&config),
            bluedot_webhook_automation_enabled(&config),
            normalize_webhook_automation_agent(config.bluedot.webhook_automation_agent.as_deref()),
            config.bluedot.webhook_automation_title_keywords.clone(),
            config.bluedot.webhook_automation_attendee_emails.clone(),
            config.bluedot.db_path.clone(),
            config.bluedot.retention_days,
            config.bluedot.max_meetings,
        )
    };

    if !enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Bluedot webhook not configured"})),
        );
    }

    let Some(webhook_secret) = webhook_secret else {
        tracing::error!("Bluedot webhook enabled but no signing secret is configured");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Bluedot webhook secret is not configured"})),
        );
    };

    let svix_id = headers
        .get("svix-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let svix_timestamp = headers
        .get("svix-timestamp")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let svix_signature = headers
        .get("svix-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if !verify_bluedot_signature(
        &webhook_secret,
        svix_id,
        svix_timestamp,
        &body,
        svix_signature,
    ) {
        tracing::warn!(
            "Bluedot webhook signature verification failed (id: {}, signature: {})",
            if svix_id.trim().is_empty() {
                "missing"
            } else {
                "present"
            },
            if svix_signature.trim().is_empty() {
                "missing"
            } else {
                "invalid"
            }
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid signature"})),
        );
    }

    if !state
        .idempotency_store
        .record_if_new(&format!("bluedot:{svix_id}"))
    {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"status": "duplicate"})),
        );
    }

    let Ok(payload) = serde_json::from_slice::<BluedotWebhookPayload>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid JSON payload"})),
        );
    };

    if !payload.is_supported_event_type() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ignored"})),
        );
    }

    let store = match BluedotMeetingStore::new(&db_path, retention_days, max_meetings) {
        Ok(store) => store,
        Err(error) => {
            tracing::error!("Failed to initialize Bluedot store: {error:#}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to initialize Bluedot store"})),
            );
        }
    };

    match store.upsert_webhook_payload(&payload) {
        Ok(meeting) => {
            let delivery_id = (!svix_id.trim().is_empty()).then_some(svix_id);
            tracing::info!(
                "Bluedot webhook stored {} for video {}",
                payload.event_type.as_deref().unwrap_or("unknown"),
                meeting.video_id
            );

            if state.auto_save {
                let key = bluedot_webhook_memory_key(delivery_id);
                let normalized = serde_json::json!({
                    "source": "bluedot",
                    "delivery_id": delivery_id,
                    "event": payload.event_type,
                    "video_id": meeting.video_id,
                    "meeting_id": meeting.meeting_id,
                    "title": meeting.title,
                    "created_at": meeting.created_at,
                    "duration_secs": meeting.duration_secs,
                    "attendees": meeting.attendees,
                    "summary_present": meeting.summary.as_ref().is_some_and(|value| !value.trim().is_empty()),
                    "transcript_entries": meeting.transcript.len(),
                });
                if let Ok(content) = serde_json::to_string_pretty(&normalized) {
                    let _ = state
                        .mem
                        .store(
                            &key,
                            &content,
                            MemoryCategory::Custom("bluedot_webhook".to_string()),
                            None,
                        )
                        .await;
                }
            }

            let automation_enqueued = automation_enabled
                && payload.is_transcript_ready_event()
                && bluedot_webhook_automation_matches(
                    &automation_title_keywords,
                    &automation_attendee_emails,
                    &meeting,
                );
            if automation_enqueued {
                let state_for_task = state.clone();
                let payload_for_task = payload.clone();
                let meeting_for_task = meeting.clone();
                let automation_agent_for_task = automation_agent.clone();
                let delivery_id_for_task = delivery_id.map(str::to_owned);
                let automation_id = delivery_id_for_task
                    .clone()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                let automation_session_id = format!("bluedot_webhook_auto_{automation_id}");
                let automation_result_key =
                    format!("bluedot_webhook_automation_result_{automation_id}");
                let automation_message = build_bluedot_webhook_automation_message(
                    delivery_id_for_task.as_deref(),
                    &payload_for_task,
                    &meeting_for_task,
                );

                tracing::info!(
                    delivery_id = delivery_id_for_task.as_deref().unwrap_or(""),
                    event = payload_for_task.event_type.as_deref().unwrap_or(""),
                    video_id = %meeting_for_task.video_id,
                    automation_agent = automation_agent_for_task.as_deref().unwrap_or(""),
                    "Bluedot webhook automation enqueued"
                );

                let semaphore = state_for_task.webhook_automation_semaphore.clone();
                tokio::spawn(async move {
                    let _permit = match semaphore.acquire().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::error!("Webhook automation semaphore closed");
                            return;
                        }
                    };
                    let automation_result = match automation_agent_for_task.as_deref() {
                        Some(agent_name) => {
                            run_gateway_named_agent(
                                &state_for_task,
                                agent_name,
                                &automation_message,
                            )
                            .await
                        }
                        None => {
                            run_gateway_chat_with_tools(
                                &state_for_task,
                                &automation_message,
                                Some(&automation_session_id),
                            )
                            .await
                        }
                    };
                    match automation_result {
                        Ok(response) => {
                            tracing::info!(
                                delivery_id = delivery_id_for_task.as_deref().unwrap_or(""),
                                session_id = %automation_session_id,
                                video_id = %meeting_for_task.video_id,
                                automation_agent = automation_agent_for_task.as_deref().unwrap_or(""),
                                "Bluedot webhook automation completed"
                            );
                            if state_for_task.auto_save
                                && !memory::should_skip_autosave_content(&response)
                            {
                                let content = serde_json::json!({
                                    "source": "bluedot",
                                    "delivery_id": delivery_id_for_task,
                                    "event": payload_for_task.event_type,
                                    "video_id": meeting_for_task.video_id,
                                    "meeting_id": meeting_for_task.meeting_id,
                                    "title": meeting_for_task.title,
                                    "response": response,
                                });
                                if let Ok(serialized) = serde_json::to_string_pretty(&content) {
                                    let _ = state_for_task
                                        .mem
                                        .store(
                                            &automation_result_key,
                                            &serialized,
                                            MemoryCategory::Custom(
                                                "bluedot_webhook_automation".to_string(),
                                            ),
                                            Some(&automation_session_id),
                                        )
                                        .await;
                                }
                            }
                        }
                        Err(error) => {
                            tracing::error!(
                                delivery_id = delivery_id_for_task.as_deref().unwrap_or(""),
                                session_id = %automation_session_id,
                                video_id = %meeting_for_task.video_id,
                                automation_agent = automation_agent_for_task.as_deref().unwrap_or(""),
                                "Bluedot webhook automation failed: {error:#}"
                            );
                        }
                    }
                });
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "video_id": meeting.video_id,
                    "automation_enqueued": automation_enqueued,
                })),
            )
        }
        Err(error) => {
            tracing::error!("Failed to store Bluedot webhook payload: {error:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to store meeting payload"})),
            )
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct LinearWebhookPayload {
    action: Option<String>,
    #[serde(rename = "type")]
    event_type: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    #[serde(rename = "webhookTimestamp")]
    webhook_timestamp: i64,
    #[serde(rename = "webhookId")]
    webhook_id: Option<String>,
    url: Option<String>,
    #[serde(default)]
    data: serde_json::Value,
    #[serde(rename = "updatedFrom")]
    updated_from: Option<serde_json::Value>,
}

/// POST /linear — incoming Linear webhook (passive ingestion only)
async fn handle_linear_webhook(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let rate_key =
        client_key_from_request(Some(peer_addr), &headers, state.trust_forwarded_headers);
    if !state.rate_limiter.allow_webhook(&rate_key) {
        tracing::warn!("/linear rate limit exceeded");
        let err = serde_json::json!({
            "error": "Too many webhook requests. Please retry later.",
            "retry_after": RATE_LIMIT_WINDOW_SECS,
        });
        return (StatusCode::TOO_MANY_REQUESTS, Json(err));
    }

    let (
        enabled,
        webhook_secret,
        automation_enabled,
        automation_agent,
        automation_events,
        automation_issue_prefixes,
    ) = {
        let config = state.config.lock();
        (
            linear_webhook_enabled(&config),
            resolve_linear_webhook_secret(&config),
            linear_webhook_automation_enabled(&config),
            normalize_webhook_automation_agent(config.linear.webhook_automation_agent.as_deref()),
            config.linear.webhook_automation_events.clone(),
            config.linear.webhook_automation_issue_prefixes.clone(),
        )
    };

    if !enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Linear webhook not configured"})),
        );
    }

    let Some(webhook_secret) = webhook_secret else {
        tracing::error!("Linear webhook enabled but no signing secret is configured");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Internal server error"})),
        );
    };

    let signature = headers
        .get("Linear-Signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if !verify_linear_signature(&webhook_secret, &body, signature) {
        tracing::warn!(
            "Linear webhook signature verification failed (signature: {})",
            if signature.is_empty() {
                "missing"
            } else {
                "invalid"
            }
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid signature"})),
        );
    }

    let Ok(payload) = serde_json::from_slice::<LinearWebhookPayload>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid JSON payload"})),
        );
    };

    if !linear_webhook_timestamp_is_fresh(payload.webhook_timestamp) {
        tracing::warn!(
            "Linear webhook rejected due to stale timestamp: {}",
            payload.webhook_timestamp
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid webhook timestamp"})),
        );
    }

    let delivery_id = headers
        .get("Linear-Delivery")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let linear_event = headers
        .get("Linear-Event")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    let idempotency_key = delivery_id
        .as_deref()
        .or(payload.webhook_id.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(idempotency_key) = idempotency_key {
        if !state.idempotency_store.record_if_new(idempotency_key) {
            tracing::info!("Linear webhook duplicate ignored: {idempotency_key}");
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "duplicate",
                    "idempotent": true,
                    "message": "Webhook delivery already processed"
                })),
            );
        }
    }

    tracing::info!(
        delivery_id = delivery_id.as_deref().unwrap_or(""),
        linear_event = linear_event.as_deref().unwrap_or(""),
        action = payload.action.as_deref().unwrap_or(""),
        entity_type = payload.event_type.as_deref().unwrap_or(""),
        "Linear webhook received"
    );

    if state.auto_save {
        let key = linear_webhook_memory_key(idempotency_key);
        let normalized = serde_json::json!({
            "source": "linear",
            "delivery_id": delivery_id,
            "event": linear_event,
            "action": payload.action,
            "type": payload.event_type,
            "created_at": payload.created_at,
            "organization_id": payload.organization_id,
            "webhook_id": payload.webhook_id,
            "url": payload.url,
            "webhook_timestamp": payload.webhook_timestamp,
            "updated_from": payload.updated_from,
            "data": payload.data,
        });
        if let Ok(content) = serde_json::to_string_pretty(&normalized) {
            let _ = state
                .mem
                .store(
                    &key,
                    &content,
                    MemoryCategory::Custom("linear_webhook".to_string()),
                    None,
                )
                .await;
        }
    }

    if automation_enabled
        && linear_webhook_automation_matches(
            &automation_events,
            &automation_issue_prefixes,
            linear_event.as_deref(),
            &payload,
        )
    {
        let state_for_task = state.clone();
        let delivery_id_for_task = delivery_id.clone();
        let linear_event_for_task = linear_event.clone();
        let automation_agent_for_task = automation_agent.clone();
        let automation_message = build_linear_webhook_automation_message(
            delivery_id_for_task.as_deref(),
            linear_event_for_task.as_deref(),
            &payload,
        );
        let automation_id = idempotency_key
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let automation_session_id = format!("linear_webhook_auto_{automation_id}");
        let automation_result_key = format!("linear_webhook_automation_result_{automation_id}");
        let action_for_task = payload.action.clone();
        let event_type_for_task = payload.event_type.clone();
        let url_for_task = payload.url.clone();

        tracing::info!(
            delivery_id = delivery_id_for_task.as_deref().unwrap_or(""),
            linear_event = linear_event_for_task.as_deref().unwrap_or(""),
            action = action_for_task.as_deref().unwrap_or(""),
            entity_type = event_type_for_task.as_deref().unwrap_or(""),
            automation_agent = automation_agent_for_task.as_deref().unwrap_or(""),
            "Linear webhook automation enqueued"
        );

        let semaphore = state_for_task.webhook_automation_semaphore.clone();
        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::error!("Webhook automation semaphore closed");
                    return;
                }
            };
            let automation_result = match automation_agent_for_task.as_deref() {
                Some(agent_name) => {
                    run_gateway_named_agent(&state_for_task, agent_name, &automation_message).await
                }
                None => {
                    run_gateway_chat_with_tools(
                        &state_for_task,
                        &automation_message,
                        Some(&automation_session_id),
                    )
                    .await
                }
            };
            match automation_result {
                Ok(response) => {
                    tracing::info!(
                        delivery_id = delivery_id_for_task.as_deref().unwrap_or(""),
                        session_id = %automation_session_id,
                        automation_agent = automation_agent_for_task.as_deref().unwrap_or(""),
                        "Linear webhook automation completed"
                    );
                    if state_for_task.auto_save && !memory::should_skip_autosave_content(&response)
                    {
                        let content = serde_json::json!({
                            "source": "linear",
                            "delivery_id": delivery_id_for_task,
                            "event": linear_event_for_task,
                            "action": action_for_task,
                            "type": event_type_for_task,
                            "url": url_for_task,
                            "response": response,
                        });
                        if let Ok(serialized) = serde_json::to_string_pretty(&content) {
                            let _ = state_for_task
                                .mem
                                .store(
                                    &automation_result_key,
                                    &serialized,
                                    MemoryCategory::Custom("linear_webhook_automation".to_string()),
                                    Some(&automation_session_id),
                                )
                                .await;
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(
                        delivery_id = delivery_id_for_task.as_deref().unwrap_or(""),
                        session_id = %automation_session_id,
                        automation_agent = automation_agent_for_task.as_deref().unwrap_or(""),
                        "Linear webhook automation failed: {error:#}"
                    );
                }
            }
        });
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// Maximum request body size for the Gmail webhook endpoint (1 MB).
/// Google Pub/Sub messages are typically under 10 KB.
const GMAIL_WEBHOOK_MAX_BODY: usize = 1024 * 1024;

/// POST /webhook/gmail — incoming Gmail Pub/Sub push notification
async fn handle_gmail_push_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(ref gmail_push) = state.gmail_push else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Gmail push not configured"})),
        );
    };

    // Enforce body size limit.
    if body.len() > GMAIL_WEBHOOK_MAX_BODY {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "Request body too large"})),
        );
    }

    // Authenticate the webhook request using a shared secret.
    let secret = gmail_push.resolve_webhook_secret();
    if !secret.is_empty() {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .unwrap_or("");

        if provided != secret {
            tracing::warn!("Gmail push webhook: unauthorized request");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Unauthorized"})),
            );
        }
    }

    let body_str = String::from_utf8_lossy(&body);
    let envelope: crate::channels::gmail_push::PubSubEnvelope =
        match serde_json::from_str(&body_str) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Gmail push webhook: invalid payload: {e}");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid Pub/Sub envelope"})),
                );
            }
        };

    // Process the notification asynchronously (non-blocking for the webhook response)
    let channel = Arc::clone(gmail_push);
    tokio::spawn(async move {
        if let Err(e) = channel.handle_notification(&envelope).await {
            tracing::error!("Gmail push notification processing failed: {e:#}");
        }
    });

    // Acknowledge immediately — Google Pub/Sub requires a 2xx within ~10s
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN HANDLERS (for CLI management)
// ══════════════════════════════════════════════════════════════════════════════

/// Response for admin endpoints
#[derive(serde::Serialize)]
struct AdminResponse {
    success: bool,
    message: String,
}

/// Reject requests that do not originate from a loopback address.
fn require_localhost(peer: &SocketAddr) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if peer.ip().is_loopback() {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Admin endpoints are restricted to localhost"
            })),
        ))
    }
}

/// POST /admin/shutdown — graceful shutdown from CLI (localhost only)
async fn handle_admin_shutdown(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    require_localhost(&peer)?;
    tracing::info!("🔌 Admin shutdown request received — initiating graceful shutdown");

    let body = AdminResponse {
        success: true,
        message: "Gateway shutdown initiated".to_string(),
    };

    let _ = state.shutdown_tx.send(true);

    Ok((StatusCode::OK, Json(body)))
}

/// GET /admin/paircode — fetch current pairing code (localhost only)
async fn handle_admin_paircode(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    require_localhost(&peer)?;
    let code = state.pairing.pairing_code();

    let body = if let Some(c) = code {
        serde_json::json!({
            "success": true,
            "pairing_required": state.pairing.require_pairing(),
            "pairing_code": c,
            "message": "Use this one-time code to pair"
        })
    } else {
        serde_json::json!({
            "success": true,
            "pairing_required": state.pairing.require_pairing(),
            "pairing_code": null,
            "message": if state.pairing.require_pairing() {
                "Pairing is active but no new code available (already paired or code expired)"
            } else {
                "Pairing is disabled for this gateway"
            }
        })
    };

    Ok((StatusCode::OK, Json(body)))
}

/// POST /admin/paircode/new — generate a new pairing code (localhost only)
async fn handle_admin_paircode_new(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    require_localhost(&peer)?;
    match state.pairing.generate_new_pairing_code() {
        Some(code) => {
            tracing::info!("🔐 New pairing code generated via admin endpoint");
            let body = serde_json::json!({
                "success": true,
                "pairing_required": state.pairing.require_pairing(),
                "pairing_code": code,
                "message": "New pairing code generated — use this one-time code to pair"
            });
            Ok((StatusCode::OK, Json(body)))
        }
        None => {
            let body = serde_json::json!({
                "success": false,
                "pairing_required": false,
                "pairing_code": null,
                "message": "Pairing is disabled for this gateway"
            });
            Ok((StatusCode::BAD_REQUEST, Json(body)))
        }
    }
}

/// GET /pair/code — fetch the initial pairing code (no auth, no localhost restriction).
///
/// This endpoint is intentionally public so that Docker and remote users can see
/// the pairing code on the web dashboard without needing terminal access. It only
/// returns a code when the gateway is in its initial un-paired state (no devices
/// paired yet and a pairing code exists). Once the first device pairs, this
/// endpoint stops returning a code.
async fn handle_pair_code(State(state): State<AppState>) -> impl IntoResponse {
    let require = state.pairing.require_pairing();
    let is_paired = state.pairing.is_paired();

    // Only expose the code during initial setup (before first pairing)
    let code = if require && !is_paired {
        state.pairing.pairing_code()
    } else {
        None
    };

    let body = serde_json::json!({
        "success": true,
        "pairing_required": require,
        "pairing_code": code,
    });

    (StatusCode::OK, Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::traits::ChannelMessage;
    use crate::memory::{Memory, MemoryCategory, MemoryEntry};
    use crate::providers::Provider;
    use async_trait::async_trait;
    use axum::http::HeaderValue;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Generate a random hex secret at runtime to avoid hard-coded cryptographic values.
    fn generate_test_secret() -> String {
        let bytes: [u8; 32] = rand::random();
        hex::encode(bytes)
    }

    #[test]
    fn security_body_limit_is_64kb() {
        assert_eq!(MAX_BODY_SIZE, 65_536);
    }

    #[test]
    fn security_timeout_default_is_30_seconds() {
        assert_eq!(REQUEST_TIMEOUT_SECS, 30);
    }

    #[test]
    fn gateway_timeout_falls_back_to_default() {
        // When env var is not set, should return the default constant
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("ZEROCLAW_GATEWAY_TIMEOUT_SECS") };
        assert_eq!(gateway_request_timeout_secs(), 30);
    }

    #[test]
    fn webhook_body_requires_message_field() {
        let valid = r#"{"message": "hello"}"#;
        let parsed: Result<WebhookBody, _> = serde_json::from_str(valid);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().message, "hello");

        let missing = r#"{"other": "field"}"#;
        let parsed: Result<WebhookBody, _> = serde_json::from_str(missing);
        assert!(parsed.is_err());
    }

    #[test]
    fn whatsapp_query_fields_are_optional() {
        let q = WhatsAppVerifyQuery {
            mode: None,
            verify_token: None,
            challenge: None,
        };
        assert!(q.mode.is_none());
    }

    #[test]
    fn app_state_is_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<AppState>();
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_hint_when_prometheus_is_disabled() {
        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider: Arc::new(MockProvider::default()),
            model: "test-model".into(),
            temperature: 0.0,
            mem: Arc::new(MockMemory),
            auto_save: false,
            webhook_secret_hash: None,
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let response = handle_metrics(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(PROMETHEUS_CONTENT_TYPE)
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("Prometheus backend not enabled"));
    }

    #[cfg(feature = "observability-prometheus")]
    #[tokio::test]
    async fn metrics_endpoint_renders_prometheus_output() {
        let event_tx = tokio::sync::broadcast::channel(16).0;
        let event_buffer = Arc::new(sse::EventBuffer::new(16));
        let wrapped = sse::BroadcastObserver::new(
            Box::new(crate::observability::PrometheusObserver::new()),
            event_tx.clone(),
            event_buffer,
        );
        crate::observability::Observer::record_event(
            &wrapped,
            &crate::observability::ObserverEvent::HeartbeatTick,
        );

        let observer: Arc<dyn crate::observability::Observer> = Arc::new(wrapped);
        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider: Arc::new(MockProvider::default()),
            model: "test-model".into(),
            temperature: 0.0,
            mem: Arc::new(MockMemory),
            auto_save: false,
            webhook_secret_hash: None,
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer,
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let response = handle_metrics(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("zeroclaw_heartbeat_ticks_total 1"));
    }

    #[test]
    fn gateway_rate_limiter_blocks_after_limit() {
        let limiter = GatewayRateLimiter::new(2, 2, 100);
        assert!(limiter.allow_pair("127.0.0.1"));
        assert!(limiter.allow_pair("127.0.0.1"));
        assert!(!limiter.allow_pair("127.0.0.1"));
    }

    #[test]
    fn rate_limiter_sweep_removes_stale_entries() {
        let limiter = SlidingWindowRateLimiter::new(10, Duration::from_secs(60), 100);
        // Add entries for multiple IPs
        assert!(limiter.allow("ip-1"));
        assert!(limiter.allow("ip-2"));
        assert!(limiter.allow("ip-3"));

        {
            let guard = limiter.requests.lock();
            assert_eq!(guard.0.len(), 3);
        }

        // Force a sweep by backdating last_sweep
        {
            let mut guard = limiter.requests.lock();
            guard.1 = Instant::now()
                .checked_sub(Duration::from_secs(RATE_LIMITER_SWEEP_INTERVAL_SECS + 1))
                .unwrap();
            // Clear timestamps for ip-2 and ip-3 to simulate stale entries
            guard.0.get_mut("ip-2").unwrap().clear();
            guard.0.get_mut("ip-3").unwrap().clear();
        }

        // Next allow() call should trigger sweep and remove stale entries
        assert!(limiter.allow("ip-1"));

        {
            let guard = limiter.requests.lock();
            assert_eq!(guard.0.len(), 1, "Stale entries should have been swept");
            assert!(guard.0.contains_key("ip-1"));
        }
    }

    #[test]
    fn rate_limiter_zero_limit_always_allows() {
        let limiter = SlidingWindowRateLimiter::new(0, Duration::from_secs(60), 10);
        for _ in 0..100 {
            assert!(limiter.allow("any-key"));
        }
    }

    #[test]
    fn idempotency_store_rejects_duplicate_key() {
        let store = IdempotencyStore::new(Duration::from_secs(30), 10);
        assert!(store.record_if_new("req-1"));
        assert!(!store.record_if_new("req-1"));
        assert!(store.record_if_new("req-2"));
    }

    #[test]
    fn rate_limiter_bounded_cardinality_evicts_oldest_key() {
        let limiter = SlidingWindowRateLimiter::new(5, Duration::from_secs(60), 2);
        assert!(limiter.allow("ip-1"));
        assert!(limiter.allow("ip-2"));
        assert!(limiter.allow("ip-3"));

        let guard = limiter.requests.lock();
        assert_eq!(guard.0.len(), 2);
        assert!(guard.0.contains_key("ip-2"));
        assert!(guard.0.contains_key("ip-3"));
    }

    #[test]
    fn idempotency_store_bounded_cardinality_evicts_oldest_key() {
        let store = IdempotencyStore::new(Duration::from_secs(300), 2);
        assert!(store.record_if_new("k1"));
        std::thread::sleep(Duration::from_millis(2));
        assert!(store.record_if_new("k2"));
        std::thread::sleep(Duration::from_millis(2));
        assert!(store.record_if_new("k3"));

        let keys = store.keys.lock();
        assert_eq!(keys.len(), 2);
        assert!(!keys.contains_key("k1"));
        assert!(keys.contains_key("k2"));
        assert!(keys.contains_key("k3"));
    }

    #[test]
    fn client_key_defaults_to_peer_addr_when_untrusted_proxy_mode() {
        let peer = SocketAddr::from(([10, 0, 0, 5], 42617));
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            HeaderValue::from_static("198.51.100.10, 203.0.113.11"),
        );

        let key = client_key_from_request(Some(peer), &headers, false);
        assert_eq!(key, "10.0.0.5");
    }

    #[test]
    fn client_key_uses_forwarded_ip_only_in_trusted_proxy_mode() {
        let peer = SocketAddr::from(([10, 0, 0, 5], 42617));
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            HeaderValue::from_static("198.51.100.10, 203.0.113.11"),
        );

        let key = client_key_from_request(Some(peer), &headers, true);
        assert_eq!(key, "198.51.100.10");
    }

    #[test]
    fn client_key_falls_back_to_peer_when_forwarded_header_invalid() {
        let peer = SocketAddr::from(([10, 0, 0, 5], 42617));
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", HeaderValue::from_static("garbage-value"));

        let key = client_key_from_request(Some(peer), &headers, true);
        assert_eq!(key, "10.0.0.5");
    }

    #[test]
    fn normalize_max_keys_uses_fallback_for_zero() {
        assert_eq!(normalize_max_keys(0, 10_000), 10_000);
        assert_eq!(normalize_max_keys(0, 0), 1);
    }

    #[test]
    fn normalize_max_keys_preserves_nonzero_values() {
        assert_eq!(normalize_max_keys(2_048, 10_000), 2_048);
        assert_eq!(normalize_max_keys(1, 10_000), 1);
    }

    #[tokio::test]
    async fn persist_pairing_tokens_writes_config_tokens() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.toml");
        let workspace_path = temp.path().join("workspace");

        let mut config = Config::default();
        config.config_path = config_path.clone();
        config.workspace_dir = workspace_path;
        config.save().await.unwrap();

        let guard = PairingGuard::new(true, &[]);
        let code = guard.pairing_code().unwrap();
        let token = guard.try_pair(&code, "test_client").await.unwrap().unwrap();
        assert!(guard.is_authenticated(&token));

        let shared_config = Arc::new(Mutex::new(config));
        Box::pin(persist_pairing_tokens(shared_config.clone(), &guard))
            .await
            .unwrap();

        // In-memory tokens should remain as plaintext 64-char hex hashes.
        let plaintext = {
            let in_memory = shared_config.lock();
            assert_eq!(in_memory.gateway.paired_tokens.len(), 1);
            in_memory.gateway.paired_tokens[0].clone()
        };
        assert_eq!(plaintext.len(), 64);
        assert!(plaintext.chars().all(|c: char| c.is_ascii_hexdigit()));

        // On disk, the token should be encrypted (secrets.encrypt defaults to true).
        let saved = tokio::fs::read_to_string(config_path).await.unwrap();
        let raw_parsed: Config = toml::from_str(&saved).unwrap();
        assert_eq!(raw_parsed.gateway.paired_tokens.len(), 1);
        let on_disk = &raw_parsed.gateway.paired_tokens[0];
        assert!(
            crate::security::SecretStore::is_encrypted(on_disk),
            "paired_token should be encrypted on disk"
        );
    }

    #[test]
    fn webhook_memory_key_is_unique() {
        let key1 = webhook_memory_key();
        let key2 = webhook_memory_key();

        assert!(key1.starts_with("webhook_msg_"));
        assert!(key2.starts_with("webhook_msg_"));
        assert_ne!(key1, key2);
    }

    #[test]
    fn whatsapp_memory_key_includes_sender_and_message_id() {
        let msg = ChannelMessage {
            id: "wamid-123".into(),
            sender: "+1234567890".into(),
            reply_target: "+1234567890".into(),
            content: "hello".into(),
            channel: "whatsapp".into(),
            timestamp: 1,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: vec![],
        };

        let key = whatsapp_memory_key(&msg);
        assert_eq!(key, "whatsapp_+1234567890_wamid-123");
    }

    #[derive(Default)]
    struct MockMemory;

    #[async_trait]
    impl Memory for MockMemory {
        fn name(&self) -> &str {
            "mock"
        }

        async fn store(
            &self,
            _key: &str,
            _content: &str,
            _category: MemoryCategory,
            _session_id: Option<&str>,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn recall(
            &self,
            _query: &str,
            _limit: usize,
            _session_id: Option<&str>,
            _since: Option<&str>,
            _until: Option<&str>,
        ) -> anyhow::Result<Vec<MemoryEntry>> {
            Ok(Vec::new())
        }

        async fn get(&self, _key: &str) -> anyhow::Result<Option<MemoryEntry>> {
            Ok(None)
        }

        async fn list(
            &self,
            _category: Option<&MemoryCategory>,
            _session_id: Option<&str>,
        ) -> anyhow::Result<Vec<MemoryEntry>> {
            Ok(Vec::new())
        }

        async fn forget(&self, _key: &str) -> anyhow::Result<bool> {
            Ok(false)
        }

        async fn count(&self) -> anyhow::Result<usize> {
            Ok(0)
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct MockProvider {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Provider for MockProvider {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: f64,
        ) -> anyhow::Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok("ok".into())
        }
    }

    #[derive(Default)]
    struct TrackingMemory {
        keys: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Memory for TrackingMemory {
        fn name(&self) -> &str {
            "tracking"
        }

        async fn store(
            &self,
            key: &str,
            _content: &str,
            _category: MemoryCategory,
            _session_id: Option<&str>,
        ) -> anyhow::Result<()> {
            self.keys.lock().push(key.to_string());
            Ok(())
        }

        async fn recall(
            &self,
            _query: &str,
            _limit: usize,
            _session_id: Option<&str>,
            _since: Option<&str>,
            _until: Option<&str>,
        ) -> anyhow::Result<Vec<MemoryEntry>> {
            Ok(Vec::new())
        }

        async fn get(&self, _key: &str) -> anyhow::Result<Option<MemoryEntry>> {
            Ok(None)
        }

        async fn list(
            &self,
            _category: Option<&MemoryCategory>,
            _session_id: Option<&str>,
        ) -> anyhow::Result<Vec<MemoryEntry>> {
            Ok(Vec::new())
        }

        async fn forget(&self, _key: &str) -> anyhow::Result<bool> {
            Ok(false)
        }

        async fn count(&self) -> anyhow::Result<usize> {
            let size = self.keys.lock().len();
            Ok(size)
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    fn test_connect_info() -> ConnectInfo<SocketAddr> {
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 30_300)))
    }

    #[tokio::test]
    async fn webhook_idempotency_skips_duplicate_provider_calls() {
        let provider_impl = Arc::new(MockProvider::default());
        let provider: Arc<dyn Provider> = provider_impl.clone();
        let memory: Arc<dyn Memory> = Arc::new(MockMemory);

        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider,
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: false,
            webhook_secret_hash: None,
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert("X-Idempotency-Key", HeaderValue::from_static("abc-123"));

        let body = Ok(Json(WebhookBody {
            message: "hello".into(),
        }));
        let first = handle_webhook(
            State(state.clone()),
            test_connect_info(),
            headers.clone(),
            body,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let body = Ok(Json(WebhookBody {
            message: "hello".into(),
        }));
        let second = handle_webhook(State(state), test_connect_info(), headers, body)
            .await
            .into_response();
        assert_eq!(second.status(), StatusCode::OK);

        let payload = second.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["status"], "duplicate");
        assert_eq!(parsed["idempotent"], true);
        assert_eq!(provider_impl.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn webhook_autosave_stores_distinct_keys_per_request() {
        let provider_impl = Arc::new(MockProvider::default());
        let provider: Arc<dyn Provider> = provider_impl.clone();

        let tracking_impl = Arc::new(TrackingMemory::default());
        let memory: Arc<dyn Memory> = tracking_impl.clone();

        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider,
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: true,
            webhook_secret_hash: None,
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let headers = HeaderMap::new();

        let body1 = Ok(Json(WebhookBody {
            message: "hello one".into(),
        }));
        let first = handle_webhook(
            State(state.clone()),
            test_connect_info(),
            headers.clone(),
            body1,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let body2 = Ok(Json(WebhookBody {
            message: "hello two".into(),
        }));
        let second = handle_webhook(State(state), test_connect_info(), headers, body2)
            .await
            .into_response();
        assert_eq!(second.status(), StatusCode::OK);

        let keys = tracking_impl.keys.lock().clone();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1]);
        assert!(keys[0].starts_with("webhook_msg_"));
        assert!(keys[1].starts_with("webhook_msg_"));
        assert_eq!(provider_impl.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn webhook_secret_hash_is_deterministic_and_nonempty() {
        let secret_a = generate_test_secret();
        let secret_b = generate_test_secret();
        let one = hash_webhook_secret(&secret_a);
        let two = hash_webhook_secret(&secret_a);
        let other = hash_webhook_secret(&secret_b);

        assert_eq!(one, two);
        assert_ne!(one, other);
        assert_eq!(one.len(), 64);
    }

    #[tokio::test]
    async fn webhook_secret_hash_rejects_missing_header() {
        let provider_impl = Arc::new(MockProvider::default());
        let provider: Arc<dyn Provider> = provider_impl.clone();
        let memory: Arc<dyn Memory> = Arc::new(MockMemory);
        let secret = generate_test_secret();

        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider,
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: false,
            webhook_secret_hash: Some(Arc::from(hash_webhook_secret(&secret))),
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let response = handle_webhook(
            State(state),
            test_connect_info(),
            HeaderMap::new(),
            Ok(Json(WebhookBody {
                message: "hello".into(),
            })),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(provider_impl.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn webhook_secret_hash_rejects_invalid_header() {
        let provider_impl = Arc::new(MockProvider::default());
        let provider: Arc<dyn Provider> = provider_impl.clone();
        let memory: Arc<dyn Memory> = Arc::new(MockMemory);
        let valid_secret = generate_test_secret();
        let wrong_secret = generate_test_secret();

        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider,
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: false,
            webhook_secret_hash: Some(Arc::from(hash_webhook_secret(&valid_secret))),
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Webhook-Secret",
            HeaderValue::from_str(&wrong_secret).unwrap(),
        );

        let response = handle_webhook(
            State(state),
            test_connect_info(),
            headers,
            Ok(Json(WebhookBody {
                message: "hello".into(),
            })),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(provider_impl.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn webhook_secret_hash_accepts_valid_header() {
        let provider_impl = Arc::new(MockProvider::default());
        let provider: Arc<dyn Provider> = provider_impl.clone();
        let memory: Arc<dyn Memory> = Arc::new(MockMemory);
        let secret = generate_test_secret();

        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider,
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: false,
            webhook_secret_hash: Some(Arc::from(hash_webhook_secret(&secret))),
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert("X-Webhook-Secret", HeaderValue::from_str(&secret).unwrap());

        let response = handle_webhook(
            State(state),
            test_connect_info(),
            headers,
            Ok(Json(WebhookBody {
                message: "hello".into(),
            })),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(provider_impl.calls.load(Ordering::SeqCst), 1);
    }

    fn linear_webhook_test_state(config: Config, memory: Arc<dyn Memory>) -> AppState {
        AppState {
            config: Arc::new(Mutex::new(config)),
            provider: Arc::new(MockProvider::default()),
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: true,
            webhook_secret_hash: None,
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        }
    }

    fn compute_linear_signature_hex(secret: &str, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn linear_webhook_payload(timestamp_ms: i64) -> String {
        serde_json::json!({
            "action": "create",
            "type": "Issue",
            "createdAt": "2026-04-07T12:00:00.000Z",
            "organizationId": "org-123",
            "webhookTimestamp": timestamp_ms,
            "webhookId": "webhook-123",
            "url": "https://linear.app/burnt/issue/JB-1/test",
            "data": {
                "id": "issue-123",
                "identifier": "JB-1",
                "title": "Passive webhook smoke test"
            }
        })
        .to_string()
    }

    fn linear_webhook_payload_struct(timestamp_ms: i64) -> LinearWebhookPayload {
        serde_json::from_str(&linear_webhook_payload(timestamp_ms)).unwrap()
    }

    fn generate_svix_secret() -> String {
        use base64::Engine as _;
        format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(generate_test_secret().as_bytes())
        )
    }

    fn compute_bluedot_signature(
        secret: &str,
        svix_id: &str,
        svix_timestamp: i64,
        body: &str,
    ) -> String {
        use base64::Engine as _;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let encoded = secret.strip_prefix("whsec_").unwrap_or(secret);
        let secret_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret_bytes).unwrap();
        mac.update(format!("{svix_id}.{svix_timestamp}.{body}").as_bytes());
        format!(
            "v1,{}",
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
        )
    }

    fn bluedot_summary_payload() -> String {
        serde_json::json!({
            "type": "video.summary.created",
            "videoId": "video-123",
            "meetingId": "meet.google.com/abc-defg-hij",
            "title": "Bluedot webhook smoke test",
            "createdAt": 1_710_000_000_i64,
            "duration": 900,
            "attendees": ["alice@example.com", { "email": "bob@example.com", "name": "Bob" }],
            "summary": "Reviewed the meeting transcript integration."
        })
        .to_string()
    }

    fn bluedot_transcript_payload() -> String {
        serde_json::json!({
            "type": "video.transcript.created",
            "videoId": "video-123",
            "meetingId": "meet.google.com/abc-defg-hij",
            "title": "Bluedot webhook smoke test",
            "createdAt": 1_710_000_000_i64,
            "duration": 900,
            "transcript": [
                { "speaker": "Alice", "text": "We should store the transcript." },
                { "speaker": "Bob", "text": "And make it searchable." }
            ]
        })
        .to_string()
    }

    #[test]
    fn linear_signature_valid() {
        let secret = generate_test_secret();
        let body = br#"{"action":"create","webhookTimestamp":1}"#;
        let signature = compute_linear_signature_hex(&secret, body);

        assert!(verify_linear_signature(&secret, body, &signature));
    }

    #[test]
    fn linear_signature_invalid_wrong_secret() {
        let secret = generate_test_secret();
        let wrong_secret = generate_test_secret();
        let body = br#"{"action":"create","webhookTimestamp":1}"#;
        let signature = compute_linear_signature_hex(&wrong_secret, body);

        assert!(!verify_linear_signature(&secret, body, &signature));
    }

    #[test]
    fn bluedot_signature_valid() {
        let secret = generate_svix_secret();
        let body = bluedot_summary_payload();
        let timestamp = current_unix_timestamp_millis() / 1000;
        let signature = compute_bluedot_signature(&secret, "msg-123", timestamp, &body);

        assert!(verify_bluedot_signature(
            &secret,
            "msg-123",
            &timestamp.to_string(),
            body.as_bytes(),
            &signature,
        ));
    }

    #[test]
    fn bluedot_signature_invalid_wrong_secret() {
        let secret = generate_svix_secret();
        let wrong_secret = generate_svix_secret();
        let body = bluedot_summary_payload();
        let timestamp = current_unix_timestamp_millis() / 1000;
        let signature = compute_bluedot_signature(&wrong_secret, "msg-123", timestamp, &body);

        assert!(!verify_bluedot_signature(
            &secret,
            "msg-123",
            &timestamp.to_string(),
            body.as_bytes(),
            &signature,
        ));
    }

    #[test]
    fn linear_webhook_automation_match_supports_event_and_event_action() {
        let payload = linear_webhook_payload_struct(current_unix_timestamp_millis());

        assert!(linear_webhook_automation_matches(
            &["Issue".into()],
            &[],
            Some("Issue"),
            &payload
        ));
        assert!(linear_webhook_automation_matches(
            &["Issue:create".into()],
            &[],
            Some("Issue"),
            &payload
        ));
        assert!(!linear_webhook_automation_matches(
            &["Project".into()],
            &[],
            Some("Issue"),
            &payload
        ));
    }

    #[test]
    fn linear_webhook_issue_identifier_reads_data_or_url() {
        let payload = linear_webhook_payload_struct(current_unix_timestamp_millis());
        assert_eq!(
            linear_webhook_issue_identifier(&payload).as_deref(),
            Some("JB-1")
        );

        let mut payload_without_identifier = payload;
        payload_without_identifier.data = serde_json::json!({
            "id": "issue-123",
            "title": "Passive webhook smoke test"
        });
        assert_eq!(
            linear_webhook_issue_identifier(&payload_without_identifier).as_deref(),
            Some("JB-1")
        );
    }

    #[test]
    fn linear_webhook_automation_match_supports_issue_prefix_filters() {
        let payload = linear_webhook_payload_struct(current_unix_timestamp_millis());

        assert!(linear_webhook_automation_matches(
            &["Issue:create".into()],
            &["JB".into()],
            Some("Issue"),
            &payload
        ));
        assert!(linear_webhook_automation_matches(
            &["Issue:create".into()],
            &["JB-".into()],
            Some("Issue"),
            &payload
        ));
        assert!(!linear_webhook_automation_matches(
            &["Issue:create".into()],
            &["SEC".into()],
            Some("Issue"),
            &payload
        ));
    }

    #[test]
    fn linear_webhook_automation_message_includes_payload_details() {
        let payload = linear_webhook_payload_struct(current_unix_timestamp_millis());
        let message =
            build_linear_webhook_automation_message(Some("delivery-123"), Some("Issue"), &payload);

        assert!(message.contains("verified Linear webhook event"));
        assert!(message.contains("\"delivery_id\": \"delivery-123\""));
        assert!(message.contains("\"type\": \"Issue\""));
        assert!(message.contains("\"identifier\": \"JB-1\""));
    }

    #[test]
    fn bluedot_webhook_automation_message_directs_linear_lookup() {
        let payload: BluedotWebhookPayload =
            serde_json::from_str(&bluedot_transcript_payload()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("bluedot.db");
        let store = BluedotMeetingStore::new(&db_path.to_string_lossy(), 365, 100).unwrap();
        let meeting = store.upsert_webhook_payload(&payload).unwrap();
        let message = build_bluedot_webhook_automation_message(Some("msg-123"), &payload, &meeting);

        assert!(message.contains("verified Bluedot transcript webhook"));
        assert!(message.contains("bluedot_meeting tool"));
        assert!(message.contains("Linear issues or projects"));
        assert!(message.contains("Likely Project"));
        assert!(message.contains("Write Recommendation"));
        assert!(message.contains("video-123"));
    }

    #[test]
    fn bluedot_webhook_automation_match_supports_title_and_attendee_filters() {
        let meeting = crate::bluedot::MeetingRecord {
            video_id: "video-123".into(),
            meeting_id: Some("meeting-123".into()),
            title: "Sprint Planning With Burnt".into(),
            created_at: current_unix_timestamp_millis() / 1000,
            duration_secs: Some(1800.0),
            attendees: vec!["pm@burnt.com".into(), "eng@burnt.com".into()],
            summary: Some("Planning".into()),
            transcript: vec![],
        };

        assert!(bluedot_webhook_automation_matches(
            &["sprint".into()],
            &[],
            &meeting
        ));
        assert!(bluedot_webhook_automation_matches(
            &[],
            &["PM@BURNT.COM".into()],
            &meeting
        ));
        assert!(bluedot_webhook_automation_matches(
            &["burnt".into()],
            &["eng@burnt.com".into()],
            &meeting
        ));
        assert!(!bluedot_webhook_automation_matches(
            &["customer".into()],
            &[],
            &meeting
        ));
        assert!(!bluedot_webhook_automation_matches(
            &[],
            &["sales@burnt.com".into()],
            &meeting
        ));
    }

    #[tokio::test]
    async fn linear_webhook_returns_not_found_when_not_configured() {
        let state = linear_webhook_test_state(Config::default(), Arc::new(MockMemory));

        let response = handle_linear_webhook(
            State(state),
            test_connect_info(),
            HeaderMap::new(),
            Bytes::from_static(br#"{}"#),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn linear_webhook_rejects_invalid_signature() {
        let secret = generate_test_secret();
        let mut config = Config::default();
        config.linear.webhook_enabled = true;
        config.linear.webhook_secret = Some(secret.clone());
        let state = linear_webhook_test_state(config, Arc::new(MockMemory));

        let payload = linear_webhook_payload(current_unix_timestamp_millis());
        let mut headers = HeaderMap::new();
        headers.insert("Linear-Signature", HeaderValue::from_static("deadbeef"));

        let response = handle_linear_webhook(
            State(state),
            test_connect_info(),
            headers,
            Bytes::from(payload),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn linear_webhook_rejects_stale_timestamp() {
        let secret = generate_test_secret();
        let mut config = Config::default();
        config.linear.webhook_enabled = true;
        config.linear.webhook_secret = Some(secret.clone());
        let state = linear_webhook_test_state(config, Arc::new(MockMemory));

        let payload = linear_webhook_payload(current_unix_timestamp_millis() - 120_000);
        let signature = compute_linear_signature_hex(&secret, payload.as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            "Linear-Signature",
            HeaderValue::from_str(&signature).unwrap(),
        );

        let response = handle_linear_webhook(
            State(state),
            test_connect_info(),
            headers,
            Bytes::from(payload),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn linear_webhook_autosaves_and_deduplicates_by_delivery_id() {
        let secret = generate_test_secret();
        let mut config = Config::default();
        config.linear.webhook_enabled = true;
        config.linear.webhook_secret = Some(secret.clone());

        let tracking_impl = Arc::new(TrackingMemory::default());
        let memory: Arc<dyn Memory> = tracking_impl.clone();
        let state = linear_webhook_test_state(config, memory);

        let payload = linear_webhook_payload(current_unix_timestamp_millis());
        let signature = compute_linear_signature_hex(&secret, payload.as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            "Linear-Signature",
            HeaderValue::from_str(&signature).unwrap(),
        );
        headers.insert(
            "Linear-Delivery",
            HeaderValue::from_static("234d1a4e-b617-4388-90fe-adc3633d6b72"),
        );
        headers.insert("Linear-Event", HeaderValue::from_static("Issue"));

        let first = handle_linear_webhook(
            State(state.clone()),
            test_connect_info(),
            headers.clone(),
            Bytes::from(payload.clone()),
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let second = handle_linear_webhook(
            State(state),
            test_connect_info(),
            headers,
            Bytes::from(payload),
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::OK);

        let keys = tracking_impl.keys.lock().clone();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0],
            "linear_webhook_234d1a4e-b617-4388-90fe-adc3633d6b72"
        );

        let payload = second.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["status"], "duplicate");
    }

    #[tokio::test]
    async fn bluedot_webhook_returns_not_found_when_not_configured() {
        let state = linear_webhook_test_state(Config::default(), Arc::new(MockMemory));

        let response = handle_bluedot_webhook(
            State(state),
            test_connect_info(),
            HeaderMap::new(),
            Bytes::from_static(br#"{}"#),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bluedot_webhook_rejects_invalid_signature() {
        let secret = generate_svix_secret();
        let mut config = Config::default();
        config.bluedot.webhook_enabled = true;
        config.bluedot.webhook_secret = Some(secret);
        let state = linear_webhook_test_state(config, Arc::new(MockMemory));

        let mut headers = HeaderMap::new();
        headers.insert("svix-id", HeaderValue::from_static("msg-1"));
        headers.insert(
            "svix-timestamp",
            HeaderValue::from_str(&(current_unix_timestamp_millis() / 1000).to_string()).unwrap(),
        );
        headers.insert("svix-signature", HeaderValue::from_static("v1,deadbeef"));

        let response = handle_bluedot_webhook(
            State(state),
            test_connect_info(),
            headers,
            Bytes::from(bluedot_summary_payload()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bluedot_webhook_rejects_stale_timestamp() {
        let secret = generate_svix_secret();
        let mut config = Config::default();
        config.bluedot.webhook_enabled = true;
        config.bluedot.webhook_secret = Some(secret.clone());
        let state = linear_webhook_test_state(config, Arc::new(MockMemory));

        let body = bluedot_summary_payload();
        let timestamp = (current_unix_timestamp_millis() / 1000) - 600;
        let signature = compute_bluedot_signature(&secret, "msg-1", timestamp, &body);
        let mut headers = HeaderMap::new();
        headers.insert("svix-id", HeaderValue::from_static("msg-1"));
        headers.insert(
            "svix-timestamp",
            HeaderValue::from_str(&timestamp.to_string()).unwrap(),
        );
        headers.insert("svix-signature", HeaderValue::from_str(&signature).unwrap());

        let response = handle_bluedot_webhook(
            State(state),
            test_connect_info(),
            headers,
            Bytes::from(body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bluedot_webhook_merges_summary_and_transcript() {
        let secret = generate_svix_secret();
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = Config::default();
        config.bluedot.webhook_enabled = true;
        config.bluedot.webhook_secret = Some(secret.clone());
        config.bluedot.db_path = tmp.path().join("bluedot.db").to_string_lossy().to_string();
        let state = linear_webhook_test_state(config.clone(), Arc::new(MockMemory));

        let summary_body = bluedot_summary_payload();
        let summary_timestamp = current_unix_timestamp_millis() / 1000;
        let summary_signature =
            compute_bluedot_signature(&secret, "msg-summary", summary_timestamp, &summary_body);
        let mut summary_headers = HeaderMap::new();
        summary_headers.insert("svix-id", HeaderValue::from_static("msg-summary"));
        summary_headers.insert(
            "svix-timestamp",
            HeaderValue::from_str(&summary_timestamp.to_string()).unwrap(),
        );
        summary_headers.insert(
            "svix-signature",
            HeaderValue::from_str(&summary_signature).unwrap(),
        );

        let first = handle_bluedot_webhook(
            State(state.clone()),
            test_connect_info(),
            summary_headers,
            Bytes::from(summary_body),
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let transcript_body = bluedot_transcript_payload();
        let transcript_timestamp = current_unix_timestamp_millis() / 1000;
        let transcript_signature = compute_bluedot_signature(
            &secret,
            "msg-transcript",
            transcript_timestamp,
            &transcript_body,
        );
        let mut transcript_headers = HeaderMap::new();
        transcript_headers.insert("svix-id", HeaderValue::from_static("msg-transcript"));
        transcript_headers.insert(
            "svix-timestamp",
            HeaderValue::from_str(&transcript_timestamp.to_string()).unwrap(),
        );
        transcript_headers.insert(
            "svix-signature",
            HeaderValue::from_str(&transcript_signature).unwrap(),
        );

        let second = handle_bluedot_webhook(
            State(state.clone()),
            test_connect_info(),
            transcript_headers.clone(),
            Bytes::from(transcript_body.clone()),
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::OK);

        let duplicate = handle_bluedot_webhook(
            State(state),
            test_connect_info(),
            transcript_headers,
            Bytes::from(transcript_body),
        )
        .await
        .into_response();
        assert_eq!(duplicate.status(), StatusCode::OK);

        let duplicate_payload = duplicate.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&duplicate_payload).unwrap();
        assert_eq!(parsed["status"], "duplicate");

        let store = BluedotMeetingStore::new(
            &config.bluedot.db_path,
            config.bluedot.retention_days,
            config.bluedot.max_meetings,
        )
        .unwrap();
        let meeting = store.get("video-123").unwrap().unwrap();
        assert_eq!(
            meeting.summary.as_deref(),
            Some("Reviewed the meeting transcript integration.")
        );
        assert_eq!(meeting.transcript.len(), 2);
        assert_eq!(meeting.attendees.len(), 2);
    }

    #[tokio::test]
    async fn bluedot_webhook_automation_enqueues_only_for_transcript_events() {
        let secret = generate_svix_secret();
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = Config::default();
        config.bluedot.webhook_enabled = true;
        config.bluedot.webhook_secret = Some(secret.clone());
        config.bluedot.webhook_automation_enabled = true;
        config.bluedot.db_path = tmp.path().join("bluedot.db").to_string_lossy().to_string();
        let state = linear_webhook_test_state(config, Arc::new(MockMemory));

        let summary_body = bluedot_summary_payload();
        let summary_timestamp = current_unix_timestamp_millis() / 1000;
        let summary_signature = compute_bluedot_signature(
            &secret,
            "msg-summary-auto",
            summary_timestamp,
            &summary_body,
        );
        let mut summary_headers = HeaderMap::new();
        summary_headers.insert("svix-id", HeaderValue::from_static("msg-summary-auto"));
        summary_headers.insert(
            "svix-timestamp",
            HeaderValue::from_str(&summary_timestamp.to_string()).unwrap(),
        );
        summary_headers.insert(
            "svix-signature",
            HeaderValue::from_str(&summary_signature).unwrap(),
        );

        let summary_response = handle_bluedot_webhook(
            State(state.clone()),
            test_connect_info(),
            summary_headers,
            Bytes::from(summary_body),
        )
        .await
        .into_response();
        assert_eq!(summary_response.status(), StatusCode::OK);
        let summary_payload = summary_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let summary_json: serde_json::Value = serde_json::from_slice(&summary_payload).unwrap();
        assert_eq!(summary_json["automation_enqueued"], false);

        let transcript_body = bluedot_transcript_payload();
        let transcript_timestamp = current_unix_timestamp_millis() / 1000;
        let transcript_signature = compute_bluedot_signature(
            &secret,
            "msg-transcript-auto",
            transcript_timestamp,
            &transcript_body,
        );
        let mut transcript_headers = HeaderMap::new();
        transcript_headers.insert("svix-id", HeaderValue::from_static("msg-transcript-auto"));
        transcript_headers.insert(
            "svix-timestamp",
            HeaderValue::from_str(&transcript_timestamp.to_string()).unwrap(),
        );
        transcript_headers.insert(
            "svix-signature",
            HeaderValue::from_str(&transcript_signature).unwrap(),
        );

        let transcript_response = handle_bluedot_webhook(
            State(state),
            test_connect_info(),
            transcript_headers,
            Bytes::from(transcript_body),
        )
        .await
        .into_response();
        assert_eq!(transcript_response.status(), StatusCode::OK);
        let transcript_payload = transcript_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let transcript_json: serde_json::Value =
            serde_json::from_slice(&transcript_payload).unwrap();
        assert_eq!(transcript_json["automation_enqueued"], true);
    }

    #[tokio::test]
    async fn bluedot_webhook_automation_respects_title_filters() {
        let secret = generate_svix_secret();
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = Config::default();
        config.bluedot.webhook_enabled = true;
        config.bluedot.webhook_secret = Some(secret.clone());
        config.bluedot.webhook_automation_enabled = true;
        config.bluedot.webhook_automation_title_keywords = vec!["customer".into()];
        config.bluedot.db_path = tmp.path().join("bluedot.db").to_string_lossy().to_string();
        let state = linear_webhook_test_state(config, Arc::new(MockMemory));

        let transcript_body = bluedot_transcript_payload();
        let transcript_timestamp = current_unix_timestamp_millis() / 1000;
        let transcript_signature = compute_bluedot_signature(
            &secret,
            "msg-transcript-filtered",
            transcript_timestamp,
            &transcript_body,
        );
        let mut transcript_headers = HeaderMap::new();
        transcript_headers.insert(
            "svix-id",
            HeaderValue::from_static("msg-transcript-filtered"),
        );
        transcript_headers.insert(
            "svix-timestamp",
            HeaderValue::from_str(&transcript_timestamp.to_string()).unwrap(),
        );
        transcript_headers.insert(
            "svix-signature",
            HeaderValue::from_str(&transcript_signature).unwrap(),
        );

        let transcript_response = handle_bluedot_webhook(
            State(state),
            test_connect_info(),
            transcript_headers,
            Bytes::from(transcript_body),
        )
        .await
        .into_response();
        assert_eq!(transcript_response.status(), StatusCode::OK);
        let transcript_payload = transcript_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let transcript_json: serde_json::Value =
            serde_json::from_slice(&transcript_payload).unwrap();
        assert_eq!(transcript_json["automation_enqueued"], false);
    }

    fn compute_nextcloud_signature_hex(secret: &str, random: &str, body: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let payload = format!("{random}{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[tokio::test]
    async fn nextcloud_talk_webhook_returns_not_found_when_not_configured() {
        let provider: Arc<dyn Provider> = Arc::new(MockProvider::default());
        let memory: Arc<dyn Memory> = Arc::new(MockMemory);

        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider,
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: false,
            webhook_secret_hash: None,
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: None,
            nextcloud_talk_webhook_secret: None,
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let response = Box::pin(handle_nextcloud_talk_webhook(
            State(state),
            HeaderMap::new(),
            Bytes::from_static(br#"{"type":"message"}"#),
        ))
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nextcloud_talk_webhook_rejects_invalid_signature() {
        let provider_impl = Arc::new(MockProvider::default());
        let provider: Arc<dyn Provider> = provider_impl.clone();
        let memory: Arc<dyn Memory> = Arc::new(MockMemory);

        let channel = Arc::new(NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            String::new(),
            vec!["*".into()],
        ));

        let secret = "nextcloud-test-secret";
        let random = "seed-value";
        let body = r#"{"type":"message","object":{"token":"room-token"},"message":{"actorType":"users","actorId":"user_a","message":"hello"}}"#;
        let _valid_signature = compute_nextcloud_signature_hex(secret, random, body);
        let invalid_signature = "deadbeef";

        let state = AppState {
            config: Arc::new(Mutex::new(Config::default())),
            provider,
            model: "test-model".into(),
            temperature: 0.0,
            mem: memory,
            auto_save: false,
            webhook_secret_hash: None,
            pairing: Arc::new(PairingGuard::new(false, &[])),
            trust_forwarded_headers: false,
            rate_limiter: Arc::new(GatewayRateLimiter::new(100, 100, 100)),
            auth_limiter: Arc::new(auth_rate_limit::AuthRateLimiter::new()),
            idempotency_store: Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000)),
            whatsapp: None,
            whatsapp_app_secret: None,
            linq: None,
            linq_signing_secret: None,
            nextcloud_talk: Some(channel),
            nextcloud_talk_webhook_secret: Some(Arc::from(secret)),
            wati: None,
            gmail_push: None,
            observer: Arc::new(crate::observability::NoopObserver),
            tools_registry: Arc::new(Vec::new()),
            cost_tracker: None,
            event_tx: tokio::sync::broadcast::channel(16).0,
            event_buffer: Arc::new(sse::EventBuffer::new(16)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            node_registry: Arc::new(nodes::NodeRegistry::new(16)),
            path_prefix: String::new(),
            session_backend: None,
            session_queue: std::sync::Arc::new(
                crate::gateway::session_queue::SessionActorQueue::new(8, 30, 600),
            ),
            device_registry: None,
            pending_pairings: None,
            canvas_store: CanvasStore::new(),
            webhook_automation_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            #[cfg(feature = "webauthn")]
            webauthn: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Nextcloud-Talk-Random",
            HeaderValue::from_str(random).unwrap(),
        );
        headers.insert(
            "X-Nextcloud-Talk-Signature",
            HeaderValue::from_str(invalid_signature).unwrap(),
        );

        let response = Box::pin(handle_nextcloud_talk_webhook(
            State(state),
            headers,
            Bytes::from(body),
        ))
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(provider_impl.calls.load(Ordering::SeqCst), 0);
    }

    // ══════════════════════════════════════════════════════════
    // WhatsApp Signature Verification Tests (CWE-345 Prevention)
    // ══════════════════════════════════════════════════════════

    fn compute_whatsapp_signature_hex(secret: &str, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn compute_whatsapp_signature_header(secret: &str, body: &[u8]) -> String {
        format!("sha256={}", compute_whatsapp_signature_hex(secret, body))
    }

    #[test]
    fn whatsapp_signature_valid() {
        let app_secret = generate_test_secret();
        let body = b"test body content";

        let signature_header = compute_whatsapp_signature_header(&app_secret, body);

        assert!(verify_whatsapp_signature(
            &app_secret,
            body,
            &signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_invalid_wrong_secret() {
        let app_secret = generate_test_secret();
        let wrong_secret = generate_test_secret();
        let body = b"test body content";

        let signature_header = compute_whatsapp_signature_header(&wrong_secret, body);

        assert!(!verify_whatsapp_signature(
            &app_secret,
            body,
            &signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_invalid_wrong_body() {
        let app_secret = generate_test_secret();
        let original_body = b"original body";
        let tampered_body = b"tampered body";

        let signature_header = compute_whatsapp_signature_header(&app_secret, original_body);

        // Verify with tampered body should fail
        assert!(!verify_whatsapp_signature(
            &app_secret,
            tampered_body,
            &signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_missing_prefix() {
        let app_secret = generate_test_secret();
        let body = b"test body";

        // Signature without "sha256=" prefix
        let signature_header = "abc123def456";

        assert!(!verify_whatsapp_signature(
            &app_secret,
            body,
            signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_empty_header() {
        let app_secret = generate_test_secret();
        let body = b"test body";

        assert!(!verify_whatsapp_signature(&app_secret, body, ""));
    }

    #[test]
    fn whatsapp_signature_invalid_hex() {
        let app_secret = generate_test_secret();
        let body = b"test body";

        // Invalid hex characters
        let signature_header = "sha256=not_valid_hex_zzz";

        assert!(!verify_whatsapp_signature(
            &app_secret,
            body,
            signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_empty_body() {
        let app_secret = generate_test_secret();
        let body = b"";

        let signature_header = compute_whatsapp_signature_header(&app_secret, body);

        assert!(verify_whatsapp_signature(
            &app_secret,
            body,
            &signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_unicode_body() {
        let app_secret = generate_test_secret();
        let body = "Hello 🦀 World".as_bytes();

        let signature_header = compute_whatsapp_signature_header(&app_secret, body);

        assert!(verify_whatsapp_signature(
            &app_secret,
            body,
            &signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_json_payload() {
        let app_secret = generate_test_secret();
        let body = br#"{"entry":[{"changes":[{"value":{"messages":[{"from":"1234567890","text":{"body":"Hello"}}]}}]}]}"#;

        let signature_header = compute_whatsapp_signature_header(&app_secret, body);

        assert!(verify_whatsapp_signature(
            &app_secret,
            body,
            &signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_case_sensitive_prefix() {
        let app_secret = generate_test_secret();
        let body = b"test body";

        let hex_sig = compute_whatsapp_signature_hex(&app_secret, body);

        // Wrong case prefix should fail
        let wrong_prefix = format!("SHA256={hex_sig}");
        assert!(!verify_whatsapp_signature(&app_secret, body, &wrong_prefix));

        // Correct prefix should pass
        let correct_prefix = format!("sha256={hex_sig}");
        assert!(verify_whatsapp_signature(
            &app_secret,
            body,
            &correct_prefix
        ));
    }

    #[test]
    fn whatsapp_signature_truncated_hex() {
        let app_secret = generate_test_secret();
        let body = b"test body";

        let hex_sig = compute_whatsapp_signature_hex(&app_secret, body);
        let truncated = &hex_sig[..32]; // Only half the signature
        let signature_header = format!("sha256={truncated}");

        assert!(!verify_whatsapp_signature(
            &app_secret,
            body,
            &signature_header
        ));
    }

    #[test]
    fn whatsapp_signature_extra_bytes() {
        let app_secret = generate_test_secret();
        let body = b"test body";

        let hex_sig = compute_whatsapp_signature_hex(&app_secret, body);
        let extended = format!("{hex_sig}deadbeef");
        let signature_header = format!("sha256={extended}");

        assert!(!verify_whatsapp_signature(
            &app_secret,
            body,
            &signature_header
        ));
    }

    // ══════════════════════════════════════════════════════════
    // IdempotencyStore Edge-Case Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn idempotency_store_allows_different_keys() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 100);
        assert!(store.record_if_new("key-a"));
        assert!(store.record_if_new("key-b"));
        assert!(store.record_if_new("key-c"));
        assert!(store.record_if_new("key-d"));
    }

    #[test]
    fn idempotency_store_max_keys_clamped_to_one() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 0);
        assert!(store.record_if_new("only-key"));
        assert!(!store.record_if_new("only-key"));
    }

    #[test]
    fn idempotency_store_rapid_duplicate_rejected() {
        let store = IdempotencyStore::new(Duration::from_secs(300), 100);
        assert!(store.record_if_new("rapid"));
        assert!(!store.record_if_new("rapid"));
    }

    #[test]
    fn idempotency_store_accepts_after_ttl_expires() {
        let store = IdempotencyStore::new(Duration::from_millis(1), 100);
        assert!(store.record_if_new("ttl-key"));
        std::thread::sleep(Duration::from_millis(10));
        assert!(store.record_if_new("ttl-key"));
    }

    #[test]
    fn idempotency_store_eviction_preserves_newest() {
        let store = IdempotencyStore::new(Duration::from_secs(300), 1);
        assert!(store.record_if_new("old-key"));
        std::thread::sleep(Duration::from_millis(2));
        assert!(store.record_if_new("new-key"));

        let keys = store.keys.lock();
        assert_eq!(keys.len(), 1);
        assert!(!keys.contains_key("old-key"));
        assert!(keys.contains_key("new-key"));
    }

    #[test]
    fn rate_limiter_allows_after_window_expires() {
        let window = Duration::from_millis(50);
        let limiter = SlidingWindowRateLimiter::new(2, window, 100);
        assert!(limiter.allow("ip-1"));
        assert!(limiter.allow("ip-1"));
        assert!(!limiter.allow("ip-1")); // blocked

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));

        // Should be allowed again
        assert!(limiter.allow("ip-1"));
    }

    #[test]
    fn rate_limiter_independent_keys_tracked_separately() {
        let limiter = SlidingWindowRateLimiter::new(2, Duration::from_secs(60), 100);
        assert!(limiter.allow("ip-1"));
        assert!(limiter.allow("ip-1"));
        assert!(!limiter.allow("ip-1")); // ip-1 blocked

        // ip-2 should still work
        assert!(limiter.allow("ip-2"));
        assert!(limiter.allow("ip-2"));
        assert!(!limiter.allow("ip-2")); // ip-2 now blocked
    }

    #[test]
    fn rate_limiter_exact_boundary_at_max_keys() {
        let limiter = SlidingWindowRateLimiter::new(10, Duration::from_secs(60), 3);
        assert!(limiter.allow("ip-1"));
        assert!(limiter.allow("ip-2"));
        assert!(limiter.allow("ip-3"));
        // At capacity now
        assert!(limiter.allow("ip-4")); // should evict ip-1

        let guard = limiter.requests.lock();
        assert_eq!(guard.0.len(), 3);
        assert!(
            !guard.0.contains_key("ip-1"),
            "ip-1 should have been evicted"
        );
        assert!(guard.0.contains_key("ip-2"));
        assert!(guard.0.contains_key("ip-3"));
        assert!(guard.0.contains_key("ip-4"));
    }

    #[test]
    fn gateway_rate_limiter_pair_and_webhook_are_independent() {
        let limiter = GatewayRateLimiter::new(2, 3, 100);

        // Exhaust pair limit
        assert!(limiter.allow_pair("ip-1"));
        assert!(limiter.allow_pair("ip-1"));
        assert!(!limiter.allow_pair("ip-1")); // pair blocked

        // Webhook should still work
        assert!(limiter.allow_webhook("ip-1"));
        assert!(limiter.allow_webhook("ip-1"));
        assert!(limiter.allow_webhook("ip-1"));
        assert!(!limiter.allow_webhook("ip-1")); // webhook now blocked
    }

    #[test]
    fn rate_limiter_single_key_max_allows_one_request() {
        let limiter = SlidingWindowRateLimiter::new(5, Duration::from_secs(60), 1);
        assert!(limiter.allow("ip-1"));
        assert!(limiter.allow("ip-2")); // evicts ip-1

        let guard = limiter.requests.lock();
        assert_eq!(guard.0.len(), 1);
        assert!(guard.0.contains_key("ip-2"));
        assert!(!guard.0.contains_key("ip-1"));
    }

    #[test]
    fn rate_limiter_concurrent_access_safe() {
        use std::sync::Arc;

        let limiter = Arc::new(SlidingWindowRateLimiter::new(
            1000,
            Duration::from_secs(60),
            1000,
        ));
        let mut handles = Vec::new();

        for i in 0..10 {
            let limiter = limiter.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..100 {
                    limiter.allow(&format!("thread-{i}-req-{j}"));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should not panic or deadlock
        let guard = limiter.requests.lock();
        assert!(guard.0.len() <= 1000, "should respect max_keys");
    }

    #[test]
    fn idempotency_store_concurrent_access_safe() {
        use std::sync::Arc;

        let store = Arc::new(IdempotencyStore::new(Duration::from_secs(300), 1000));
        let mut handles = Vec::new();

        for i in 0..10 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..100 {
                    store.record_if_new(&format!("thread-{i}-key-{j}"));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let keys = store.keys.lock();
        assert!(keys.len() <= 1000, "should respect max_keys");
    }

    #[test]
    fn rate_limiter_rapid_burst_then_cooldown() {
        let limiter = SlidingWindowRateLimiter::new(5, Duration::from_millis(50), 100);

        // Burst: use all 5 requests
        for _ in 0..5 {
            assert!(limiter.allow("burst-ip"));
        }
        assert!(!limiter.allow("burst-ip")); // 6th should fail

        // Cooldown
        std::thread::sleep(Duration::from_millis(60));

        // Should be allowed again
        assert!(limiter.allow("burst-ip"));
    }

    #[test]
    fn require_localhost_accepts_ipv4_loopback() {
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        assert!(require_localhost(&peer).is_ok());
    }

    #[test]
    fn require_localhost_accepts_ipv6_loopback() {
        let peer = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 12345));
        assert!(require_localhost(&peer).is_ok());
    }

    #[test]
    fn require_localhost_rejects_non_loopback_ipv4() {
        let peer = SocketAddr::from(([192, 168, 1, 100], 12345));
        let err = require_localhost(&peer).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn require_localhost_rejects_non_loopback_ipv6() {
        let peer = SocketAddr::from((
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            12345,
        ));
        let err = require_localhost(&peer).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
