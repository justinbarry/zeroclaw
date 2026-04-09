# Bluedot Setup

This guide covers Bluedot webhook ingest and the `bluedot_meeting` tool for stored meeting summaries and transcripts.

## 1. What this integration does

- Exposes the `bluedot_meeting` tool for recent-meeting lookup, transcript search, and transcript pagination.
- Receives inbound Bluedot webhooks on `POST /bluedot`.
- Verifies Svix signatures before storing meeting data.
- Merges summary and transcript events into one meeting record keyed by `videoId`.
- Stores meeting data in a dedicated SQLite database instead of generic memory autosave.
- Can optionally auto-run the agent after transcript-ready events to look for related Linear issues and projects.

## 2. Recommended configuration

Add this to `~/.zeroclaw/config.toml`:

```toml
[bluedot]
enabled = true
webhook_enabled = true
webhook_automation_enabled = true
webhook_automation_agent = "project_manager"
allowed_actions = ["recent", "get", "search", "transcript"]
db_path = "~/.zeroclaw/bluedot-meetings.db"
retention_days = 365
max_meetings = 500
```

Recommended environment variable:

```bash
export BLUEDOT_WEBHOOK_SECRET='whsec_...'
```

Notes:

- `BLUEDOT_WEBHOOK_SECRET` overrides `bluedot.webhook_secret`.
- The SQLite store is separate from the standard memory backend.
- `webhook_automation_enabled = true` runs the agent only after transcript-ready Bluedot events.
- `webhook_automation_agent = "project_manager"` runs that named agent profile instead of the primary gateway agent.
- If `[agents.project_manager]` omits `provider` and `model`, it inherits the root `default_provider` and `default_model`, which is the right setup when the main agent already runs on Codex.
- The automation prompt tells the agent to inspect the meeting via `bluedot_meeting` and look for related Linear issues or projects.
- For the Linear lookup to work, enable the `linear` tool and allow read actions such as `search_issues` and `search_projects`.

## 3. Gateway endpoint

Run the daemon or gateway and expose the webhook endpoint:

```bash
zeroclaw daemon
# or
zeroclaw gateway start --host 127.0.0.1 --port 3000
```

Configure your Bluedot webhook URL to:

- `https://<your-public-url>/bluedot`

## 4. Webhook security contract

ZeroClaw expects Svix-style headers from Bluedot:

- `svix-id`
- `svix-timestamp`
- `svix-signature`

Verification behavior:

- signature: HMAC-SHA256 over `svix-id.svix-timestamp.raw_body`
- replay guard: timestamps older than 5 minutes are rejected
- duplicate suppression: repeated `svix-id` values are acknowledged as duplicates

If verification fails, the gateway returns `401 Unauthorized`.

## 5. Stored meeting data

Each meeting record is merged by `videoId` and can include:

- title
- meeting id / URL reference
- attendees
- summary
- full transcript

The `bluedot_meeting` tool supports:

- `recent`
- `get`
- `search`
- `transcript`

Use `transcript` when a meeting is too long for the inline transcript preview returned by `get`.

## 6. Backfill saved payloads

If you already have a directory of saved Bluedot webhook payload JSON files, import them directly:

```bash
zeroclaw bluedot import ./backfill/bluedot-payloads
```

Useful flags:

- `--dry-run` validates files and shows create/update counts without writing
- `--fail-fast` stops on the first invalid file or payload error

The importer walks directories recursively and reuses the same merge logic as live webhook ingest, so summary-first and transcript-first payloads both converge into the same meeting record.
