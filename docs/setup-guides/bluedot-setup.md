# Bluedot Setup

This guide covers Bluedot webhook ingest and the `bluedot_meeting` tool for stored meeting summaries and transcripts.

## 1. What this integration does

- Exposes the `bluedot_meeting` tool for recent-meeting lookup, transcript search, and transcript pagination.
- Receives inbound Bluedot webhooks on `POST /bluedot`.
- Verifies Svix signatures before storing meeting data.
- Merges summary and transcript events into one meeting record keyed by `videoId`.
- Stores meeting data in a dedicated SQLite database instead of generic memory autosave.

## 2. Recommended configuration

Add this to `~/.zeroclaw/config.toml`:

```toml
[bluedot]
enabled = true
webhook_enabled = true
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
- V1 is passive ingest plus query tooling only. It does not auto-run the agent on new meetings.

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
