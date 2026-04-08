# Linear Setup

This guide covers Linear API access, write approvals, inbound webhooks, and scoped webhook automation for ZeroClaw.

## 1. What this integration does

- Exposes the `linear` tool for issue, project, team, user, and workflow state access.
- Gates mutating Linear actions behind the `linear.write` approval key.
- Receives inbound Linear webhooks via `POST /linear`.
- Verifies `Linear-Signature`, checks `webhookTimestamp`, and deduplicates by `Linear-Delivery`.
- Optionally runs background agent automation for selected webhook events.

## 2. Recommended configuration

Add this to `~/.zeroclaw/config.toml`:

```toml
[linear]
enabled = true
allowed_actions = [
  "get_issue",
  "search_issues",
  "list_comments",
  "get_project",
  "search_projects",
  "list_teams",
  "list_users",
  "list_workflow_states",
  "create_comment",
  "create_issue",
  "update_issue",
  "update_project",
  "graphql_query",
  "graphql_mutation",
]
webhook_enabled = true
webhook_automation_enabled = true
webhook_automation_events = ["Issue:create", "Issue:update", "Comment"]
webhook_automation_issue_prefixes = ["JB"]

[autonomy]
always_ask = ["linear.write"]
```

Recommended environment variables:

```bash
export LINEAR_API_KEY='lin_api_...'
export LINEAR_WEBHOOK_SECRET='whsec_...'
```

Notes:

- `LINEAR_API_KEY` overrides `linear.api_key`.
- `LINEAR_WEBHOOK_SECRET` overrides `linear.webhook_secret`.
- `always_ask = ["linear.write"]` keeps all Linear writes approval-gated, including curated writes and raw `graphql_mutation`.
- `webhook_automation_issue_prefixes = ["JB"]` limits background automation to issues like `JB-123`.

## 3. Gateway endpoint

Run the daemon or gateway and expose the webhook endpoint:

```bash
zeroclaw daemon
# or
zeroclaw gateway start --host 127.0.0.1 --port 3000
```

Configure your Linear webhook URL to:

- `https://<your-public-url>/linear`

## 4. Webhook security contract

ZeroClaw follows Linear's documented webhook contract:

- header `Linear-Signature`
- header `Linear-Delivery`
- header `Linear-Event`
- body field `webhookTimestamp`

Verification behavior:

- signature: HMAC-SHA256 over the raw request body using the webhook signing secret
- replay guard: webhook timestamp must be within 60 seconds
- duplicate suppression: repeated `Linear-Delivery` values are acknowledged as duplicates

If verification fails, the gateway returns `401 Unauthorized`.

## 5. Automation behavior

When `webhook_automation_enabled = true`, ZeroClaw:

1. verifies and parses the webhook
2. checks the configured event filters
3. checks `webhook_automation_issue_prefixes` when configured
4. enqueues a background agent run through the normal non-interactive gateway path
5. stores the automation result in memory under category `linear_webhook_automation`

Current behavior is intentionally conservative:

- webhook requests are acknowledged immediately
- automation runs in the background
- results are stored, not posted back to Linear automatically

## 6. Quick validation checklist

1. Set `LINEAR_API_KEY` and `LINEAR_WEBHOOK_SECRET`.
2. Start the gateway and confirm it prints `POST /linear`.
3. In Linear, configure a webhook that targets your public `/linear` URL.
4. Trigger a `JB-*` issue create or update event.
5. Confirm the gateway accepts the webhook and stores the event.
6. If automation is enabled, confirm a `linear_webhook_automation` memory entry is created.

## 7. Safe first rollout

Use this rollout order:

1. enable the API tool only
2. enable passive webhooks
3. enable automation with `webhook_automation_issue_prefixes = ["JB"]`
4. expand prefixes only after reviewing stored automation results

## 8. Troubleshooting

- `404 Linear webhook not configured`: `linear.webhook_enabled` is not enabled.
- `401 Invalid signature`: `LINEAR_WEBHOOK_SECRET` or `linear.webhook_secret` does not match the webhook signing secret.
- `401 Invalid webhook timestamp`: request arrived outside the 60-second replay window.
- webhook `200` but no automation run: event filter or issue-prefix scope did not match.
- Linear writes prompt unexpectedly: `linear.write` is in `always_ask`, which is the recommended production setting.

Reference:

- Linear webhook documentation: <https://linear.app/developers/webhooks>
