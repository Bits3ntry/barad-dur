# Slack notifications

A Slack channel is a notification channel with `kind: "slack"`. Slack's
**incoming webhooks** authenticate by the secret URL itself, so there is nothing
to install and no OAuth app to maintain.

## Configure it

1. In Slack: *Apps → Incoming Webhooks → Add to Slack*, pick the channel, copy
   the URL (`https://hooks.slack.com/services/T…/B…/…`).
2. In the console: `Administration → Notifications → Delivery channels`, kind
   **slack**, paste the URL, **add channel**.
3. Press **test**. A delivered test says `HTTP 200`; a rejection is reported with
   Slack's own body (`slack_rejected: invalid_payload`), never swallowed.

Or by API:

```bash
curl -X POST "$BARAD/api/v1/notifications/channels" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' -d '{
    "name": "sec-alerts", "kind": "slack",
    "url": "https://hooks.slack.com/services/T000/B000/xxxx",
    "events": ["sla.breached"], "actor": "ana@example.com"}'
```

## What gets sent

```json
{
  "text": "*sla.breached* · title: 2 findings past SLA · severity: HIGH · count: 2",
  "blocks": [
    {"type": "section", "text": {"type": "mrkdwn", "text": "…same line…"}},
    {"type": "context", "elements": [{"type": "mrkdwn",
      "text": "channel `sec-alerts` · event `sla.breached`"}]}
  ]
}
```

`text` is the fallback Slack shows in notifications and on clients that cannot
render blocks; the block carries the same content. The signed envelope used for
generic webhooks (`X-Barad-Signature`, `{"event", "channel", "payload"}`) is
**not** sent to Slack — Slack would ignore it and reject the payload.

Delivery results are recorded per channel (`GET /api/v1/notifications/deliveries`)
with HTTP status and error, and the test button reports the same fields.

## Local testing without Slack

The validation allows `http://127.0.0.1` / `http://localhost` targets so a
deployment can be exercised against a local mock:

```bash
python3 - <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.rfile.read(int(self.headers['Content-Length'])))
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 8123), H).serve_forever()
PY
```

Then create the channel with `http://127.0.0.1:8123/slack`. Anything else must be
https: the URL is the credential.

## Limits

- Only the events the product emits today (`sla.breached`, `test`) can be
  routed; per-finding notifications are not implemented.
- No Slack *app* features (slash commands, buttons that change a finding,
  threading). Those need a Slack app with OAuth and a public endpoint.
- `tick` (the loop that produces the digest) is invoked by the scheduler you
  run; Slack delivery does not schedule anything by itself.
