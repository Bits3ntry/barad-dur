Everything a machine needs to talk to this platform, and the order to set it up in.

### Service identities (API keys)

Settings → **Service identities** issues keys. One rule decides how you treat them: **an API key is a full-organization owner and bypasses the role checks**. A key is not "a bot with limited rights" — it is the workspace. So:

- one key per consumer (CI, worker, MCP, a dashboard), named after its consumer;
- never in a browser profile you would not hand over, never in a commit, never in a screenshot;
- revoked from the same screen, immediately; the last active key cannot be revoked, which is a guard against locking yourself out;
- a key pasted into a chat is a key to rotate.

Every key's use shows up in the **Audit trail**, so "which consumer did this" has an answer.

### The local CLI (`barad`)

Three commands, no dashboard needed, no network needed:

| Command | Result | Remote effect |
|---|---|---|
| `barad scan [path]` | evidence in `.barad/reports/<project>/<version>/<scan-id>/` | none |
| `barad run [path]` | the same scan, then synchronize the enabled integrations | only what you configured |
| `barad health` | tool, config and endpoint checks | authenticated reads only |

```sh
python3 -m venv /tmp/barad-venv
/tmp/barad-venv/bin/python -m pip install .
/tmp/barad-venv/bin/barad health
/tmp/barad-venv/bin/barad scan . --out /tmp/evidence
```

Configuration is an optional `.barad.yml` in the invocation directory; credentials are environment variables, never YAML. `security.json` and `sast.json` can contain secrets and source excerpts: they stay owner-only.

### The scanner CLI (`shauron`)

The execution plane, described in its own chapter: `scan`, `plan`, `surface`, `upload`, `worker`, `agent`, `login`, `ticket`, `runtime`, `tools`, `doctor`. Use it when the console is not the right driver — CI, a fleet, or an offline run that uploads later.

### The CI action

`action/action.yml` in the Shauron repository is a composite action; the repository workflow uses the same CLI:

```yaml
- uses: actions/checkout@v4
- uses: ./action
  with:
    command: scan   # scan, run or health
    target: .
    config: config/ci.barad.yml
```

For `run`, put the integration credentials only in a trusted step or job. The action mints the ticket **before** the slow work, installs the pinned engines, then scans — so a failure is recorded as an abandoned run rather than as a run that never existed.

### The MCP server

`mcp/` ships `barad-mcp`, which exposes the platform's own tool catalogue to external agents (the same declarations the in-process executor uses, imported rather than copied). It needs the platform package installed beside it and a platform identity. An MCP caller acts as its own principal — it is not a second way to be an owner.

### Webhooks and Slack

Settings → **Notifications** creates **delivery channels**. Two kinds: `slack` (an incoming-webhook URL) and `webhook` (any receiver).

Each channel subscribes to events, toggled per row:

| Event | Fires when |
|---|---|
| `sla.breached` | a finding passed its deadline |
| `advisory.new` | the advisory sweep created findings the workspace did not have |

Three mechanics that explain the silence people report:

- the **signing secret is shown once**, at creation — copy it then;
- delivery is **deduplicated per channel per day**, so a channel that fired this morning stays quiet this afternoon;
- a webhook receiver inside a container must reach the host by a name it can resolve (`host.docker.internal`), and a port already taken by another listener fails silently — the old process answers, usually with a 404.

The **bell** in the console is the in-app centre and works with no channel configured. If you subscribed to nothing and expected nothing, that is correct.

### Email

Settings → **Delivery** configures the deployment's outgoing mail: host, port, sender, user, password, STARTTLS. One relay serves invitations and every email notification, which is why it is a deployment setting rather than an organization one. The screen always says which source is in effect (`database`, `environment` or `none`) and whether a password is stored — the password itself is write-only.

### Jira

Settings carry `JIRA_BASE_URL` and `JIRA_TOKEN` at the deployment level; the **Jira** screen then lists links between findings and tickets, creates one, pushes a status, and **reconciles** (re-reads the remote and reports drift). A missing configuration prints as *Jira not configured*, which is a deployment problem, not a console bug.

### Talking to the API directly

Every screen is a client of the same API. Two calls worth memorising:

```sh
# health, no auth
curl -s http://127.0.0.1:8090/healthz

# list findings as the workspace
curl -s -H "X-API-Key: $BARAD_API_KEY" \
  "http://127.0.0.1:8090/api/v1/findings?sort=severity&limit=20"
```

The OpenAPI document is served by the API itself (`/docs`), which is the authoritative list of routes — this chapter is a map, not a substitute.

### A minimal automation, end to end

1. Issue a key named after the consumer (Settings → Service identities).
2. Put it in the consumer's secret store.
3. Point the consumer at the platform's reachable address — `127.0.0.1:8090` is host-only on purpose, so a CI runner in another network needs the bound interface or a reverse proxy.
4. Do one read (`/healthz`, then a list) before writing anything.
5. Put the key's use in the audit trail by giving it a recognisable name, then read the trail once to confirm it is there.
