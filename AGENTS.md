# AGENTS.md — bring the POC up from a clone

This file is for an agent (or a person) who has just cloned the repository and has to
leave the demo **working**, not "mostly working". Read it top to bottom; every command is
meant to be run in this order, from the repo root.

What "working" means, in the four lanes the demo walks:

| Lane | What the operator types | What must happen |
|---|---|---|
| discovery | `descubrí la superficie de https://juice-shop.demo` | mission `discover` → morgoth → `recon.surface`; the thread shows the task and every `tool`/`observation`; the asset keeps the paths it answered |
| validation | `validame con una POC si el SQLi de Django sigue activo en https://juice-shop.demo` | mission `validate` with the target you named; the finding goes to `exploit_state: reproduced` with `validation_output` |
| validation (finding) | `validá <finding id>` | plan derived from the recorded proof, verdict in the thread, `promote` writes the row |
| exploit | `@morgoth explotá el bypass de login en https://juice-shop.demo` | `exploit.chain`, request/response and a verdict |

The chat is the harness: `#chat::<session id>` is addressable (an F5 keeps the thread),
and a mission renders under the turn that armed it — capability, profile, state, budget,
task status, attempts and every command with its answer.

## 0 · Prerequisites

- Docker (compose v2), Python 3.11+, Node 18+, `make`, `openssl`.
- A **lab host** the workers can reach: this repo does not ship one. The demo points at
  `juice-shop.demo`, resolved through `POC_TARGET_IP`, and the field agent trusts its CA
  from `POC_TLS_DIR`. If you do not have the lab, discovery and validation will report
  connection failures — that is the honest answer, not a bug.

## 1 · Configure

```bash
cp .env.example .env
# Fill every `change-me`: barad_db_password, SHAURON_BARAD_KEY (64 hex), BOOTSTRAP_TOKEN,
# POC_TARGET_IP, POC_TLS_DIR, and POC_DIR if your lab lives somewhere else.
set -a; source .env; set +a
```

`POC_TLS_DIR` must contain the lab's CA bundle (`ca-bundle.pem`); `scripts/poc_demo/tls_front.sh`
creates a self-signed one if you are standing up your own front.

## 2 · Stack

The demo stack is **three** compose files. Using only the base file on a later `up`
silently drops the lab alias and the CA, and then every mission fails with DNS/TLS errors:

```bash
docker compose -f compose.yaml -f compose.local.yaml -f compose.demo.yaml up -d --build
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/healthz   # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8092/         # 200 (console)
```

After any backend change, rebuild only what changed, always with the three files:

```bash
docker build -q -t barad-dur-platform-api ./backend
docker compose -f compose.yaml -f compose.local.yaml -f compose.demo.yaml \
  up -d --no-deps --no-build --force-recreate platform-api
```

After any UI change:

```bash
npm run build --prefix frontend && rsync -a --delete frontend/dist/ console_html/
```

`console_html/` is what the console container serves; the build alone changes nothing.

## 3 · First boot

1. Open `http://127.0.0.1:8092/` and claim the owner with `BOOTSTRAP_TOKEN`.
2. Settings → AI: add an OpenAI-compatible provider (base URL, model, key, prices) and
   mark it default. Without it every chat turn answers `no provider configured`.
3. Settings → Organisation: keep the owner email; the seed uses it as the project owner.

## 4 · Seed the estate

```bash
./.venv/bin/python scripts/poc_demo/make_repos.py          # the two lab repositories
./.venv/bin/python scripts/poc_demo/seed_platform.py       # project, versions, deployments, asset, scope, grant, cycle
bash scripts/poc_demo/run_scans.sh --new-only              # SBOM + CVEs + SAST (optional, ~4 min)
bash scripts/poc_demo/run_recon.sh                         # asset observations (optional)
```

`seed_platform.py` is addressed by slug: re-running reuses what exists and prints the ids.
It also creates the `redteam` grant on `juice-shop.demo` — **without that grant the chat
proposes the mission and the console shows "Aprobar y ejecutar" instead of running it.**

Everything from scratch (destroys only what the POC created, keeps keys and settings):

```bash
bash scripts/poc_demo/poc_build_demo.sh      # reset → seed → scans → recon
bash scripts/poc_demo/reset.sh               # wipe, with a backup under .barad/backups
```

## 5 · Verify before saying it works

```bash
# the estate answers
curl -s -H "X-API-Key: $SHAURON_BARAD_KEY" http://127.0.0.1:8090/api/v1/findings | head -c 200

# the lab is reachable *from inside the stack*, with its CA (no -k, ever)
docker exec barad-dur-agent-worker-1 curl -sS -o /dev/null -w '%{http_code}\n' https://juice-shop.demo/
```

Then, in the console, new chat (`#chat::<uuid>` appears in the address):

1. `descubrí la superficie de https://juice-shop.demo` → a strip says *ejecución en curso*,
   lines appear every 3 s, and in 2–3 min the thread gets **Informe de reconocimiento ·
   discovery**; the asset gains `web_path` observations whose source is `agent:recon`.
2. `validá <finding id>` → **VULNERABLE** in the thread and the finding reads `reproducido`
   with a `validation_output`.
3. `@morgoth explotá el bypass de login en https://juice-shop.demo y decime si entra como admin`
   → `exploit.chain` with the request and the answer.

## 6 · The pitfalls that cost a day each

- **Three compose files, always.** `platform-api` needs the lab alias and the CA because the
  replay gates run in that process; the workers need them because the field agent does.
- **Never `-k`.** The agent refuses to skip TLS on purpose. Fix trust: `SSL_CERT_FILE` and
  `CURL_CA_BUNDLE` point at `/lab-tls/ca-bundle.pem` inside the containers.
- **A field call needs the allowlist.** `refused: not in this task's allowlist` means the
  model asked for a tool the mission did not grant; check `mission.tools`.
- **Budget is a ceiling, not a spend.** Chat missions are armed with 12 steps / 60 000 tokens;
  a differential proof spends most of it before the verdict.
- **A lease renews on every event.** A run that is posting is alive; if you see
  `lease expired without a final event`, the worker died, not the platform.
- **A plan the operator approved reaches the field.** If a run ignores its steps, check
  `mission.evidence.plan` and the field system prompt (`_plan_brief`).
- **Nothing writes the human axis.** The machine moves `exploit_state`; `triage_status` is a
  person's decision.

## 7 · Where the rest is written down

- `docs/talks/poc-demo-15min/` — the 15-minute script: `comandos.md` (real commands, no
  wrappers), `grabacion.md` (recording order), `guion-poc.md` (the narrative).
- `docs/PLATFORM.md` — the platform's own quickstart.
- `scripts/poc_demo/` — every step above as a script, plus `reset.sql` and `reset_check.sql`.
- `backend/tests/` — 864 tests; `make lint` runs the linters and the UI import check.
