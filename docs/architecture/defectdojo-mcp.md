# DefectDojo MCP server

Configurable Model Context Protocol server over the DefectDojo REST API v2. Built for BARAD-DÛR: the HTTP client is a plain library, the MCP layer is a thin wrapper on top.

```
LLM client ──stdio/JSON-RPC──▶ defectdojo_mcp.server   (tools, capability gating)
                                      │
                                      ▼
                               defectdojo_mcp.client   (stdlib only, no MCP dependency)
                                      │  HTTPS + "Authorization: Token …"
                                      ▼
                               DefectDojo API v2  ──▶  Postgres
```

The database is never written to directly. DefectDojo's own logic (parsers, deduplication, status invariants, risk acceptance, notifications) only runs through the API, so every write goes through it.

## Why not the built-in server

DefectDojo CE has **no** MCP server; it is a Pro-only feature (confirmed in the official feature comparison and by inspecting the running 3.4.202 code: no MCP module, route or dependency). This component keeps the free, self-hosted edition viable.

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `DEFECTDOJO_URL` | yes | — | Base URL, e.g. `http://127.0.0.1:18082` |
| `DEFECTDOJO_API_TOKEN` | yes¹ | — | API token; sent as `Authorization: Token …` |
| `DEFECTDOJO_API_TOKEN_FILE` | yes¹ | — | Alternative: path to a file containing the token |
| `DEFECTDOJO_ALLOW_WRITE` | no | `false` | Registers the write tools |
| `DEFECTDOJO_ALLOW_REMOTE` | no | `false` | Permits a non-loopback host |
| `DEFECTDOJO_INSECURE_SKIP_TLS_VERIFY` | no | `false` | Disables TLS verification |
| `DEFECTDOJO_TIMEOUT` | no | `30` | HTTP timeout, seconds |
| `DEFECTDOJO_MAX_LIMIT` | no | `100` | Page size for list calls |
| `MCP_TRANSPORT` | no | `stdio` | `stdio`, `sse` or `streamable-http` |

¹ one of the two is required.

Refused at startup: `http://user:pass@host` (credentials in the URL), a URL with query/fragment, and a non-loopback host without `DEFECTDOJO_ALLOW_REMOTE=true`.

`python -m defectdojo_mcp` also reads a local `.env` from the working directory, filling only variables that are not already set. Values are never logged.

Security properties:

- The token is redacted from every raised message, including HTTP error bodies that echo it.
- Redirects are refused, so the token cannot be replayed to another location.
- Proxy environment variables are ignored, so the token is not forwarded to an unintended proxy.
- Pagination follows only the `offset` of the server's `next` link, never its host.
- Write tools are **absent** from `tools/list` when writes are disabled — a client cannot see a capability that was not granted.
- `create_finding` defaults to `active=true`, `verified=false`: created is not verified.

## API version: v2 (stable) vs v3 (alpha)

This component calls **API v2** (`/api/v2/...`). That is a deliberate choice, not an oversight.

DefectDojo 3.4.202 also ships an **API v3** under `dojo/api_v3`, marked *alpha* in the source and mounted only when `V3_FEATURE_LOCATIONS` is enabled:

```python
# dojo/urls.py
# API v3 (alpha) -- mounted conditionally on V3_FEATURE_LOCATIONS (D5/§4.1).
# With the flag off the whole /api/v3/ tree is absent.
if getattr(settings, "V3_FEATURE_LOCATIONS", False):
```

In this local instance the flag is on, so v3 is reachable — **without a trailing slash** (NinjaAPI routes have none: `/api/v3/findings`, not `/api/v3/findings/`).

| | v2 | v3 (alpha) |
|---|---|---|
| Status | stable contract | alpha, flag-gated |
| Auth | `Authorization: Token …` | same |
| Trailing slash | required on collection routes | **not** allowed |
| Coverage | findings, tests, engagements, products, product types, test types, notes + history, import/reimport, risk acceptance, dedup, tokens | assets, engagements, tests, findings, locations, organizations, users, `POST /import` |
| Verb coverage | full DRF set | GET/POST/PUT/PATCH/DELETE per entity |
| Shape | flat, foreign keys as ids | **nested** (`test`, `engagement`, `asset` inline) |
| Extras | parsers, notes, dedup | `export.csv` per entity, `expand`, `fields` |

Why the MCP stays on v2:

1. **Stability.** v3 is labelled alpha upstream; building a component that BARAD-DÛR depends on against an alpha contract invites silent breakage on minor upgrades.
2. **Coverage.** The write workflow needs test types (to resolve `found_by`), notes, and scan import semantics. v2 exposes all of them with documented behaviour; v3 covers a narrower model.
3. **Verified.** Every v2 endpoint used here was exercised against the running instance.

Single deliberate exception: **assets exist only in v3**, so `create_asset`/`update_asset` must write there. The alternative would be inventing an asset in the database, which is exactly what this component refuses to do. Everything else that persists findings or status stays on v2.

Where v3 is genuinely better: correlation reads. One `/api/v3/findings?expand=...` response already contains the finding, test, engagement and asset inline, which avoids the id-chasing that v2 requires. If BARAD-DÛR later needs heavy cross-entity traversal, adding a **read-only** v3 path alongside the v2 write path is the sensible split — not replacing v2.

## Tools

Read, always available (v2, stable):

| Tool | Purpose |
|---|---|
| `server_info` | base URL, write flag, TLS flag, allowed severities — never the token |
| `list_products` / `get_product` | products the token can see |
| `list_engagements` / `get_engagement` | engagements, filterable by product |
| `list_tests` / `get_test` | tests, filterable by engagement or test type |
| `list_test_types` | parser names, needed for `import_scan` |
| `list_findings` | filters: test, engagement, product, severity, active, verified, duplicate |
| `get_finding` | full record including evidence fields |

Read, v3 (alpha, nested):

| Tool | Purpose |
|---|---|
| `list_assets` / `get_asset` | assets and their organization — v3-only concept, absent from v2 |
| `list_findings_with_context` | findings with `test`, `engagement` and `asset` nested inline; supports `fields` and `expand` |
| `get_finding_with_context` | one finding with nested context |
| `list_organizations` | organizations |
| `list_locations` | locations — requires broader privileges than a product-scoped user has |

16 read tools in total, 23 with writes enabled. All v3 tools are read-only except asset creation/update, which has no v2 equivalent.

Write, only with `DEFECTDOJO_ALLOW_WRITE=true`:

| Tool | Purpose |
|---|---|
| `create_finding` | one hand-written finding in an existing test |
| `update_finding` | state/content changes on an allowlist of fields |
| `add_finding_note` | audit trail entry on a finding |
| `import_scan` | import a local report file; DefectDojo parses and deduplicates |
| `reimport_scan` | re-import into an existing test so findings update instead of duplicate |
| `create_asset` | create an asset in an organization — **the one v3 write**, because v2 has no asset concept |
| `update_asset` | change asset fields (v3) |

For scanner output (`Trivy`, `CycloneDX`, `Syft`) use `import_scan`/`reimport_scan`, not `create_finding`: only the import path runs the parser, the hash computation and the deduplication chain.

## Wiring a client

Claude Desktop / Claude Code (`claude_desktop_config.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "defectdojo": {
      "command": "/absolute/path/to/barad-dur/.venv/bin/python",
      "args": ["-m", "defectdojo_mcp"],
      "cwd": "/absolute/path/to/barad-dur",
      "env": {
        "DEFECTDOJO_URL": "http://127.0.0.1:18082",
        "DEFECTDOJO_API_TOKEN_FILE": "/absolute/path/to/barad-dur/.secrets/mcp-token.txt",
        "DEFECTDOJO_ALLOW_WRITE": "false"
      }
    }
  }
}
```

Prefer `DEFECTDOJO_API_TOKEN_FILE` over inline tokens: client config files are often plain text and sometimes committed by accident.

Start read-only. Enable writes only when you have a supervised process that never closes a finding without retest evidence.

## Reuse from BARAD-DÛR

The client has no third-party dependency, so it can be imported without the MCP SDK:

```python
from defectdojo_mcp.config import Settings
from defectdojo_mcp.client import Client

client = Client(Settings.from_env())
for finding in client.list_findings(product=1, severity="High"):
    ...
```

BARAD-DÛR's own correlation service should use exactly this client; the MCP server then reuses the same code path instead of duplicating integration logic.

## Real integration notes (verified against DefectDojo 3.4.202)

Two non-obvious behaviours cost time and are recorded here so nobody rediscovers them:

1. **Users must be `Dojo_User`, not `django.contrib.auth.models.User`.** DefectDojo uses multi-table inheritance. Creating a base `User` produces a login that authenticates but fails when assigning `authorized_users` with `TypeError: 'Dojo_User' instance expected`.
2. **Product visibility comes from `authorized_users`, not from role membership.** In 3.4.202 the filter is `Product.objects.filter(Q(authorized_users=user) | Q(prod_type__authorized_users=user))`. A `Product_Type_Member` with a role grants nothing for product listing; the user must be in `Product_Type.authorized_users` (or `Product.authorized_users`). Authorization results are cached, so clear the cache after changing assignments.

Verified with a dedicated least-privilege user (`barad-dur-mcp`, `Dojo_User`, `Writer` on the synthetic product type only): it lists its own product and **does not** see other product types, and a real finding plus note were created through the API.

## Limitations

- `/api/v3/locations` returns **403** for a product-scoped user (`Permission denied`) while `/api/v3/findings/{id}/locations` works and returns `[]`. That is expected: the global locations endpoint needs wider visibility. The tool surfaces the 403 verbatim rather than pretending the list is empty.
- v3 tools fail with an explicit `V3_FEATURE_LOCATIONS` message (not a bare 404) when an instance has the flag off.

- The MCP server reads local files for `import_scan`, so it must run on the host that holds the reports; it is not a remote upload service.
- `add_finding_note` returns the server response, which may omit the new note id; read `GET /api/v2/findings/{id}/notes/` when the id matters.
- No OAuth, no per-tool authorization beyond the capability gating described above, and no rate limiting.
- `stdio` is the tested transport; `sse`/`streamable-http` expose a network endpoint and need TLS and authentication in front before any real use.
- Token rotation is manual (`/api/v2/users/{id}/reset_api_token/`).
