# Scope semantics (v0, implemented in `backend/app/scoping.py`)

This is the authoritative statement of what a scope row means. It is implemented
by `backend.app.scoping` and pinned by `backend/tests/test_v0_scope.py`. Any
change here is a change to the authorization surface and needs a migration plus
tests, not a code tweak.

## Two separate things

| Layer | Table | Answers |
|---|---|---|
| Declaration | `scope_targets`, `scope_exclusions` | what the organization says is in bounds |
| Authorization | `scan_grants` | what a specific principal may actually run, until when |

A scope row never launches anything. `capabilities` on a target records what a
future grant *may* be issued for; the collector still checks a grant.

## Types and normalization

| Type | Accepted value | Normalized to | Creates an asset? |
|---|---|---|---|
| `domain` | `example.com`, `*.example.com` | lowercase, trailing dot dropped | exact only |
| `host` | hostname, IP, CIDR | type detected | yes (`domain`/`ip`/`cidr`) |
| `ip` | IPv4/IPv6 literal | canonical address text | yes |
| `cidr` | `10.0.0.0/8` | `ip_network(strict=False)` | yes |
| `url` | `https://host[:port][/path]` | lowercase scheme+host, path without trailing slash | yes |
| `repository` | `owner/name` | as written | no |
| `service`, `api` | free name | as written | no |
| `cloud_account` | provider account reference | as written | no |

Values that mix concerns (`https://...` under `domain`, a query string under
`url`, `*.` under `ip`) are rejected with 422 and an explanation. A `host` row
may hold an IP or CIDR because legacy rows declared them that way; the value is
then canonicalized as an address/network.

## Wildcards

`*.example.com` matches **subdomains at any depth**: `api.example.com` and
`a.b.example.com`. It does **not** match the apex `example.com` unless the row
sets `include_apex = true`. Rationale: the apex is a different authorization
decision from "anything below this domain", and lumping them together is how a
seed rule silently authorizes a site nobody declared.

A pattern is a **rule/seed**:

- it never creates an asset — `concrete_asset()` returns `None`;
- it never expands into names (the inventory fills from registration, import or
  collection, not from a rule);
- it does not cover another pattern (overlapping wildcards are a policy
  question, not a match).

## URLs

`https://api.example.com/v1` covers exactly that scheme and that host, and paths
`/v1` and `/v1/...` — not `/v10`. An explicit port must match; a URL without a
port matches any port on that host. A URL host may itself be a wildcard
(`https://*.example.com`), which follows the same depth/apex rules.

## IPs and CIDRs

- `ip` matches that address only.
- `cidr` matches by containment; overlapping networks cover each other
  (`10.1.0.0/16` is covered by `10.0.0.0/8`).
- An IP inside an excluded CIDR is excluded.

## Exclusions

Exclusions are evaluated **first** and win, including against a wildcard target
that would otherwise cover the value. An exclusion can be time-boxed
(`expires_at`); an expired exclusion stops applying. Excluding a resource:

- does not delete its inventory or its scope declaration;
- does not resolve its findings;
- does not by itself authorize anything.

## Capabilities

`passive_discovery`, `active_verification`, `code_analysis`. Defaults by type:
network types → `passive_discovery`; `repository` → `code_analysis`;
`cloud_account` → none.

- `active_verification` is never implied; it must be listed.
- A `cloud_account` row accepts no capability (422): an account reference does
  not authorize probing any provider address. Concrete IPs/domains must be
  declared separately.
- `/api/v1/scope/check` denies when the requested capability is not listed, the
  row is disabled, or the row is outside its validity window.

## Validity and state

`valid_from` / `valid_until` are timezone-aware timestamps; the reported state
is `active`, `scheduled`, `expired` or `disabled`. `DELETE /scope/targets/{id}`
disables by default (history and the asset link stay); `?hard=true` removes the
row explicitly.

## Linking to the inventory

A concrete target creates the canonical asset (type mapped as above) with
`source = "scope"`, or links the asset that already exists — provenance is never
rewritten. Re-posting the same type+value returns `already_known: true`; nothing
is duplicated. The asset link is visible on both screens and is audited.

## Decisions taken for v0 (previously unspecified)

1. A wildcard excludes the apex unless `include_apex` is set (see above).
2. Depth is unlimited below the pattern; there is no one-level variant.
3. URL scope is scheme + host (+port) + path prefix; query and fragment are not
   part of a scope value.
4. `cloud_account` is declarative only; no resolution or capability is defined
   in v0, and the UI states that.
