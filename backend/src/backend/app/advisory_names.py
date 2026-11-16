"""The nickname → CVE table: the lore an operator actually types.

The model is forbidden from recalling CVEs from memory, and the KEV feed records the
vendor's description ("Google Brotli Unchecked Return Value Vulnerability") — never
the name the internet gave it ("Node2Shell"). Without this table an operator who says
the famous name gets "nothing in the estate matches node2shell": technically true,
and useless.

Curated on purpose. An alias is a fact with a diff — one row, reviewable in review —
not a similarity search and not a model's memory. Keys are normalised
(lowercase, letters and digits only) so `Node 2 Shell`, `node2shell` and
`Node-2-Shell` are one key.
"""
from __future__ import annotations

import re

#: nickname -> CVE. Keep the canonical spelling of the nickname; normalisation happens
#: at lookup time (`normalize`), so "dirty pipe" and "DirtyPipe" are the same entry.
ALIASES: dict[str, str] = {
    "node2shell": "CVE-2026-111497",
    "brotli2shell": "CVE-2026-111497",
    "http2shell": "CVE-2026-111497",
    "log4shell": "CVE-2021-44228",
    "log4j": "CVE-2021-44228",
    "log4j2": "CVE-2021-44228",
    "spring4shell": "CVE-2022-22965",
    "text4shell": "CVE-2022-42889",
    "heartbleed": "CVE-2014-0160",
    "shellshock": "CVE-2014-6271",
    "pwnkit": "CVE-2021-4034",
    "dirtypipe": "CVE-2022-0847",
    "dirty pipe": "CVE-2022-0847",
    "zerologon": "CVE-2020-1472",
    "eternalblue": "CVE-2017-0144",
    "bluekeep": "CVE-2019-0708",
    "proxyshell": "CVE-2021-34473",
    "proxylogon": "CVE-2021-27065",
    "regresshion": "CVE-2024-6387",
    "xzbackdoor": "CVE-2024-3094",
    "citrixbleed": "CVE-2023-4966",
    "printnightmare": "CVE-2021-34527",
    "follina": "CVE-2022-30190",
}

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def normalize(term: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (term or "").lower())


def resolve(term: str) -> str | None:
    """The CVE for a nickname or a literal CVE id, or `None` when it is neither."""
    cleaned = (term or "").strip()
    if CVE_RE.match(cleaned):
        return cleaned.upper()
    return ALIASES.get(normalize(cleaned))
