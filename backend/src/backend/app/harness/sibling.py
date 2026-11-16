"""Ask the same question as two different principals.

An authorization bypass is not a hunch: it is user B receiving user A's record. This
module sends the identical request twice — same method, same path, same body — with a
different identity each time, and compares what came back.

The comparison is deliberately conservative. `leak` requires the owner marker the
operator supplied to appear in B's response; without it the answer is `ambiguous`,
because a 200 can be a public page and calling that a bypass is how a scanner loses
its credibility.
"""

from __future__ import annotations

import hashlib
import re

import httpx

#: A test hooks the transport; production uses a real client.
TRANSPORT = None
OK = {200, 201, 202, 203, 204, 206}
DENIED = {401, 403, 404, 410}
_TOKENS = re.compile(r"[A-Za-z0-9]{3,}")


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _TOKENS.findall(text or "")}


def similarity(a: str, b: str) -> float:
    left, right = _tokens(a), _tokens(b)
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _send(client: httpx.Client, method: str, url: str, headers: dict, body: str | None):
    try:
        response = client.request(method, url, headers=headers,
                                  content=body or None)
        return {"status": response.status_code, "text": response.text,
                "sha256_16": hashlib.sha256(response.text.encode()).hexdigest()[:16],
                "error": None}
    except httpx.HTTPError as error:
        return {"status": None, "text": "", "sha256_16": None,
                "error": type(error).__name__}


def run(*, method: str, url: str, headers_a: dict, headers_b: dict,
        body: str | None = None, owner_marker: str | None = None,
        transport=None) -> dict:
    """Send twice and answer `leak | denied | ambiguous | blocked`."""
    client = (httpx.Client(transport=transport or TRANSPORT, timeout=10.0,
                           follow_redirects=False) if (transport or TRANSPORT)
              else httpx.Client(timeout=10.0, follow_redirects=False))
    try:
        first = _send(client, method, url, headers_a, body)
        second = _send(client, method, url, headers_b, body)
    finally:
        client.close()

    def digest(result: dict) -> dict:
        return {"status": result["status"], "sha256_16": result["sha256_16"],
                "chars": len(result["text"]), "error": result["error"]}

    payload = {"request": {"method": method, "url": url},
               "a": digest(first), "b": digest(second),
               "owner_marker": bool(owner_marker)}

    if first["error"] or second["error"]:
        return {**payload, "state": "blocked",
                "reason": "one of the requests did not complete: "
                          f"{first['error'] or second['error']}"}
    if first["status"] in DENIED:
        return {**payload, "state": "ambiguous",
                "reason": f"identity A is not authorized either ({first['status']}); "
                          "pick a principal that can read its own record"}
    if second["status"] in DENIED:
        return {**payload, "state": "denied",
                "reason": f"identity B was refused ({second['status']})"}
    if second["status"] not in OK:
        return {**payload, "state": "ambiguous",
                "reason": f"identity B answered {second['status']}"}

    overlap = round(similarity(first["text"], second["text"]), 3)
    payload["similarity"] = overlap
    if owner_marker:
        present = owner_marker.lower() in second["text"].lower()
        payload["marker_in_b"] = present
        if present and overlap >= 0.85:
            return {**payload, "state": "leak",
                    "reason": f"B received A's record: {owner_marker!r} present "
                              f"(similarity {overlap})"}
        if present:
            return {**payload, "state": "leak",
                    "reason": f"B received A's record: {owner_marker!r} present"}
        return {**payload, "state": "ambiguous",
                "reason": f"B answered {second['status']} but {owner_marker!r} is "
                          "absent: not proof of a leak"}
    if overlap >= 0.85:
        return {**payload, "state": "ambiguous",
                "reason": f"B answered {second['status']} with a near-identical body "
                          "(similarity {overlap}); pass owner_marker to confirm"
                          .format(overlap=overlap)}
    return {**payload, "state": "ambiguous",
            "reason": f"B answered {second['status']} with a different body "
                      f"(similarity {overlap})"}
