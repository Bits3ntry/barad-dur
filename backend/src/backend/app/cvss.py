"""CVSS v3.0/v3.1 base score, computed from the vector.

Why this exists: not every producer stores a number. Trivy writes `cvss_score`
beside the vector, NVD's CPE ingest keeps only `cvss_vector` on the advisory and
then overwrites the finding's JSON detail with a note, so a runtime CVE arrived at
the console as "no CVSS score" while the vector sat right there — the same vector
NVD scored. Deriving the base score from the vector is arithmetic, not a guess:
the formula below is the specification's, and the tests pin it against vectors
whose published scores are known.

CVSS v4.0 is deliberately **not** computed. Its scoring is a set of macro-vector
lookups rather than a closed formula, and a wrong number is worse than none: an
unsupported vector returns None and the caller says it has no score.
"""

import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required depends on Scope, which is why it is read after S.
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(value: float) -> float:
    """The spec's Roundup: round up to one decimal, without float artefacts."""
    return math.ceil(round(value * 100000) / 10000) / 10


def parse(vector: str | None) -> dict:
    """`CVSS:3.1/AV:N/AC:L/…` → {"AV": "N", …}; the prefix is dropped."""
    metrics = {}
    if not vector:
        return metrics
    for part in str(vector).split("/"):
        key, _, value = part.partition(":")
        # `S`, `C`, `I` and `A` are one letter; `AV`, `AC`… are two; the leading
        # `CVSS:3.1` has a four-letter name and is not a metric.
        if 1 <= len(key) <= 2 and value:
            metrics[key.upper()] = value.upper()
    return metrics


def base_score(vector: str | None) -> float | None:
    """The v3.0/v3.1 base score, or None for a version this module does not score."""
    metrics = parse(vector)
    if not metrics:
        return None
    try:
        changed = metrics["S"] == "C"
        exploitability = 8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] \
            * (PR_CHANGED if changed else PR_UNCHANGED)[metrics["PR"]] * UI[metrics["UI"]]
        iss = 1 - ((1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]]))
    except KeyError:
        return None
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    if changed:
        total = min(1.08 * total, 10)
    return _roundup(min(total, 10))
