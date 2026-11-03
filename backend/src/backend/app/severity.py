"""One severity vocabulary for every producer and consumer.

Advisories do not agree on names: OSV/PyPA says MODERATE, GitHub says
IMPORTANT, SARIF sometimes says WARNING. Storing those raw makes the console
count a MEDIUM as UNKNOWN and sort it to the top, so every write and every
rollup goes through `canonical`.
"""

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

# Ordered worst-first; the index doubles as the rank used for sorting.
_ALIASES = {
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "IMPORTANT": "HIGH",
    "SERIOUS": "HIGH",
    "SEVERE": "HIGH",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "MINOR": "LOW",
    "NEGLIGIBLE": "LOW",
    "INFORMATIONAL": "LOW",
    "INFO": "LOW",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
    "NOTE": "LOW",
    "NONE": "LOW",
}


def canonical(value) -> str:
    """Map any producer's severity label onto CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN."""
    if value is None:
        return "UNKNOWN"
    key = str(value).strip().upper()
    if not key:
        return "UNKNOWN"
    return _ALIASES.get(key, key if key in SEVERITIES else "UNKNOWN")


def rank(value) -> int:
    """0 for the worst severity, 4 for unknown — sort ascending for 'worst first'."""
    return SEVERITIES.index(canonical(value))


def raw_variants(severity: str) -> tuple[str, ...]:
    """Every stored spelling that means `severity`, for filtering rows in SQL."""
    wanted = canonical(severity)
    return tuple(sorted({spelling for spelling, mapped in _ALIASES.items() if mapped == wanted}
                        | {wanted}))
