"""Severity vocabulary: one label per meaning, everywhere.

Advisories disagree (OSV/PyPA says MODERATE, GitHub says IMPORTANT); storing the
raw label made the portfolio count a MEDIUM as UNKNOWN and sort it to the top of
"worst first".
"""
from backend.app import severity


def test_canonical_maps_known_aliases():
    assert severity.canonical("MODERATE") == "MEDIUM"
    assert severity.canonical("important") == "HIGH"
    assert severity.canonical("  critical ") == "CRITICAL"
    assert severity.canonical("negligible") == "LOW"


def test_canonical_handles_missing_and_unknown():
    assert severity.canonical(None) == "UNKNOWN"
    assert severity.canonical("") == "UNKNOWN"
    assert severity.canonical("weird") == "UNKNOWN"


def test_rank_sorts_worst_first():
    labels = ["LOW", "MODERATE", "CRITICAL", None, "HIGH"]
    ordered = sorted(labels, key=severity.rank)
    assert [severity.canonical(label) for label in ordered] == [
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def test_raw_variants_covers_every_stored_spelling():
    variants = severity.raw_variants("MEDIUM")
    assert "MEDIUM" in variants and "MODERATE" in variants
    assert "HIGH" in severity.raw_variants("high")


def test_osv_severity_is_stored_canonical():
    """The write path must not persist a producer's private vocabulary."""
    from backend.app import vulns

    label, vector = vulns.severity_of({"database_specific": {"severity": "MODERATE"},
                                       "severity": [{"type": "CVSS_V3",
                                                     "score": "CVSS:3.1/AV:N"}]})
    assert label == "MEDIUM"
    assert vector == "CVSS:3.1/AV:N"
