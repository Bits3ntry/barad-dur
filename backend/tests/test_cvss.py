"""The base score is computed, so it is pinned against published numbers.

`test_a_score_stored_under_the_runtime_key_is_still_a_score` covers the other
half: when the source did store a score, that score wins and nothing is derived.
"""
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import cvss  # noqa: E402

# Every pair below is a vector the estate actually holds and the score its source
# published alongside it.
KNOWN = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H": 8.2,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
    "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
}


def test_every_known_vector_scores_as_published():
    for vector, expected in KNOWN.items():
        assert cvss.base_score(vector) == expected, vector


def test_v4_is_refused_rather_than_guessed():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert cvss.base_score(vector) is None


def test_a_missing_or_malformed_vector_answers_none():
    assert cvss.base_score(None) is None
    assert cvss.base_score("") is None
    assert cvss.base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_parse_reads_one_letter_metrics():
    metrics = cvss.parse("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N")
    assert metrics["S"] == "C"
    assert metrics["C"] == "H"
    assert "CVSS" not in metrics
