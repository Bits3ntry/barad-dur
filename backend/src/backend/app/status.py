"""What "closed" means, once.

Findings arrive from producers that spell closure differently — `closed` from the
scan refresh, `resolved` from a person, `false_positive` from triage — and every
screen that kept its own copy of the set drifted. The build page counted 96 open
findings while the project table printed 212 for the same build, because one set
knew `closed` and the other did not; a door built on either number would have
opened a queue that disagreed with the count it was clicked from.

The one deliberate exception is notifications: what deserves an alert is a
delivery policy, not a count, and it reads its own set where that policy lives.
"""

CLOSED_STATUSES = frozenset({
    "closed",
    "resolved",
    "false_positive",
    "accepted_risk",
    "suppressed",
})

# The name the gates, the cycle screens and the dashboard already use.
NON_OPEN = CLOSED_STATUSES

# The name the SBOM and inventory readers use.
SETTLED_STATUSES = CLOSED_STATUSES
