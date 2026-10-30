"""Sanitised evidence: what may leave the runner.

A Trivy secret finding embeds the matched credential. The raw report stays in the
local evidence directory (that is the analyst's evidence), while every copy that
is uploaded to an external system is redacted first. Only secret evidence is
touched: vulnerability and misconfiguration findings keep their full fidelity, so
redaction can never silently hide a finding.
"""
import copy
import json

REDACTED = "[REDACTED]"
_REDACT_KEYS = ("Match", "Code", "Layer", "Content")


def sanitize_trivy_report(document):
    """Return a copy of a Trivy JSON report with secret matches redacted."""
    sanitized = copy.deepcopy(document)
    redacted = 0
    counts = {"secrets": 0, "vulnerabilities": 0, "misconfigurations": 0}
    for result in sanitized.get("Results") or []:
        if not isinstance(result, dict):
            continue
        counts["vulnerabilities"] += len(result.get("Vulnerabilities") or [])
        counts["misconfigurations"] += len(result.get("Misconfigurations") or [])
        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            counts["secrets"] += 1
            for key in _REDACT_KEYS:
                if secret.get(key):
                    secret[key] = REDACTED
                    redacted += 1
    return sanitized, {"redacted_fields": redacted, **counts}


def write_sanitized_report(source_path, destination_path):
    document = json.loads(open(source_path, encoding="utf-8").read())
    sanitized, summary = sanitize_trivy_report(document)
    with open(destination_path, "w", encoding="utf-8") as handle:
        json.dump(sanitized, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return summary
