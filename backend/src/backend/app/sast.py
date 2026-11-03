"""Report parsers for the code-analysis viewer.

Supported report formats (v0, both implemented end to end):
  * SARIF 2.1.0 (`run` object, as produced by OpenGrep/Semgrep `--sarif`,
    CodeQL, Trivy, etc.)
  * OpenGrep/Semgrep JSON (`results[].check_id/path/start/end/extra`)

What the parser does not do is claim more than the report says: a result with no
location is counted as uninterpreted, a source→sink trace is kept only when the
report carries one, and the CWE is taken from rule metadata (`cwe` or `tags`)
rather than inferred from the rule name.

Nothing here executes or evaluates the code or the report.
"""
import re

SARIF_LEVEL = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

MAX_RESULTS = 5000
MAX_FILES = 500
MAX_FILE_CHARS = 400_000


def _cwe_from(*sources) -> str | None:
    for source in sources:
        if not source:
            continue
        value = source.get("cwe") if isinstance(source, dict) else None
        if isinstance(value, (list, tuple)) and value:
            value = value[0]
        if isinstance(value, str) and value.strip():
            match = re.search(r"CWE-(\d+)", value, re.IGNORECASE)
            return f"CWE-{match.group(1)}" if match else value.strip()
        tags = source.get("tags") if isinstance(source, dict) else None
        for tag in tags or []:
            match = re.search(r"CWE-(\d+)", str(tag), re.IGNORECASE)
            if match:
                return f"CWE-{match.group(1)}"
    return None


def _severity(value, default="MEDIUM") -> str:
    if value is None:
        return default
    text = str(value).strip().upper()
    if text in SEVERITY_ORDER:
        return text
    if text in {"MODERATE"}:
        return "MEDIUM"
    if text in {"IMPORTANT", "ERROR", "SERIOUS"}:
        return "HIGH"
    if text in {"WARNING"}:
        return "MEDIUM"
    if text in {"NOTE", "INFO", "INFORMATIONAL", "NONE"}:
        return "LOW"
    return default


def parse_sarif(run: dict) -> dict:
    driver = ((run or {}).get("tool") or {}).get("driver") or {}
    tool = driver.get("name") or "sarif"
    tool_version = driver.get("version")
    rules = [rule for rule in (driver.get("rules") or [])
             if isinstance(rule, dict) and rule.get("id")]
    rules_index = {rule["id"]: rule for rule in rules}
    results, uninterpreted = [], []
    for position, result in enumerate(run.get("results") or []):
        if not isinstance(result, dict) or position >= MAX_RESULTS:
            uninterpreted.append({"index": position, "reason": "not an object or over limit"})
            continue
        rule_id = result.get("ruleId") or ((result.get("rule") or {}).get("id"))
        locations = result.get("locations") or []
        physical = (locations[0] or {}).get("physicalLocation") if locations else None
        path = (((physical or {}).get("artifactLocation") or {}).get("uri"))
        region = (physical or {}).get("region") or {}
        if not rule_id or not path:
            uninterpreted.append({"index": position,
                                  "reason": "no rule id or no location"})
            continue
        rule = rules_index.get(rule_id) or {}
        message = ((result.get("message") or {}).get("text")
                   or ((rule.get("shortDescription") or {}).get("text")) or rule_id)
        severity = _severity(result.get("level") and SARIF_LEVEL.get(
            str(result.get("level")).lower(), result.get("level")),
            default=_severity(None))
        security = ((rule.get("properties") or {}).get("security-severity")
                    or (result.get("properties") or {}).get("security-severity"))
        try:
            score = float(security)
            severity = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                        else "MEDIUM" if score >= 4 else "LOW")
        except (TypeError, ValueError):
            pass
        snippet = (((region.get("snippet") or {}).get("text"))
                   or result.get("evidence") or None)
        results.append({
            "rule_id": rule_id, "path": path,
            "line": region.get("startLine"), "end_line": region.get("endLine"),
            "severity": severity, "message": message,
            "cwe": _cwe_from(rule.get("properties"), result.get("properties")),
            "snippet": snippet,
            "source_sink": (result.get("codeFlows") or [])[:1] and
                           {"code_flows": len(result.get("codeFlows") or [])} or {},
        })
    return {"format": "sarif", "tool": tool, "tool_version": tool_version,
            "rules": [{"id": rule.get("id"),
                       "name": ((rule.get("name") or rule.get("shortDescription") or {})
                                .get("text") if isinstance(rule.get("shortDescription"), dict)
                                else rule.get("name")),
                       "cwe": _cwe_from(rule.get("properties"))} for rule in rules],
            "results": results, "uninterpreted": uninterpreted}


def parse_opengrep(report: dict) -> dict:
    """OpenGrep/Semgrep JSON (`results[]` with `check_id`, `path`, `extra`)."""
    report = report or {}
    errors = report.get("errors") or []
    results, uninterpreted = [], []
    for position, item in enumerate(report.get("results") or []):
        if not isinstance(item, dict) or position >= MAX_RESULTS:
            uninterpreted.append({"index": position, "reason": "not an object or over limit"})
            continue
        rule_id = item.get("check_id") or item.get("rule_id")
        path = item.get("path")
        start = (item.get("start") or {})
        end = (item.get("end") or {})
        if not rule_id or not path:
            uninterpreted.append({"index": position,
                                  "reason": "no rule id or no location"})
            continue
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        results.append({
            "rule_id": rule_id, "path": path,
            "line": start.get("line"), "end_line": end.get("line"),
            "severity": _severity(extra.get("severity")),
            "message": extra.get("message") or rule_id,
            "cwe": _cwe_from(metadata),
            "snippet": extra.get("lines"),
            "source_sink": {},
        })
    tool = (report.get("tool") or {}).get("name") or "opengrep"
    tool_version = ((report.get("tool") or {}).get("version")
                    or (report.get("version") if isinstance(report.get("version"), str)
                        else None))
    return {"format": "opengrep", "tool": tool, "tool_version": tool_version,
            "rules": [], "results": results,
            "uninterpreted": uninterpreted + [
                {"reason": f"scanner error: {error.get('message') or error}",
                 "index": index} for index, error in enumerate(errors[:50])
                if isinstance(error, dict)]}


def parse_report(fmt: str, report: dict) -> dict:
    if fmt == "sarif":
        return parse_sarif(report)
    if fmt == "opengrep":
        return parse_opengrep(report)
    raise ValueError("format must be 'sarif' or 'opengrep'")


def parse_diff(text: str) -> dict:
    """Parse a unified diff into per-file added/removed line numbers + hunks.

    Only line numbers and the diff text are kept: "this finding sits on a line
    the diff touched" is a fact about the diff, not proof that the change
    introduced the weakness.
    """
    files: dict[str, dict] = {}
    current = None
    new_line = 0
    for raw in (text or "").splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path == "/dev/null":
                current = None
                continue
            current = files.setdefault(path, {"path": path, "added": set(),
                                              "removed": set(), "hunks": []})
            continue
        if current is None:
            continue
        if raw.startswith("@@ "):
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$", raw)
            new_line = int(match.group(1)) if match else new_line
            current["hunks"].append({"header": raw, "lines": []})
            continue
        if not current["hunks"]:
            continue
        hunk = current["hunks"][-1]
        if raw.startswith("+") and not raw.startswith("+++"):
            current["added"].add(new_line)
            hunk["lines"].append({"kind": "added", "new_line": new_line,
                                  "text": raw[1:]})
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            current["removed"].add(new_line)
            hunk["lines"].append({"kind": "removed", "new_line": None,
                                  "text": raw[1:]})
        else:
            hunk["lines"].append({"kind": "context", "new_line": new_line,
                                  "text": raw[1:]})
            new_line += 1
    return {"files": files,
            "added_total": sum(len(f["added"]) for f in files.values()),
            "removed_total": sum(len(f["removed"]) for f in files.values())}
