"""Load a workspace-local `.env` without exposing its values."""
import os
import re
from pathlib import Path

from .core.errors import ConfigError

_ENTRY = re.compile(r"(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$")


def load_workspace_environment(workspace, environ=None):
    """Merge `<workspace>/.env` below the explicit process environment.

    The parser deliberately supports only plain `KEY=VALUE` assignments. It
    avoids shell expansion and command substitution while accepting optional
    surrounding single or double quotes.
    """
    environment = dict(os.environ if environ is None else environ)
    path = Path(workspace) / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return environment
    except OSError as error:
        raise ConfigError(f"cannot read workspace .env: {error.strerror}") from None

    for number, line in enumerate(lines, start=1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        match = _ENTRY.fullmatch(entry)
        if not match:
            raise ConfigError(f"invalid workspace .env entry at line {number}")
        key, value = match.groups()
        value = _value(value, number)
        if key not in environment:
            environment[key] = value
    return environment


def _value(value, number):
    value = value.strip()
    if not value:
        return ""
    if value[0] in "\"'":
        if len(value) < 2 or value[-1] != value[0]:
            raise ConfigError(f"invalid workspace .env entry at line {number}")
        return value[1:-1]
    return value.split(" #", 1)[0].rstrip()
