"""`barad scan [path] [--output dir]`: the standalone scan entry point."""
import json
import os
import sys
from pathlib import Path

from barad_security.errors import BaradError, ConfigError, UsageError
from barad_security.gitctx import detect_git_context

from ..config import CONFIG_FILENAME, load_settings, read_project_config
from ..project import derive_name, detect_ecosystems
from ..scan import run_scan


def register(subparsers):
    parser = subparsers.add_parser(
        "scan", help="scan a filesystem path or the image target configured in .barad.yml"
    )
    parser.add_argument("path", nargs="?",
                        help="directory to scan (default: the configured scan target)")
    parser.add_argument("--output", help="artifact directory (must stay inside the scan root)")
    parser.add_argument("--config", help="path to .barad.yml (default: discovered)")
    parser.add_argument("--json", action="store_true", help="print the evidence manifest as JSON")
    parser.set_defaults(execute=execute)


def execute(args):
    result = perform(args)
    if args.json:
        print(json.dumps(result.manifest, indent=2, sort_keys=True, default=str))
    else:
        _print_summary(result)
    if result.error:
        print(f"error: {result.error}", file=sys.stderr)
    return result.exit_code


def perform(args):
    """Resolve a target and invoke the same scanning engine for scan and run."""
    settings, target_type, target_value, context, name_source = resolve(args)
    return run_scan(settings, target_type=target_type, target_value=target_value,
                    git_context=context, name_source=name_source, environ=os.environ)


def resolve(args):
    """Validate inputs before any scanner or remote side effect."""
    cwd = Path.cwd()
    path = _scan_path(args.path, cwd)
    search_root = (path.parent if path and path.is_file() else path) or cwd
    config_path, context = _discover_config(search_root, args.config)
    document, source = read_project_config(config_path)
    configured = document.get("scan") if isinstance(document.get("scan"), dict) else {}
    target_type = configured.get("target_type", "fs")

    if path is not None:
        if target_type == "image":
            raise UsageError(
                "image scanning is configured; omit the positional path or remove "
                "scan.target_type: image from .barad.yml"
            )
        root = path.parent if path.is_file() else path
        target_type, target_value = "fs", path.name if path.is_file() else "."
    elif target_type == "image":
        target_value = configured.get("target")
        if not target_value:
            raise ConfigError(
                "invalid configuration: scan.target is required when scan.target_type is 'image'"
            )
        root = config_path.parent if config_path else cwd
    else:
        root, target_value = _configured_root(configured.get("target") or ".", config_path, cwd)

    output_override = _output_override(args.output, cwd, root)
    if root != search_root:
        context = _git_context(root)
    configured_name = document.get("project", {}).get("name") if isinstance(
        document.get("project"), dict) else None
    git_root = context.repository_root if context is not None and context.available else None
    name, name_source = derive_name(configured_name, git_root, root)
    ecosystems = detect_ecosystems(root) if target_type == "fs" else []

    settings = load_settings(
        document,
        source=source,
        root=root,
        project_name=name,
        ecosystems=ecosystems,
        environ=os.environ,
        output_override=output_override,
        target_override=target_value if target_type == 'fs' and target_value != '.' else None,
    )
    return settings, target_type, target_value, context, name_source


def _scan_path(value, cwd):
    if value is None:
        return None
    candidate = Path(value).expanduser()
    candidate = (candidate if candidate.is_absolute() else cwd / candidate).resolve()
    if not candidate.exists():
        raise UsageError(f"scan path not found: {candidate}")
    if not candidate.is_dir() and not (candidate.is_file() and candidate.suffix.lower() == '.jar'):
        if candidate.name.lower().startswith(("dockerfile", "containerfile")):
            raise UsageError(
                f"scan path is not a directory: {candidate}; a Dockerfile is a build "
                "definition, not an image target (configure scan.target_type: image with "
                "a built image reference)"
            )
        raise UsageError(f"scan path is not a directory: {candidate}")
    return candidate


def _discover_config(search_root, explicit):
    if explicit:
        candidate = Path(explicit).expanduser()
        candidate = (candidate if candidate.is_absolute() else Path.cwd() / candidate).resolve()
        if not candidate.is_file():
            raise ConfigError(f"configuration file not found: {candidate}")
        return candidate, _git_context(search_root)
    context = _git_context(search_root)
    candidates = [search_root]
    if context is not None and context.available and context.repository_root != search_root:
        candidates.append(context.repository_root)
    for directory in candidates:
        candidate = Path(directory) / CONFIG_FILENAME
        if candidate.is_file():
            return candidate.resolve(), context
    return None, context


def _git_context(root):
    try:
        return detect_git_context(root, environ=os.environ)
    except BaradError:
        return None


def _configured_root(configured, config_path, cwd):
    relative = Path(configured)
    if relative.is_absolute() or ".." in relative.parts:
        raise ConfigError(
            "invalid configuration: scan.target must stay inside the configuration directory"
        )
    base = config_path.parent if config_path else cwd
    candidate = (base / relative).resolve()
    if candidate != base and base not in candidate.parents:
        raise ConfigError('invalid configuration: scan.target escapes the project root')
    if candidate.is_file() and candidate.suffix.lower() == '.jar':
        return base, relative.as_posix()
    if not candidate.is_dir():
        raise ConfigError(
            f"invalid configuration: scan.target does not exist or is not a directory: {configured}"
        )
    return candidate, "."


def _output_override(value, cwd, root):
    if value is None:
        return None
    output = Path(value).expanduser()
    output = (output if output.is_absolute() else cwd / output).resolve()
    if output != root and root not in output.parents:
        raise UsageError(f"output must stay inside the scan root: {output}")
    state_dir = (root / ".barad" / "state").resolve()
    if output == state_dir or state_dir in output.parents:
        raise UsageError(f"output must not overlap the state directory: {state_dir}")
    return output.relative_to(root).as_posix()


def _print_summary(result):
    manifest = result.manifest
    counts = manifest["scan"].get("counts") or {}
    version = manifest["application_version"]
    inventory = manifest["inventory"]
    print(f"scan {manifest['project']['name']}: {manifest['status']}")
    print(f"  target: {manifest['project']['target']['type']} "
          f"{manifest['project']['target']['value']}")
    print(f"  version: {version.get('value') or 'unresolved'} ({version.get('source')})")
    print(f"  commit: {manifest.get('commit') or 'none'}")
    print(f"  evidence: {result.run_dir}")
    print(f"  scan: {manifest['scan']['status']} "
          f"(vulns={counts.get('total', 0)} secrets={counts.get('secrets', 0)} "
          f"misconfigurations={counts.get('misconfigurations', 0)})")
    print(f"  inventory: {inventory.get('comparison')} "
          f"{str(inventory.get('fingerprint'))[:12]}")
