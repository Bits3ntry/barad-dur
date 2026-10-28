"""Command line entry point: one runner, four execution surfaces.

    barad-security run --event pr --base-ref main
    barad-security run --event release --version 8.9.0
    barad-security sync --run-id RUN_ID
    barad-security sync --pending
    barad-security validate-config

Exit codes are documented in `barad_security.errors`; findings never fail a run
unless `execution.fail_on_findings` asks for it.
"""
import argparse
import json
import sys
import traceback
from pathlib import Path

from . import __version__
from .config import load_config
from .errors import (
    EXIT_FAILURE, EXIT_OK, EXIT_USAGE, BaradError, ConfigError, UsageError,
)
from .gitctx import EVENTS
from .orchestration import SecurityRunner, detect_source
from .sync import sync_pending, sync_run


def build_parser():
    parser = argparse.ArgumentParser(
        prog="barad-security",
        description="BARAD-DÛR security runner: Trivy on every run, CycloneDX SBOM when the inventory changes.",
    )
    parser.add_argument("--version", action="version", version=f"barad-security {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="path to barad-security.yml (default: repository root)")
    common.add_argument("--repository", default=".", help="repository root (default: current directory)")
    common.add_argument("--json", action="store_true", help="print the machine-readable result to stdout")

    run = subparsers.add_parser("run", parents=[common],
                                help="run the security workflow once")
    run.add_argument("--event", choices=EVENTS, help="execution event (default: infer from the environment)")
    run.add_argument("--base-ref", help="Git reference to compare against")
    run.add_argument("--version", dest="version_override",
                     help="application version for this run (for example the release version)")
    run.add_argument("--run-id", help="explicit run identifier (default: derived)")
    run.add_argument("--source", choices=("local", "github", "act"),
                     help="execution surface (default: detected from the environment)")

    sync = subparsers.add_parser("sync", parents=[common],
                                 help="retry pending publications without rescanning")
    group = sync.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-id", help="run identifier whose publications are pending")
    group.add_argument("--pending", action="store_true", help="sync every queued run")

    subparsers.add_parser("validate-config", parents=[common],
                          help="validate the configuration without scanning")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(parser, args)
    except BaradError as error:
        print(f"error: {error.message}", file=sys.stderr)
        if error.details:
            print(json.dumps(error.details, indent=2, sort_keys=True), file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as error:  # pragma: no cover - unexpected internal failure
        print(f"internal error: {type(error).__name__}: {error}", file=sys.stderr)
        if getattr(args, "json", False):
            traceback.print_exc()
        return EXIT_FAILURE


def _dispatch(parser, args):
    repository = Path(args.repository).expanduser().resolve()
    if not repository.is_dir():
        raise UsageError(f"repository not found: {repository}")
    config = load_config(args.config, repo_root=repository)

    if args.command == "validate-config":
        if args.json:
            print(json.dumps({"valid": True, "config": str(config.source),
                              "fingerprint": config.fingerprint()}, sort_keys=True))
        else:
            print(f"configuration valid: {config.source}")
            print(f"  project: {config.get('project.name')} / {config.get('project.service')}")
            print(f"  trivy: {config.get('trivy.runner')} {config.get('trivy.scan_type')} "
                  f"scanners={','.join(config.get('trivy.scanners'))}")
            print(f"  sbom: {'enabled' if config.get('sbom.enabled') else 'disabled'} via {config.get('sbom.generator')}")
            print(f"  artifacts: {config.get('artifacts.directory')}")
        return EXIT_OK

    if args.command == "run":
        runner = SecurityRunner(
            config,
            event=args.event,
            base_ref=args.base_ref,
            version=args.version_override,
            run_id=args.run_id,
            source=args.source or detect_source(),
        )
        outcome = runner.run()
        if args.json:
            print(json.dumps(outcome.manifest, indent=2, sort_keys=True, default=str))
        else:
            _print_run_summary(outcome)
        return outcome.exit_code

    if args.command == "sync":
        if args.pending:
            outcomes = sync_pending(config)
        else:
            outcomes = [sync_run(config, args.run_id)]
        if args.json:
            print(json.dumps(outcomes, indent=2, sort_keys=True, default=str))
        else:
            for outcome in outcomes:
                if outcome.get("error"):
                    print(f"{outcome['run_id']}: error: {outcome['error']}")
                    continue
                services = ", ".join(f"{name}={value.get('status')}"
                                     for name, value in outcome.get("services", {}).items())
                state = "resolved" if outcome.get("resolved") else "still pending"
                print(f"{outcome['run_id']}: {state}{(' (' + services + ')') if services else ''}")
        unresolved = [outcome for outcome in outcomes if not outcome.get("resolved")]
        return EXIT_FAILURE if unresolved else EXIT_OK

    parser.error("unknown command")  # pragma: no cover - argparse enforces it
    return EXIT_USAGE


def _print_run_summary(outcome):
    manifest = outcome.manifest
    counts = manifest.get("security", {}).get("counts", {})
    print(f"run {outcome.run_id}: {outcome.status}")
    print(f"  evidence: {outcome.run_dir}")
    steps = manifest.get("steps", {})
    trivy = steps.get("trivy", {})
    print(f"  trivy: {trivy.get('status')} "
          f"(vulns={counts.get('total', 0)} secrets={counts.get('secrets', 0)} "
          f"misconfigs={counts.get('misconfigurations', 0)})")
    sbom = steps.get("sbom")
    if sbom:
        print(f"  sbom: {sbom.get('status')}")
    else:
        reason = manifest.get("decisions", {}).get("sbom_reason")
        print(f"  sbom: SKIPPED ({reason})")
    for name in ("barad_dur", "dependency_track", "defectdojo"):
        step = steps.get(name)
        if step:
            reason = step.get("reason")
            print(f"  {name}: {step.get('status')}{(' (' + reason + ')') if reason else ''}")
    if manifest.get("problems"):
        print(f"  problems: {len(manifest['problems'])}")
