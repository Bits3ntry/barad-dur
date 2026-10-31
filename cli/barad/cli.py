"""Argument parsing and process exit codes for the standalone `barad` CLI."""
import argparse
import sys

from .core.errors import EXIT_FAILURE, BaradError

from . import __version__
from .commands import health, run, scan, worker


def build_parser():
    parser = argparse.ArgumentParser(
        prog="barad",
        description="BARAD-DÛR standalone CLI: scan a repository, run the workflow, "
                    "inspect local health. None of these commands needs a running server.",
    )
    parser.add_argument("--version", action="version", version=f"barad {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for module in (scan, run, health, worker):
        module.register(subparsers)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.execute(args)
    except BaradError as error:
        print(f"error: {error.message}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as error:  # unexpected failure: never mask it as success
        print(f"internal error: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_FAILURE
