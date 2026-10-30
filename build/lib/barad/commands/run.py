"""`barad run [path]`: scan every time, then synchronize enabled integrations."""
import json
import sys

from ..run import run_workflow


def register(subparsers):
    parser = subparsers.add_parser('run', help='scan and synchronize enabled remote services')
    parser.add_argument('path', nargs='?', help='directory to scan (default: current directory)')
    parser.add_argument('--config', help='path to .barad.yml (default: discovered)')
    parser.add_argument('--output', '--out', '-O', dest='output',
                        help='local artifact directory (default: .barad/reports in the current directory)')
    parser.add_argument('--json', action='store_true', help='print the evidence manifest as JSON')
    parser.set_defaults(execute=execute)


def execute(args):
    result = run_workflow(args)
    manifest = result.manifest
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"run {manifest['project']['name']}: {manifest['status']}")
        print(f"  evidence: {result.run_dir}")
        print(f"  scan: {manifest['scan']['status']}")
        for key, value in manifest['sync'].items():
            print(f"  {key}: {value['status']} ({value.get('reason') or value.get('mode') or 'ok'})")
    if result.error:
        print(f'error: {result.error}', file=sys.stderr)
    return result.exit_code
