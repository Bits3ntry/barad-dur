"""`barad worker`: register as a Shauron worker and execute claimed jobs."""
import json
import sys

from ..core.errors import EXIT_FAILURE
from .. import worker as worker_module


def register(subparsers):
    parser = subparsers.add_parser(
        "worker",
        help="claim authorized scan jobs from a Barad-dûr platform and run them",
        description=("Registers this machine as a worker, claims jobs the platform "
                     "has already authorized, runs the local CLI scan and pushes "
                     "the evidence back. Nothing is executed without a lease."))
    parser.add_argument("--platform-url", required=True,
                       help="e.g. http://127.0.0.1:8090")
    parser.add_argument("--api-key", default="",
                       help="organization API key (full org rights)")
    parser.add_argument("--worker-token", default="",
                       help="scoped worker token (preferred; cannot read findings)")
    parser.add_argument("--isolate-image", default="",
                        help=("run each scan in a digest-pinned throwaway "
                              "container (no network, read-only rootfs, "
                              "memory/cpu limits, non-root)"))
    parser.add_argument("--name", default="shauron-worker",
                        help="worker name (stable identity)")
    parser.add_argument("--capability", action="append", default=None,
                        help="capability this worker accepts (repeatable)")
    parser.add_argument("--max-concurrent", type=int, default=1)
    parser.add_argument("--once", action="store_true",
                        help="handle at most one claim attempt, then exit")
    parser.add_argument("--limit", type=int, default=None,
                        help="stop after N handled jobs")
    parser.add_argument("--poll", type=int, default=5,
                        help="seconds between claim attempts")
    parser.set_defaults(execute=_execute)
    return parser


def _execute(args):
    try:
        result = worker_module.serve(
            args.platform_url, args.api_key, name=args.name,
            capabilities=args.capability, max_concurrent=args.max_concurrent,
            once=args.once, poll=args.poll, limit=args.limit,
            worker_token=args.worker_token or None,
            isolate_image=args.isolate_image or None)
    except worker_module.WorkerError as error:
        print(f"worker error: {error}", file=sys.stderr)
        return EXIT_FAILURE
    print(json.dumps(result, indent=2))
    return 0
