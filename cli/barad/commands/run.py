"""Reserved integration command until the next work unit."""
def register(subparsers):
    parser = subparsers.add_parser("run", help="run remote synchronization (reserved)")
    parser.add_argument("path", nargs="?")
    parser.add_argument("--config")
    parser.add_argument("--json", action="store_true")
    parser.set_defaults(execute=lambda args: 2)
