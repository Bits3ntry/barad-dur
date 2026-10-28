"""Reserved diagnostic command until the next work unit."""
def register(subparsers):
    parser = subparsers.add_parser("health", help="check installation (reserved)")
    parser.set_defaults(execute=lambda args: 2)
