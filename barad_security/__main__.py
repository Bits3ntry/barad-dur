"""Allows `python -m barad_security`, which is what `bin/barad-security` calls."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
