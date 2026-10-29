"""Compatibility module for :mod:`integrations.defectdojo`."""
import sys

from integrations import defectdojo as _implementation

sys.modules[__name__] = _implementation
