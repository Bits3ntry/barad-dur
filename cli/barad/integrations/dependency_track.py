"""Compatibility module for :mod:`integrations.dependency_track`."""
import sys

from integrations import dependency_track as _implementation

sys.modules[__name__] = _implementation
