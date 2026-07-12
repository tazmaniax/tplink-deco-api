"""Errors raised when a mutation plan no longer matches the controller."""

from __future__ import annotations

from .base import DecoError


class ControllerChangedError(DecoError):
    """Raised when the connected controller changes after a plan is created."""
