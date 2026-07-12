"""Errors raised when a semantic mutation cannot produce a plan."""

from __future__ import annotations

from .base import DecoError


class MutationIneligibleError(DecoError):
    """Raised when mutation preflight blockers prevent plan creation."""

    def __init__(self, blockers: tuple[str, ...]) -> None:
        super().__init__("Failed to create mutation plan: mutation is not execution-eligible")
        self.blockers = blockers
