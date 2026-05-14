"""Login response dataclass."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LoginResult:
    """Outcome of a successful login: session token and user level."""

    stok: str
    usr_lvl: int = 1
