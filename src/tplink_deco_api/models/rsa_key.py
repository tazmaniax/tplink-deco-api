"""RSA public key parsed from the router's hex-encoded handshake."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RsaKey:
    """RSA public key (modulus + exponent) decoded from hex strings."""

    n: int
    e: int

    @classmethod
    def from_hex(cls, modulus_hex: str, exponent_hex: str) -> RsaKey:
        """Build an ``RsaKey`` from hex-encoded modulus and exponent."""
        return cls(n=int(modulus_hex, 16), e=int(exponent_hex, 16))
