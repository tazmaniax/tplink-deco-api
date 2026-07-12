"""Byte-stream contract required by the TMP/AppV2 session."""

from __future__ import annotations

from typing import Protocol


class TmpStream(Protocol):
    """Describe an already-connected, timeout-configured TMP byte stream."""

    def recv(self, size: int) -> bytes:
        """Receive up to ``size`` bytes from the stream."""
        ...

    def sendall(self, data: bytes) -> None:
        """Send all bytes to the stream."""
        ...

    def close(self) -> None:
        """Close the stream and its underlying transport."""
        ...
