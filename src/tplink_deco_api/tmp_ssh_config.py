"""Configuration for the hidden Deco SSH-to-TMP transport."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha1


@dataclass(frozen=True)
class TmpSshConfig:
    """Configure a host-key-pinned SSH tunnel to the local TMP service."""

    host: str
    tp_link_id: str
    password: str = field(repr=False)
    host_key_sha256: str = ""
    ssh_port: int = 20001
    destination_host: str = "127.0.0.1"
    destination_port: int = 20002
    timeout: float = 20.0
    allow_unverified_host_key: bool = False

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("Failed to configure TMP SSH: host is required")
        if "@" not in self.tp_link_id.strip():
            raise ValueError("Failed to configure TMP SSH: TP-Link ID must be an email address")
        if not self.password:
            raise ValueError("Failed to configure TMP SSH: password is required")
        if not 1 <= self.ssh_port <= 65535:
            raise ValueError("Failed to configure TMP SSH: SSH port is invalid")
        if not 1 <= self.destination_port <= 65535:
            raise ValueError("Failed to configure TMP SSH: destination port is invalid")
        if self.timeout <= 0:
            raise ValueError("Failed to configure TMP SSH: timeout must be positive")
        if self.host_key_sha256 and not self.host_key_sha256.startswith("SHA256:"):
            raise ValueError("Failed to configure TMP SSH: host key must use SHA256: format")

    @property
    def ssh_username(self) -> str:
        """Derive the firmware SSH username from the TP-Link ID."""
        # TP-Link's firmware protocol mandates SHA-1 for this identifier; it is not a password hash.
        return sha1(self.tp_link_id.strip().encode(), usedforsecurity=False).hexdigest()
