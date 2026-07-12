"""Host-key-pinned Paramiko byte stream for the Deco TMP tunnel."""

from __future__ import annotations

import base64
import hashlib
import logging
import socket
from typing import TYPE_CHECKING

import paramiko

from .exceptions import TransportError

if TYPE_CHECKING:
    from types import TracebackType

    from .tmp_ssh_config import TmpSshConfig

log: logging.Logger = logging.getLogger("tplink_deco_api.tmp_ssh")


class TmpSshStream:
    """Expose the router's loopback TMP service as a verified byte stream."""

    def __init__(self, config: TmpSshConfig) -> None:
        self._config = config
        self._socket: socket.socket | None = None
        self._transport: paramiko.Transport | None = None
        self._channel: paramiko.Channel | None = None
        self._host_key_sha256 = ""

    @property
    def host_key_sha256(self) -> str:
        """Return the fingerprint observed during SSH negotiation."""
        return self._host_key_sha256

    @property
    def connected(self) -> bool:
        """Return whether the authenticated tunnel channel is open."""
        return self._channel is not None and not self._channel.closed

    def probe_host_key(self) -> str:
        """Negotiate SSH without authenticating and return its host-key fingerprint."""
        try:
            self._start_client()
            return self._host_key_sha256
        finally:
            self.close()

    def open(self) -> None:
        """Verify the host key, authenticate, and open the loopback TMP channel."""
        if self.connected:
            return
        try:
            self._start_client()
            config = self._config
            if not config.allow_unverified_host_key:
                if not config.host_key_sha256:
                    raise TransportError(
                        "Failed to open TMP SSH: expected host-key fingerprint is required"
                    )
                if config.host_key_sha256 != self._host_key_sha256:
                    raise TransportError(
                        "Failed to open TMP SSH: host-key fingerprint does not match"
                    )
            transport = self._require_transport()
            try:
                transport.auth_password(
                    config.ssh_username,
                    config.password,
                    fallback=False,
                )
            except paramiko.BadAuthenticationType as exc:
                if "keyboard-interactive" not in exc.allowed_types:
                    raise
                transport.auth_interactive(
                    config.ssh_username,
                    lambda _title, _instructions, prompts: [
                        config.password for _prompt, _echo in prompts
                    ],
                )
            if not transport.is_authenticated():
                raise TransportError("Failed to open TMP SSH: authentication failed")
            channel = transport.open_channel(
                "direct-tcpip",
                (config.destination_host, config.destination_port),
                ("127.0.0.1", 0),
                timeout=config.timeout,
            )
            channel.settimeout(config.timeout)
            self._channel = channel
            log.info("TMP SSH tunnel opened for host %s", config.host)
        except TransportError:
            self.close()
            raise
        except (OSError, paramiko.SSHException) as exc:
            self.close()
            raise TransportError(f"Failed to open TMP SSH: {type(exc).__name__}") from exc

    def recv(self, size: int) -> bytes:
        """Receive bytes from the tunneled TMP service."""
        try:
            return self._require_channel().recv(size)
        except (OSError, paramiko.SSHException) as exc:
            raise TransportError(f"Failed to receive TMP data: {type(exc).__name__}") from exc

    def sendall(self, data: bytes) -> None:
        """Send bytes to the tunneled TMP service."""
        try:
            self._require_channel().sendall(data)
        except (OSError, paramiko.SSHException) as exc:
            raise TransportError(f"Failed to send TMP data: {type(exc).__name__}") from exc

    def close(self) -> None:
        """Close the channel, SSH transport, and TCP socket."""
        channel, self._channel = self._channel, None
        transport, self._transport = self._transport, None
        sock, self._socket = self._socket, None
        if channel is not None:
            channel.close()
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()

    def __enter__(self) -> TmpSshStream:
        """Open and return the tunneled stream."""
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the stream when leaving its context."""
        self.close()

    def _start_client(self) -> None:
        if self._transport is not None:
            return
        config = self._config
        try:
            sock = socket.create_connection(
                (config.host, config.ssh_port),
                timeout=config.timeout,
            )
            self._socket = sock
            transport = paramiko.Transport(sock)
            self._transport = transport
            transport.banner_timeout = config.timeout
            security = transport.get_security_options()
            preferred = (
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group1-sha1",
            )
            existing = tuple(security.kex)
            security.kex = tuple(
                dict.fromkeys(
                    algorithm for algorithm in (*preferred, *existing) if algorithm in existing
                )
            )
            transport.start_client(timeout=config.timeout)
            key = transport.get_remote_server_key()
            digest = hashlib.sha256(key.asbytes()).digest()
            encoded = base64.b64encode(digest).decode().rstrip("=")
            self._host_key_sha256 = f"SHA256:{encoded}"
        except (OSError, paramiko.SSHException) as exc:
            self.close()
            raise TransportError(f"Failed to negotiate TMP SSH: {type(exc).__name__}") from exc

    def _require_transport(self) -> paramiko.Transport:
        if self._transport is None:
            raise TransportError("Failed to use TMP SSH: transport is not open")
        return self._transport

    def _require_channel(self) -> paramiko.Channel:
        if self._channel is None:
            raise TransportError("Failed to use TMP SSH: channel is not open")
        return self._channel
