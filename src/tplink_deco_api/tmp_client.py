"""High-level client for Deco TMP reads and scoped verification."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, TypeVar

from .exceptions import TmpProtocolError, TransportError
from .tmp_protocol import TmpAppV2Session

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from ._json import JsonObject, JsonValue
    from .tmp_ssh_config import TmpSshConfig
    from .tmp_ssh_stream import TmpSshStream

log: logging.Logger = logging.getLogger("tplink_deco_api.tmp")

_T = TypeVar("_T")


def _new_tmp_ssh_stream(config: TmpSshConfig) -> TmpSshStream:
    from .tmp_ssh_stream import TmpSshStream

    return TmpSshStream(config)


class DecoTmpClient:
    """Provide AppV2 reads and scoped verification over pinned SSH."""

    def __init__(self, config: TmpSshConfig) -> None:
        self._config = config
        self._stream: TmpSshStream | None = None
        self._session: TmpAppV2Session | None = None

    @property
    def connected(self) -> bool:
        """Return whether the AppV2 session is negotiated and ready."""
        return (
            self._stream is not None
            and self._stream.connected
            and self._session is not None
            and self._session.ready
        )

    def probe_host_key(self) -> str:
        """Return the router SSH fingerprint without authenticating."""
        return _new_tmp_ssh_stream(self._config).probe_host_key()

    def open(self) -> None:
        """Open SSH, associate TMP, and negotiate the AppV2 session."""
        if self.connected:
            return
        stream = _new_tmp_ssh_stream(self._config)
        session = TmpAppV2Session(stream, timeout=self._config.timeout)
        try:
            stream.open()
            session.open()
        except Exception:
            stream.close()
            raise
        self._stream = stream
        self._session = session

    def request_read(self, opcode: int, payload: bytes = b"") -> bytes:
        """Invoke one catalogued read-only opcode and return raw bytes."""
        return self._request_with_reconnect(lambda session: session.request_read(opcode, payload))

    def request_read_json(self, opcode: int, params: JsonValue = None) -> JsonObject:
        """Invoke one catalogued read-only opcode with a JSON parameter envelope."""
        return self._request_with_reconnect(
            lambda session: session.request_read_json(opcode, params)
        )

    def _request_mutation_json(self, opcode: int, params: JsonValue) -> JsonObject:
        return self._require_session()._request_mutation_json(opcode, params)

    def close(self) -> None:
        """Close the AppV2 session and SSH transport."""
        session, self._session = self._session, None
        stream, self._stream = self._stream, None
        if session is not None:
            session.close()
        elif stream is not None:
            stream.close()

    def __enter__(self) -> DecoTmpClient:
        """Open and return this client."""
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the client when leaving its context."""
        self.close()

    def _require_session(self) -> TmpAppV2Session:
        if not self.connected or self._session is None:
            raise RuntimeError("Failed to use TMP client: client is not connected")
        return self._session

    def _request_with_reconnect(self, request: Callable[[TmpAppV2Session], _T]) -> _T:
        for attempt in range(2):
            try:
                return request(self._require_session())
            except (TmpProtocolError, TransportError) as exc:
                if not self._is_connection_failure(exc):
                    raise
                self.close()
                if attempt == 1:
                    raise
                log.warning("TMP connection closed during read; reconnecting once")
                self.open()
        raise AssertionError("Failed to request TMP read: retry loop exhausted")

    @staticmethod
    def _is_connection_failure(error: TmpProtocolError | TransportError) -> bool:
        return isinstance(error, TransportError) or "unexpected EOF" in str(error)
