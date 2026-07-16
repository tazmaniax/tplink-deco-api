"""TMP/AppV2 framing with public reads and narrowly scoped verification writes."""

from __future__ import annotations

import json
import secrets
import struct
import time
import zlib
from contextlib import suppress
from typing import TYPE_CHECKING, TypeAlias, cast

from ._json import loads
from .exceptions import TmpProtocolError, TransportError
from .tmp_opcode_catalog import get_tmp_opcode

if TYPE_CHECKING:
    from types import TracebackType

    from ._json import JsonObject, JsonValue
    from .tmp_stream import TmpStream

_ASSOCIATE_REQUEST = 1
_ASSOCIATE_ACCEPT = 2
_ASSOCIATE_REFUSE = 3
_HELLO = 4
_DATA = 5
_BYE = 6

_ACK = 1
_PUSH = 2
_PULL = 4
_PUSH_ACK = _PUSH | _ACK
_PULL_ACK = _PULL | _ACK

_CRC_PLACEHOLDER = 0x5A6B7C8D
_TOKEN_ALLOCATE = 0x0001
_COMPONENT_NEGOTIATE = 0x4001
_MAX_REQUEST_SIZE = 8_156
_MAX_RESPONSE_SIZE = 16 * 1024 * 1024

_GENERAL_HEADER = struct.Struct("!BBBB")
_TRANSFER_HEADER = struct.Struct("!HBBII")
_BUSINESS_HEADER = struct.Struct("!BB")
_APPV2_HEADER = struct.Struct("!HBBHIII")

_Frame: TypeAlias = tuple[int, int, int, int, int, int, int, int, bytes]
_Message: TypeAlias = tuple[int, int, int, int, int, int, int, int, bytes]


def _checksum(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _read_exact(stream: TmpStream, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise TmpProtocolError(
                f"Failed to read TMP frame: unexpected EOF after {len(result)} of {size} bytes"
            )
        result.extend(chunk)
    return bytes(result)


def _pack_frame(
    control: int,
    payload: bytes = b"",
    *,
    main_version: int = 1,
    secondary_version: int = 1,
    reason: int = 0,
    transfer_flag: int = 0,
    transfer_error: int = 0,
) -> bytes:
    general = _GENERAL_HEADER.pack(main_version, secondary_version, control, reason)
    if control != _DATA:
        if payload:
            raise TmpProtocolError("Failed to encode TMP frame: control frame has a payload")
        return general
    serial = secrets.randbits(32)
    checksum_header = _TRANSFER_HEADER.pack(
        len(payload), transfer_flag, transfer_error, serial, _CRC_PLACEHOLDER
    )
    checksum = _checksum(general + checksum_header + payload)
    transfer = _TRANSFER_HEADER.pack(len(payload), transfer_flag, transfer_error, serial, checksum)
    return general + transfer + payload


def _read_frame(stream: TmpStream) -> _Frame:
    general_raw = _read_exact(stream, _GENERAL_HEADER.size)
    general = cast("tuple[int, int, int, int]", _GENERAL_HEADER.unpack(general_raw))
    main_version, secondary_version, control, reason = general
    if control != _DATA:
        return (main_version, secondary_version, control, reason, 0, 0, 0, 0, b"")

    transfer_raw = _read_exact(stream, _TRANSFER_HEADER.size)
    transfer = cast("tuple[int, int, int, int, int]", _TRANSFER_HEADER.unpack(transfer_raw))
    payload_size, transfer_flag, transfer_error, serial, received_checksum = transfer
    if payload_size > _MAX_RESPONSE_SIZE:
        raise TmpProtocolError(
            f"Failed to read TMP frame: payload size {payload_size} exceeds limit"
        )
    payload = _read_exact(stream, payload_size)
    checksum_header = _TRANSFER_HEADER.pack(
        payload_size, transfer_flag, transfer_error, serial, _CRC_PLACEHOLDER
    )
    calculated_checksum = _checksum(general_raw + checksum_header + payload)
    if calculated_checksum != received_checksum:
        raise TmpProtocolError(
            "Failed to read TMP frame: checksum mismatch "
            f"({received_checksum:#x} != {calculated_checksum:#x})"
        )
    if transfer_error:
        raise TmpProtocolError(f"Failed to read TMP frame: transfer error code {transfer_error}")
    return (
        main_version,
        secondary_version,
        control,
        reason,
        transfer_flag,
        transfer_error,
        serial,
        received_checksum,
        payload,
    )


def _pack_message(
    opcode: int,
    flag: int,
    transaction_id: int,
    *,
    payload_checksum: int,
    total_payload_size: int,
    offset_or_ack_size: int,
    chunk: bytes = b"",
) -> bytes:
    appv2 = _APPV2_HEADER.pack(
        opcode,
        flag,
        0,
        transaction_id,
        payload_checksum,
        total_payload_size,
        offset_or_ack_size,
    )
    return _pack_frame(_DATA, _BUSINESS_HEADER.pack(1, 2) + appv2 + chunk)


def _read_message(stream: TmpStream) -> _Message | None:
    frame = _read_frame(stream)
    control = frame[2]
    reason = frame[3]
    if control != _DATA:
        if control == _ASSOCIATE_REFUSE:
            raise TmpProtocolError(f"Failed to associate TMP session: reason code {reason}")
        return None
    payload = frame[8]
    header_size = _BUSINESS_HEADER.size + _APPV2_HEADER.size
    if len(payload) < header_size:
        raise TmpProtocolError("Failed to read AppV2 message: header is truncated")
    business = cast("tuple[int, int]", _BUSINESS_HEADER.unpack(payload[:2]))
    if business != (1, 2):
        raise TmpProtocolError(
            f"Failed to read AppV2 message: unsupported business header {business!r}"
        )
    header = cast(
        "tuple[int, int, int, int, int, int, int]",
        _APPV2_HEADER.unpack(payload[2:header_size]),
    )
    opcode, flag, error, transaction_id, payload_checksum, total_size, offset = header
    return (
        opcode,
        flag,
        error,
        transaction_id,
        payload_checksum,
        total_size,
        offset,
        control,
        payload[header_size:],
    )


def _contiguous_size(chunks: dict[int, bytes]) -> int:
    offset = 0
    while offset in chunks:
        chunk = chunks[offset]
        if not chunk:
            break
        offset += len(chunk)
    return offset


class TmpAppV2Session:
    """Exchange CRC-checked AppV2 operations over an open stream."""

    def __init__(self, stream: TmpStream, *, timeout: float = 8.0) -> None:
        if timeout <= 0:
            raise ValueError("Failed to configure TMP session: timeout must be positive")
        self._stream = stream
        self._timeout = timeout
        self._next_transaction_id = 1
        self._ready = False

    @property
    def ready(self) -> bool:
        """Return whether association and protocol negotiation succeeded."""
        return self._ready

    def open(self) -> None:
        """Associate the stream and perform required AppV2 negotiation."""
        if self._ready:
            return
        self._associate()
        self._exchange(_TOKEN_ALLOCATE, b"")
        self._exchange(_COMPONENT_NEGOTIATE, b"")
        self._ready = True

    def request_read(self, opcode: int, payload: bytes = b"") -> bytes:
        """Invoke one catalogued read-only opcode and return its raw response."""
        if not self._ready:
            raise TmpProtocolError("Failed to request TMP read: session is not ready")
        try:
            operation = get_tmp_opcode(opcode)
        except KeyError as exc:
            raise ValueError(f"Failed to request TMP read: unknown opcode 0x{opcode:04X}") from exc
        if operation.safety != "read_only":
            raise ValueError(
                f"Failed to request TMP read: {operation.name} is classified {operation.safety}"
            )
        return self._exchange(opcode, payload)

    def request_read_json(self, opcode: int, params: JsonValue = None) -> JsonObject:
        """Invoke one read-only opcode using the Deco JSON parameter envelope."""
        envelope: dict[str, JsonValue] = {
            "configVersion": time.time_ns() // 1_000_000,
            "params": params,
        }
        payload = json.dumps(envelope, separators=(",", ":")).encode()
        try:
            return loads(self.request_read(opcode, payload))
        except (UnicodeDecodeError, ValueError) as exc:
            raise TmpProtocolError("Failed to parse TMP response: invalid JSON object") from exc

    def _request_mutation_json(self, opcode: int, params: JsonValue) -> JsonObject:
        if not self._ready:
            raise TmpProtocolError("Failed to request TMP mutation: session is not ready")
        try:
            operation = get_tmp_opcode(opcode)
        except KeyError as exc:
            raise ValueError(
                f"Failed to request TMP mutation: unknown opcode 0x{opcode:04X}"
            ) from exc
        if operation.safety != "mutation":
            raise ValueError(
                f"Failed to request TMP mutation: {operation.name} is classified {operation.safety}"
            )
        envelope: dict[str, JsonValue] = {
            "configVersion": time.time_ns() // 1_000_000,
            "params": params,
        }
        payload = json.dumps(envelope, separators=(",", ":")).encode()
        try:
            return loads(self._exchange(opcode, payload))
        except (UnicodeDecodeError, ValueError) as exc:
            raise TmpProtocolError(
                "Failed to parse TMP mutation response: invalid JSON object"
            ) from exc

    def close(self) -> None:
        """Best-effort close the TMP session and its supplied stream."""
        self._ready = False
        with suppress(OSError, TmpProtocolError, TransportError):
            self._stream.sendall(_pack_frame(_BYE))
        self._stream.close()

    def __enter__(self) -> TmpAppV2Session:
        """Open and return this session."""
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the session when leaving its context."""
        self.close()

    def _associate(self) -> None:
        self._stream.sendall(_pack_frame(_ASSOCIATE_REQUEST))
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            try:
                frame = _read_frame(self._stream)
            except TimeoutError:
                continue
            control = frame[2]
            if control == _HELLO:
                continue
            if control == _ASSOCIATE_REFUSE:
                raise TmpProtocolError(f"Failed to associate TMP session: reason code {frame[3]}")
            if control == _ASSOCIATE_ACCEPT:
                self._stream.sendall(_pack_frame(_ASSOCIATE_ACCEPT))
                self._stream.sendall(_pack_frame(_HELLO))
                return
        raise TmpProtocolError("Failed to associate TMP session: response timed out")

    def _exchange(self, opcode: int, payload: bytes) -> bytes:
        if not 0 <= opcode <= 0xFFFF:
            raise ValueError("Failed to request TMP operation: opcode must fit in 16 bits")
        if len(payload) > _MAX_REQUEST_SIZE:
            raise ValueError(
                f"Failed to request TMP operation: payload exceeds {_MAX_REQUEST_SIZE} bytes"
            )
        transaction_id = self._next_transaction_id & 0xFFFF
        self._next_transaction_id += 1
        payload_checksum = _checksum(payload)
        self._stream.sendall(
            _pack_message(
                opcode,
                _PUSH,
                transaction_id,
                payload_checksum=payload_checksum,
                total_payload_size=len(payload),
                offset_or_ack_size=0,
                chunk=payload,
            )
        )
        pull_sent = False
        if not payload:
            self._send_pull(opcode, transaction_id, 0)
            pull_sent = True

        chunks: dict[int, bytes] = {}
        expected_total: int | None = None
        expected_checksum: int | None = None
        requested_offset = 0
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            try:
                message = _read_message(self._stream)
            except TimeoutError:
                continue
            if message is None:
                continue
            message_opcode, flag, error, message_transaction = message[:4]
            if message_opcode != opcode or message_transaction != transaction_id:
                continue
            if error:
                raise TmpProtocolError(
                    f"Failed to request TMP operation 0x{opcode:04X}: AppV2 error {error}"
                )
            if flag == _PUSH_ACK:
                if not pull_sent and message[6] >= len(payload):
                    self._send_pull(opcode, transaction_id, 0)
                    pull_sent = True
                continue
            if flag not in {_PUSH, _PULL_ACK}:
                continue

            checksum, total, offset, chunk = message[4], message[5], message[6], message[8]
            if total > _MAX_RESPONSE_SIZE:
                raise TmpProtocolError(
                    f"Failed to request TMP operation: response size {total} exceeds limit"
                )
            if expected_total is None:
                expected_total = total
                expected_checksum = checksum
            elif total != expected_total or checksum != expected_checksum:
                raise TmpProtocolError(
                    "Failed to request TMP operation: response metadata changed between chunks"
                )
            if offset + len(chunk) > total:
                raise TmpProtocolError(
                    "Failed to request TMP operation: response chunk exceeds declared size"
                )
            previous = chunks.get(offset)
            if previous is not None and previous != chunk:
                raise TmpProtocolError(
                    "Failed to request TMP operation: conflicting response chunk"
                )
            chunks[offset] = chunk
            contiguous = _contiguous_size(chunks)
            if flag == _PUSH:
                self._stream.sendall(
                    _pack_message(
                        opcode,
                        _PUSH_ACK,
                        transaction_id,
                        payload_checksum=0,
                        total_payload_size=0,
                        offset_or_ack_size=contiguous,
                    )
                )
            if expected_total == 0:
                response = b""
            elif contiguous >= expected_total:
                response = b"".join(chunks[index] for index in sorted(chunks))[:expected_total]
            else:
                if contiguous != requested_offset:
                    requested_offset = contiguous
                    self._send_pull(opcode, transaction_id, contiguous)
                continue
            if expected_checksum is not None and _checksum(response) != expected_checksum:
                raise TmpProtocolError(
                    "Failed to request TMP operation: response payload checksum mismatch"
                )
            return response
        raise TmpProtocolError(
            f"Failed to request TMP operation 0x{opcode:04X}: response timed out"
        )

    def _send_pull(self, opcode: int, transaction_id: int, offset: int) -> None:
        self._stream.sendall(
            _pack_message(
                opcode,
                _PULL,
                transaction_id,
                payload_checksum=0,
                total_payload_size=0,
                offset_or_ack_size=offset,
            )
        )
