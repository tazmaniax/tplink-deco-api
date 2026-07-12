"""Tests for the read-only TMP/AppV2 wire session."""

from __future__ import annotations

import json
import struct
from unittest import mock

import pytest

from tplink_deco_api import TmpAppV2Session, TmpProtocolError
from tplink_deco_api.tmp_protocol import (
    _APPV2_HEADER,
    _ASSOCIATE_ACCEPT,
    _ASSOCIATE_REFUSE,
    _BUSINESS_HEADER,
    _DATA,
    _HELLO,
    _MAX_REQUEST_SIZE,
    _PULL_ACK,
    _PUSH,
    _PUSH_ACK,
    _checksum,
    _pack_frame,
    _read_frame,
    _read_message,
)


class FakeStream:
    """Provide deterministic recv/send behavior for protocol tests."""

    def __init__(self, incoming: bytes = b"") -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.closed = False

    def recv(self, size: int) -> bytes:
        chunk = self.incoming[:size]
        del self.incoming[:size]
        return bytes(chunk)

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def close(self) -> None:
        self.closed = True


class TimeoutStream(FakeStream):
    """Raise a timeout once all prepared bytes have been consumed."""

    def recv(self, size: int) -> bytes:
        if not self.incoming:
            raise TimeoutError
        return super().recv(size)


def _response(
    opcode: int,
    transaction_id: int,
    payload: bytes,
    *,
    flag: int = _PUSH,
    offset: int = 0,
    total: int | None = None,
    checksum: int | None = None,
    error: int = 0,
) -> bytes:
    size = len(payload) if total is None else total
    payload_checksum = _checksum(payload) if checksum is None else checksum
    header = _APPV2_HEADER.pack(
        opcode,
        flag,
        error,
        transaction_id,
        payload_checksum,
        size,
        offset,
    )
    return _pack_frame(_DATA, _BUSINESS_HEADER.pack(1, 2) + header + payload)


def _opening_frames() -> bytes:
    return (
        _pack_frame(_HELLO)
        + _pack_frame(_ASSOCIATE_ACCEPT)
        + _response(0x0001, 1, b"")
        + _response(0x4001, 2, b"")
    )


def _opened_session(extra_incoming: bytes = b"") -> tuple[TmpAppV2Session, FakeStream]:
    stream = FakeStream(_opening_frames() + extra_incoming)
    session = TmpAppV2Session(stream, timeout=0.1)
    session.open()
    return session, stream


def test_frame_round_trip_and_control_frame_validation() -> None:
    raw = _pack_frame(_DATA, b"payload", transfer_flag=7)
    frame = _read_frame(FakeStream(raw))

    assert frame[2] == _DATA
    assert frame[4] == 7
    assert frame[8] == b"payload"
    assert _read_frame(FakeStream(_pack_frame(_HELLO)))[2] == _HELLO
    with pytest.raises(TmpProtocolError, match="control frame has a payload"):
        _pack_frame(_HELLO, b"invalid")


def test_frame_rejects_eof_checksum_error_transfer_error_and_oversize() -> None:
    with pytest.raises(TmpProtocolError, match="unexpected EOF"):
        _read_frame(FakeStream(b"\x01"))

    corrupt = bytearray(_pack_frame(_DATA, b"payload"))
    corrupt[-1] ^= 0xFF
    with pytest.raises(TmpProtocolError, match="checksum mismatch"):
        _read_frame(FakeStream(bytes(corrupt)))

    transfer_error = _pack_frame(_DATA, b"", transfer_error=9)
    with pytest.raises(TmpProtocolError, match="transfer error code 9"):
        _read_frame(FakeStream(transfer_error))

    general = struct.pack("!BBBB", 1, 1, _DATA, 0)
    transfer = struct.pack("!HBBII", 0xFFFF, 0, 0, 1, 0)
    with (
        mock.patch("tplink_deco_api.tmp_protocol._MAX_RESPONSE_SIZE", 10),
        pytest.raises(TmpProtocolError, match="payload size"),
    ):
        _read_frame(FakeStream(general + transfer))


def test_message_rejects_refusal_short_header_and_business_version() -> None:
    with pytest.raises(TmpProtocolError, match="reason code 7"):
        _read_message(FakeStream(_pack_frame(_ASSOCIATE_REFUSE, reason=7)))
    with pytest.raises(TmpProtocolError, match="header is truncated"):
        _read_message(FakeStream(_pack_frame(_DATA, b"short")))

    payload = _BUSINESS_HEADER.pack(2, 9) + bytes(_APPV2_HEADER.size)
    with pytest.raises(TmpProtocolError, match="unsupported business header"):
        _read_message(FakeStream(_pack_frame(_DATA, payload)))
    assert _read_message(FakeStream(_pack_frame(_HELLO))) is None


def test_session_opens_once_and_closes_with_bye() -> None:
    stream = FakeStream(_opening_frames())
    session = TmpAppV2Session(stream, timeout=0.1)

    with session as opened:
        assert opened is session
        assert session.ready is True
        sent_before = bytes(stream.sent)
        session.open()
        assert bytes(stream.sent) == sent_before

    assert session.ready is False
    assert stream.closed is True
    frames = FakeStream(bytes(stream.sent))
    controls: list[int] = []
    while frames.incoming:
        controls.append(_read_frame(frames)[2])
    assert controls[:3] == [1, 2, 4]
    assert controls[-1] == 6


def test_association_refusal_and_timeout_are_reported() -> None:
    refused = TmpAppV2Session(FakeStream(_pack_frame(_ASSOCIATE_REFUSE, reason=4)), timeout=0.1)
    with pytest.raises(TmpProtocolError, match="reason code 4"):
        refused.open()

    stream = mock.Mock()
    stream.recv.side_effect = TimeoutError
    timed_out = TmpAppV2Session(stream, timeout=0.001)
    with pytest.raises(TmpProtocolError, match="response timed out"):
        timed_out.open()


def test_read_json_handles_ack_and_chunked_response() -> None:
    response = b'{"error_code":0,"result":{"support_plc":true}}'
    split = 17
    incoming = (
        _response(0x400F, 3, b"", flag=_PUSH_ACK, offset=10_000)
        + _response(
            0x400F,
            3,
            response[:split],
            flag=_PUSH,
            total=len(response),
            checksum=_checksum(response),
        )
        + _response(
            0x400F,
            3,
            response[split:],
            flag=_PULL_ACK,
            offset=split,
            total=len(response),
            checksum=_checksum(response),
        )
    )
    session, stream = _opened_session(incoming)

    with mock.patch("time.time_ns", return_value=1_234_000_000):
        result = session.request_read_json(0x400F, {"device_id": "default"})

    assert result["error_code"] == 0
    assert result["result"] == {"support_plc": True}

    sent = FakeStream(bytes(stream.sent))
    request_payload = None
    while sent.incoming:
        message = _read_message(sent)
        if message is not None and message[0] == 0x400F and message[1] == _PUSH:
            request_payload = json.loads(message[8])
    assert request_payload == {
        "configVersion": 1234,
        "params": {"device_id": "default"},
    }


def test_read_safety_and_input_guards_fail_before_sending() -> None:
    cold = TmpAppV2Session(FakeStream(), timeout=1)
    with pytest.raises(TmpProtocolError, match="session is not ready"):
        cold.request_read(0x400F)
    with pytest.raises(ValueError, match="timeout must be positive"):
        TmpAppV2Session(FakeStream(), timeout=0)

    session, stream = _opened_session()
    sent_size = len(stream.sent)
    with pytest.raises(ValueError, match="unknown opcode"):
        session.request_read(0xFFFF)
    with pytest.raises(ValueError, match="classified mutation"):
        session.request_read(0x424D)
    with pytest.raises(ValueError, match="fit in 16 bits"):
        session._exchange(0x10000, b"")
    with pytest.raises(ValueError, match="payload exceeds"):
        session._exchange(0x400F, bytes(_MAX_REQUEST_SIZE + 1))
    assert len(stream.sent) == sent_size


def test_private_mutation_transport_accepts_only_catalogued_non_destructive_write() -> None:
    response = b'{"error_code":0,"result":{}}'
    session, stream = _opened_session(_response(0x4209, 3, response))

    with mock.patch("time.time_ns", return_value=1_234_000_000):
        result = session._request_mutation_json(0x4209, {"enable": True})

    assert result == {"error_code": 0, "result": {}}
    sent = FakeStream(bytes(stream.sent))
    request_payload = None
    while sent.incoming:
        message = _read_message(sent)
        if message is not None and message[0] == 0x4209 and message[1] == _PUSH:
            request_payload = json.loads(message[8])
    assert request_payload == {
        "configVersion": 1234,
        "params": {"enable": True},
    }


def test_private_mutation_transport_guards_fail_before_sending() -> None:
    cold = TmpAppV2Session(FakeStream(), timeout=1)
    with pytest.raises(TmpProtocolError, match="session is not ready"):
        cold._request_mutation_json(0x4209, {"enable": True})

    session, stream = _opened_session()
    sent_size = len(stream.sent)
    with pytest.raises(ValueError, match="unknown opcode"):
        session._request_mutation_json(0xFFFF, {})
    with pytest.raises(ValueError, match="classified read_only"):
        session._request_mutation_json(0x4208, {})
    with pytest.raises(ValueError, match="classified destructive"):
        session._request_mutation_json(0x4016, {})
    assert len(stream.sent) == sent_size


def test_response_errors_and_invalid_json_are_rejected() -> None:
    error_session, _ = _opened_session(_response(0x400F, 3, b"", error=12))
    with pytest.raises(TmpProtocolError, match="AppV2 error 12"):
        error_session.request_read(0x400F)

    invalid_json, _ = _opened_session(_response(0x400F, 3, b"not-json"))
    with pytest.raises(TmpProtocolError, match="invalid JSON object"):
        invalid_json.request_read_json(0x400F)

    non_object, _ = _opened_session(_response(0x400F, 3, b"[]"))
    with pytest.raises(TmpProtocolError, match="invalid JSON object"):
        non_object.request_read_json(0x400F)


@pytest.mark.parametrize(
    ("incoming", "message"),
    [
        (
            _response(0x400F, 3, b"abc", total=2),
            "chunk exceeds declared size",
        ),
        (
            _response(0x400F, 3, b"abc", checksum=123),
            "payload checksum mismatch",
        ),
        (
            _response(0x400F, 3, b"a", total=2, checksum=1)
            + _response(0x400F, 3, b"b", offset=1, total=3, checksum=1),
            "metadata changed",
        ),
        (
            _response(0x400F, 3, b"a", total=2, checksum=1)
            + _response(0x400F, 3, b"b", total=2, checksum=1),
            "conflicting response chunk",
        ),
    ],
)
def test_malformed_chunked_responses_are_rejected(incoming: bytes, message: str) -> None:
    session, _ = _opened_session(incoming)
    with pytest.raises(TmpProtocolError, match=message):
        session.request_read(0x400F)


def test_unrelated_messages_are_ignored_until_timeout() -> None:
    unrelated = _response(0x4004, 99, b"{}")
    stream = TimeoutStream(_opening_frames() + unrelated)
    session = TmpAppV2Session(stream, timeout=0.001)
    session.open()
    with pytest.raises(TmpProtocolError, match="0x400F: response timed out"):
        session.request_read(0x400F)


def test_close_suppresses_send_failure_but_closes_stream() -> None:
    stream = mock.Mock()
    stream.sendall.side_effect = OSError
    TmpAppV2Session(stream).close()
    stream.close.assert_called_once()
