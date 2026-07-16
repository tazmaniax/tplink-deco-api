"""Tests for the optional host-key-pinned TMP SSH adapter."""

from __future__ import annotations

import base64
import hashlib
from unittest import mock

import paramiko
import pytest

from tplink_deco_api import (
    DecoTmpClient,
    TmpProtocolError,
    TmpSshConfig,
    TmpSshStream,
    TransportError,
)


def _fingerprint(key_bytes: bytes = b"router-key") -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _config(**overrides: object) -> TmpSshConfig:
    values: dict[str, object] = {
        "host": "192.0.2.1",
        "tp_link_id": "owner@example.com",
        "password": "secret",
        "host_key_sha256": _fingerprint(),
        "timeout": 5.0,
    }
    values.update(overrides)
    return TmpSshConfig(**values)  # type: ignore[arg-type]


def _mock_transport() -> tuple[mock.Mock, mock.Mock, mock.Mock, mock.Mock]:
    sock = mock.Mock()
    transport = mock.Mock()
    security = mock.Mock()
    security.kex = (
        "curve25519-sha256@libssh.org",
        "diffie-hellman-group14-sha1",
    )
    key = mock.Mock()
    key.asbytes.return_value = b"router-key"
    channel = mock.Mock()
    channel.closed = False
    channel.recv.return_value = b"reply"
    transport.get_security_options.return_value = security
    transport.get_remote_server_key.return_value = key
    transport.is_authenticated.return_value = True
    transport.open_channel.return_value = channel
    return sock, transport, security, channel


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"host": ""}, "host is required"),
        ({"tp_link_id": "owner"}, "must be an email"),
        ({"password": ""}, "password is required"),
        ({"ssh_port": 0}, "SSH port is invalid"),
        ({"destination_port": 65536}, "destination port is invalid"),
        ({"timeout": 0}, "timeout must be positive"),
        ({"host_key_sha256": "md5:value"}, "SHA256: format"),
    ],
)
def test_tmp_ssh_config_rejects_invalid_values(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _config(**overrides)


def test_tmp_ssh_config_derives_username_without_exposing_password() -> None:
    config = _config()

    assert config.ssh_username == "66f171d88474476cb4933b33b39cceba825e24f1"
    assert "secret" not in repr(config)


def test_probe_host_key_negotiates_without_authentication() -> None:
    sock, transport, security, _ = _mock_transport()
    stream = TmpSshStream(_config(host_key_sha256=""))

    with (
        mock.patch("socket.create_connection", return_value=sock),
        mock.patch("paramiko.Transport", return_value=transport),
    ):
        fingerprint = stream.probe_host_key()

    assert fingerprint == _fingerprint()
    assert security.kex == (
        "diffie-hellman-group14-sha1",
        "curve25519-sha256@libssh.org",
    )
    transport.start_client.assert_called_once_with(timeout=5.0)
    transport.auth_password.assert_not_called()
    transport.close.assert_called_once()
    sock.close.assert_called_once()


def test_open_verifies_host_key_authenticates_and_tunnels() -> None:
    sock, transport, _, channel = _mock_transport()
    stream = TmpSshStream(_config())

    with (
        mock.patch("socket.create_connection", return_value=sock),
        mock.patch("paramiko.Transport", return_value=transport),
        stream,
    ):
        assert stream.connected is True
        assert stream.host_key_sha256 == _fingerprint()
        assert stream.recv(10) == b"reply"
        stream.sendall(b"request")
        stream.open()

    transport.auth_password.assert_called_once_with(
        "66f171d88474476cb4933b33b39cceba825e24f1",
        "secret",
        fallback=False,
    )
    transport.open_channel.assert_called_once_with(
        "direct-tcpip",
        ("127.0.0.1", 20002),
        ("127.0.0.1", 0),
        timeout=5.0,
    )
    channel.settimeout.assert_called_once_with(5.0)
    channel.sendall.assert_called_once_with(b"request")
    channel.close.assert_called_once()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"host_key_sha256": ""}, "fingerprint is required"),
        ({"host_key_sha256": "SHA256:wrong"}, "does not match"),
    ],
)
def test_open_fails_closed_on_unpinned_or_changed_host_key(
    overrides: dict[str, object], message: str
) -> None:
    sock, transport, _, _ = _mock_transport()
    stream = TmpSshStream(_config(**overrides))
    with (
        mock.patch("socket.create_connection", return_value=sock),
        mock.patch("paramiko.Transport", return_value=transport),
        pytest.raises(TransportError, match=message),
    ):
        stream.open()
    transport.auth_password.assert_not_called()
    transport.close.assert_called_once()


def test_open_supports_explicit_unverified_and_keyboard_interactive_auth() -> None:
    sock, transport, _, channel = _mock_transport()
    error = paramiko.BadAuthenticationType("password disabled", ["keyboard-interactive"])
    transport.auth_password.side_effect = error
    stream = TmpSshStream(_config(host_key_sha256="", allow_unverified_host_key=True))

    with (
        mock.patch("socket.create_connection", return_value=sock),
        mock.patch("paramiko.Transport", return_value=transport),
    ):
        stream.open()

    handler = transport.auth_interactive.call_args.args[1]
    assert handler("title", "instructions", [("Password", False)]) == ["secret"]
    assert stream.connected is True
    stream.close()
    channel.close.assert_called_once()


def test_open_rejects_authentication_failure_and_wraps_ssh_errors() -> None:
    sock, transport, _, _ = _mock_transport()
    transport.is_authenticated.return_value = False
    stream = TmpSshStream(_config())
    with (
        mock.patch("socket.create_connection", return_value=sock),
        mock.patch("paramiko.Transport", return_value=transport),
        pytest.raises(TransportError, match="authentication failed"),
    ):
        stream.open()

    broken = TmpSshStream(_config())
    with (
        mock.patch("socket.create_connection", side_effect=OSError),
        pytest.raises(TransportError, match="Failed to negotiate TMP SSH: OSError"),
    ):
        broken.open()


def test_stream_requires_channel_and_wraps_channel_errors() -> None:
    stream = TmpSshStream(_config())
    with pytest.raises(TransportError, match="channel is not open"):
        stream.recv(1)
    with pytest.raises(TransportError, match="channel is not open"):
        stream.sendall(b"x")

    sock, transport, _, channel = _mock_transport()
    with (
        mock.patch("socket.create_connection", return_value=sock),
        mock.patch("paramiko.Transport", return_value=transport),
    ):
        stream.open()
    channel.recv.side_effect = OSError
    channel.sendall.side_effect = paramiko.SSHException
    with pytest.raises(TransportError, match="Failed to receive TMP data: OSError"):
        stream.recv(1)
    with pytest.raises(TransportError, match="Failed to send TMP data: SSHException"):
        stream.sendall(b"x")
    stream.close()
    stream.close()


def test_tmp_client_manages_stream_session_and_read_calls() -> None:
    stream = mock.Mock()
    session = mock.Mock()
    session.ready = True
    session.request_read.return_value = b"raw"
    session.request_read_json.return_value = {"error_code": 0}
    client = DecoTmpClient(_config())

    with (
        mock.patch("tplink_deco_api.tmp_client._new_tmp_ssh_stream", return_value=stream),
        mock.patch("tplink_deco_api.tmp_client.TmpAppV2Session", return_value=session),
        client as opened,
    ):
        assert opened is client
        assert client.connected is True
        client.open()
        assert client.request_read(0x400F) == b"raw"
        assert client.request_read_json(0x400F) == {"error_code": 0}

    stream.open.assert_called_once()
    session.open.assert_called_once()
    session.close.assert_called_once()


def test_tmp_client_probe_guards_and_failed_open_cleanup() -> None:
    stream = mock.Mock()
    stream.probe_host_key.return_value = _fingerprint()
    client = DecoTmpClient(_config())
    with mock.patch("tplink_deco_api.tmp_client._new_tmp_ssh_stream", return_value=stream):
        assert client.probe_host_key() == _fingerprint()
        stream.open.side_effect = TransportError("failed")
        with pytest.raises(TransportError, match="failed"):
            client.open()
    stream.close.assert_called_once()

    disconnected = DecoTmpClient(_config())
    with pytest.raises(RuntimeError, match="not connected"):
        disconnected.request_read(0x400F)
    disconnected.close()


def test_tmp_client_reconnects_once_after_unexpected_eof() -> None:
    first_stream = mock.Mock(connected=True)
    first_session = mock.Mock(ready=True)
    first_session.request_read.side_effect = TmpProtocolError(
        "Failed to read TMP frame: unexpected EOF after 0 of 4 bytes"
    )
    second_stream = mock.Mock(connected=True)
    second_session = mock.Mock(ready=True)
    second_session.request_read.return_value = b"recovered"
    client = DecoTmpClient(_config())

    with (
        mock.patch(
            "tplink_deco_api.tmp_client._new_tmp_ssh_stream",
            side_effect=[first_stream, second_stream],
        ),
        mock.patch(
            "tplink_deco_api.tmp_client.TmpAppV2Session",
            side_effect=[first_session, second_session],
        ),
    ):
        client.open()
        assert client.request_read(0x400F) == b"recovered"

    first_session.close.assert_called_once()
    second_stream.open.assert_called_once()
    second_session.open.assert_called_once()
    assert client.connected is True


def test_tmp_client_does_not_reconnect_after_non_connection_protocol_error() -> None:
    stream = mock.Mock(connected=True)
    session = mock.Mock(ready=True)
    session.request_read_json.side_effect = TmpProtocolError(
        "Failed to request TMP operation 0x400F: AppV2 error 12"
    )
    client = DecoTmpClient(_config())

    with (
        mock.patch("tplink_deco_api.tmp_client._new_tmp_ssh_stream", return_value=stream),
        mock.patch("tplink_deco_api.tmp_client.TmpAppV2Session", return_value=session),
    ):
        client.open()
        with pytest.raises(TmpProtocolError, match="AppV2 error 12"):
            client.request_read_json(0x400F)

    session.close.assert_not_called()
    stream.open.assert_called_once()


def test_tmp_client_disconnect_state_includes_ssh_channel() -> None:
    stream = mock.Mock(connected=False)
    session = mock.Mock(ready=True)
    client = DecoTmpClient(_config())
    client._stream = stream
    client._session = session

    assert client.connected is False
    with pytest.raises(RuntimeError, match="not connected"):
        client.request_read(0x400F)
