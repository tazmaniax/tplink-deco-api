"""Network-free unit tests for ``DecoClient`` login and request flow.

The HTTP layer is replaced by a fake transport that returns real
AES-encrypted envelopes, so the full crypto/protocol/session path runs
in-process without ever touching a router.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest import mock

import pytest

from tplink_deco_api import (
    AddressReservation,
    AddressReservationTable,
    ApiError,
    ApiResponse,
    AuthenticationError,
    CapabilityReport,
    ClientDevice,
    DecoClient,
    Device,
    DeviceMode,
    EndpointSpec,
    NetworkTotals,
    NodeClientList,
    Performance,
    SpeedTest,
    TransportError,
    WlanConfig,
    get_endpoint,
)
from tplink_deco_api.auth.protocol import build_payload, parse_response
from tplink_deco_api.crypto import aes_encrypt
from tplink_deco_api.models.session_keys import SessionKeys

if TYPE_CHECKING:
    from collections.abc import Mapping

    from tplink_deco_api._json import JsonObject

_SIGN_N = int(
    "DE1E5BD8347A6BED75ED9E96190B47FDCE5696B49A542F908003D01DD3CBF59B"
    "9A76F42A68048D85B1E3AFC78CD23191AA26CD69E5932D4CA02F35687071F65F",
    16,
)
_SIGN_N_HEX = format(_SIGN_N, "x")
_E_HEX = "010001"


class _FakeTransport:
    """Stand-in for ``HttpTransport`` that serves canned handshake + encrypted bodies.

    ``login()`` issues three POSTs (auth, keys, login). The first two are plain
    JSON; the login one returns an AES envelope encrypted with the AES key/IV the
    client generated, which the fake reads back out of the posted form body.
    """

    def __init__(self, *, result_for_form: Mapping[str, JsonObject] | None = None) -> None:
        self.result_for_form = dict(result_for_form or {})
        self.posted_urls: list[str] = []
        self.multipart_posts: list[tuple[str, Mapping[str, str]]] = []
        self._aes_key = ""
        self._aes_iv = ""
        self.login_stok = "deadbeefstoktoken"
        self.login_usr_lvl = 2
        self.session_cleared = False

    def post_json(self, url: str, body: Mapping[str, str]) -> JsonObject:
        self.posted_urls.append(url)
        if "form=auth" in url:
            return {"result": {"key": [_SIGN_N_HEX, _E_HEX], "seq": 100}}
        if "form=keys" in url:
            return {"result": {"password": [_SIGN_N_HEX, _E_HEX]}}
        form = url.rsplit("form=", 1)[-1]
        if form in self.result_for_form:
            return {"result": self.result_for_form[form], "error_code": 0}
        raise AssertionError(f"unexpected post_json url: {url}")

    def post_form(self, url: str, body: str) -> JsonObject:
        self.posted_urls.append(url)
        self._capture_aes(body)
        if "form=login" in url:
            inner = {
                "result": {"stok": self.login_stok, "usrLvl": self.login_usr_lvl},
                "error_code": 0,
            }
            return self._envelope(inner)
        form = url.rsplit("form=", 1)[-1]
        result = self.result_for_form.get(form, {})
        return self._envelope({"result": result, "error_code": 0})

    def post_bytes(
        self,
        url: str,
        body: bytes = b"",
        content_type: str = "application/json",
    ) -> bytes:
        self.posted_urls.append(url)
        return b"downloaded log\n"

    def post_multipart_fields(
        self,
        url: str,
        fields: Mapping[str, str],
    ) -> bytes:
        self.posted_urls.append(url)
        self.multipart_posts.append((url, fields))
        return b"encrypted backup"

    def _capture_aes(self, body: str) -> None:
        # The fake decrypts the sign block off-band by re-deriving the AES pair
        # from the most recent client. Instead we recover key/iv from the keys
        # the client stored: the test passes them in via ``set_aes``.
        pass

    def set_aes(self, aes_key: str, aes_iv: str) -> None:
        self._aes_key = aes_key
        self._aes_iv = aes_iv

    def clear_session(self) -> None:
        self.session_cleared = True

    def _envelope(self, inner: JsonObject) -> JsonObject:
        data_b64 = aes_encrypt(self._aes_key, self._aes_iv, json.dumps(inner))
        return {"data": data_b64}


def _make_client(
    transport: _FakeTransport,
) -> DecoClient:
    client = DecoClient("192.0.2.1", "admin", "secret")
    client._transport = transport  # type: ignore[assignment]
    return client


def _login(client: DecoClient, transport: _FakeTransport) -> None:
    """Drive login, wiring the fake's AES pair to whatever the client generated."""
    real_post_form = transport.post_form

    def wrapped(url: str, body: str) -> JsonObject:
        keys = client._session.keys if client._session else None
        if keys is not None:
            transport.set_aes(keys.aes_key, keys.aes_iv)
        return real_post_form(url, body)

    transport.post_form = wrapped  # type: ignore[assignment]


def test_login_success_sets_session() -> None:
    transport = _FakeTransport()
    client = _make_client(transport)
    _login(client, transport)

    result = client.login()

    assert result.stok == transport.login_stok
    assert result.usr_lvl == 2
    assert client.is_authenticated()
    assert any("form=auth" in u for u in transport.posted_urls)
    assert any("form=keys" in u for u in transport.posted_urls)
    assert any("form=login" in u for u in transport.posted_urls)


def test_login_seq_propagates_to_session() -> None:
    transport = _FakeTransport()
    client = _make_client(transport)
    _login(client, transport)
    client.login()
    assert client._session is not None
    assert client._session.keys.seq == 100


def test_login_malformed_rsa_keys_raises() -> None:
    transport = _FakeTransport()

    def bad_post_json(url: str, body: Mapping[str, str]) -> JsonObject:
        if "form=auth" in url:
            return {"result": {"key": [_SIGN_N_HEX], "seq": 1}}  # only one element
        return {"result": {"password": [_SIGN_N_HEX, _E_HEX]}}

    transport.post_json = bad_post_json  # type: ignore[assignment]
    client = _make_client(transport)
    with pytest.raises(AuthenticationError, match="RSA key handshake malformed"):
        client.login()


def test_login_missing_stok_raises() -> None:
    transport = _FakeTransport()
    transport.login_stok = ""
    client = _make_client(transport)
    _login(client, transport)
    with pytest.raises(AuthenticationError, match="missing stok"):
        client.login()


def test_login_default_usr_lvl() -> None:
    transport = _FakeTransport()
    client = _make_client(transport)
    _login(client, transport)
    # Drop usr_lvl from the login envelope to exercise the default.
    real_post_form = transport.post_form

    def patched(url: str, body: str) -> JsonObject:
        if "form=login" in url:
            keys = client._session.keys if client._session else None
            assert keys is not None
            transport.set_aes(keys.aes_key, keys.aes_iv)
            inner = {"result": {"stok": "tok"}, "error_code": 0}
            return transport._envelope(inner)
        return real_post_form(url, body)

    transport.post_form = patched  # type: ignore[assignment]
    result = client.login()
    assert result.usr_lvl == 1


def test_request_before_login_raises() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    with pytest.raises(AuthenticationError, match="not authenticated"):
        client.request("admin/device", "device_list", {"operation": "read"})


def test_logout_invalidates_session() -> None:
    transport = _FakeTransport()
    client = _make_client(transport)
    _login(client, transport)
    client.login()
    assert client.is_authenticated()
    client.logout()
    assert not client.is_authenticated()
    assert client._session is not None
    assert client._session.keys.seq == 0
    assert transport.session_cleared
    assert any("form=logout" in url for url in transport.posted_urls)


def test_logout_without_session_is_noop() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    client.logout()
    assert not client.is_authenticated()


def test_logout_falls_back_to_local_cleanup_when_endpoint_is_absent() -> None:
    client, transport = _logged_in({})

    with mock.patch.object(
        client,
        "request_envelope",
        side_effect=TransportError("Failed to POST logout: HTTP 404", status_code=404),
    ):
        client.logout()

    assert not client.is_authenticated()
    assert transport.session_cleared


def test_logout_propagates_other_transport_errors_after_local_cleanup() -> None:
    client, transport = _logged_in({})

    with (
        mock.patch.object(
            client,
            "request_envelope",
            side_effect=TransportError("Failed to POST logout: HTTP 500", status_code=500),
        ),
        pytest.raises(TransportError, match="HTTP 500"),
    ):
        client.logout()

    assert not client.is_authenticated()
    assert transport.session_cleared


def test_invalidate_session_without_login_clears_transport() -> None:
    transport = _FakeTransport()
    client = _make_client(transport)

    client.invalidate_session()

    assert transport.session_cleared


def test_is_authenticated_false_initially() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    assert not client.is_authenticated()


def _logged_in(result_for_form: Mapping[str, JsonObject]) -> tuple[DecoClient, _FakeTransport]:
    transport = _FakeTransport(result_for_form=result_for_form)
    client = _make_client(transport)
    _login(client, transport)
    client.login()
    # After login the AES pair is fixed; subsequent forms reuse it.
    assert client._session is not None
    transport.set_aes(client._session.keys.aes_key, client._session.keys.aes_iv)
    return client, transport


def test_get_device_list() -> None:
    payload = {
        "device_list": [
            {"mac": "0c-ef-15-e1-b2-16", "device_model": "BE65"},
            {"mac": "aa:bb:cc:dd:ee:ff", "device_model": "X20"},
            "not-an-object",
        ]
    }
    client, _ = _logged_in({"device_list": payload})
    devices = client.get_device_list()
    assert all(isinstance(d, Device) for d in devices)
    assert len(devices) == 2
    assert devices[0].mac == "0C:EF:15:E1:B2:16"
    assert devices[0].device_model == "BE65"


def test_get_device_list_missing_key_returns_empty() -> None:
    client, _ = _logged_in({"device_list": {}})
    assert client.get_device_list() == []


def test_get_device_mode() -> None:
    payload = {"workmode": "router", "sysmode": "router", "region": {"device": "EU"}}
    client, _ = _logged_in({"mode": payload})
    mode = client.get_device_mode()
    assert isinstance(mode, DeviceMode)
    assert mode.workmode == "router"
    assert mode.region == "EU"


def test_get_wlan_config() -> None:
    payload = {"band2_4": {"host": {"ssid": "", "channel": 6}}}
    client, _ = _logged_in({"wlan": payload})
    wlan = client.get_wlan_config()
    assert isinstance(wlan, WlanConfig)
    assert wlan.band2_4.host.channel == 6


def test_get_performance() -> None:
    client, _ = _logged_in({"performance": {"cpu_usage": 0.05, "mem_usage": 0.42}})
    perf = client.get_performance()
    assert isinstance(perf, Performance)
    assert perf.cpu_usage == pytest.approx(0.05)
    assert perf.mem_usage == pytest.approx(0.42)


def test_get_client_list() -> None:
    payload = {
        "client_list": [
            {"mac": "AA:BB:CC:DD:EE:01", "up_speed": 100, "down_speed": 200},
            {"mac": "AA:BB:CC:DD:EE:02", "up_speed": 50, "down_speed": 75},
        ]
    }
    client, _ = _logged_in({"client_list": payload})
    clients = client.get_client_list()
    assert all(isinstance(c, ClientDevice) for c in clients)
    assert len(clients) == 2
    assert clients[0].up_speed == 100


def test_get_client_list_custom_mac_in_request() -> None:
    payload = {"client_list": []}
    client, transport = _logged_in({"client_list": payload})
    client.get_client_list(deco_mac="AA:BB:CC:DD:EE:FF")
    assert any("form=client_list" in u for u in transport.posted_urls)


def test_get_client_totals() -> None:
    payload = {
        "client_list": [
            {"mac": "AA:BB:CC:DD:EE:01", "up_speed": 100, "down_speed": 200},
            {"mac": "AA:BB:CC:DD:EE:02", "up_speed": 50, "down_speed": 75},
        ]
    }
    client, _ = _logged_in({"client_list": payload})
    totals = client.get_client_totals()
    assert isinstance(totals, NetworkTotals)
    assert totals.up_speed == 150
    assert totals.down_speed == 275


def test_get_address_reservations() -> None:
    payload = {
        "reservation_list": [
            {"mac": "aa-bb-cc-dd-ee-01", "ip": "192.168.68.100"},
            {"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.68.101"},
            "not-an-object",
        ],
        "reservation_list_max_count": 2,
    }
    client, transport = _logged_in({"addr_reservation": payload})

    table = client.get_address_reservations()

    assert isinstance(table, AddressReservationTable)
    assert all(isinstance(item, AddressReservation) for item in table.reservations)
    assert table.reservations[0].mac == "AA:BB:CC:DD:EE:01"
    assert table.reservations[0].ip == "192.168.68.100"
    assert table.max_count == 2
    assert table.is_full
    assert any("form=addr_reservation" in url for url in transport.posted_urls)


def test_get_clients_by_node_preserves_topology() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    devices = [
        Device.from_api({"mac": "AA:BB:CC:DD:EE:01"}),
        Device.from_api({"mac": "AA:BB:CC:DD:EE:02"}),
    ]
    clients = {
        devices[0].mac: [ClientDevice.from_api({"mac": "00:00:00:00:00:01"})],
        devices[1].mac: [ClientDevice.from_api({"mac": "00:00:00:00:00:02"})],
    }

    with (
        mock.patch.object(client, "get_device_list", return_value=devices),
        mock.patch.object(
            client,
            "get_client_list",
            side_effect=lambda node_mac: clients[node_mac],
        ) as get_clients,
    ):
        topology = client.get_clients_by_node()

    assert all(isinstance(item, NodeClientList) for item in topology)
    assert tuple(item.node_mac for item in topology) == tuple(device.mac for device in devices)
    assert topology[0].clients[0].mac == "00:00:00:00:00:01"
    assert topology[1].to_dict()["clients"][0]["mac"] == "00:00:00:00:00:02"
    assert get_clients.call_args_list == [mock.call(devices[0].mac), mock.call(devices[1].mac)]


def test_get_address_reservations_missing_list_returns_empty_table() -> None:
    client, _ = _logged_in({"addr_reservation": {}})

    table = client.get_address_reservations()

    assert table.reservations == ()
    assert table.max_count == 0
    assert not table.is_full


def test_get_speed_test_returns_observed_p9_fields() -> None:
    client, _ = _logged_in(
        {
            "speedtest": {
                "down_speed": 500,
                "up_speed": 100,
                "status": "idle",
                "ever_tested": True,
                "last_speed_test_time": 1_720_000_000,
            }
        }
    )

    result = client.get_speed_test()

    assert isinstance(result, SpeedTest)
    assert result.down_speed == 500
    assert result.up_speed == 100
    assert result.status == "idle"
    assert result.ever_tested
    assert result.last_speed_test_time == 1_720_000_000


def test_request_url_includes_stok() -> None:
    client, transport = _logged_in({"mode": {"workmode": "router", "sysmode": "router"}})
    client.get_device_mode()
    admin_urls = [u for u in transport.posted_urls if "admin/device" in u]
    assert admin_urls
    assert f";stok={transport.login_stok}/" in admin_urls[-1]


def test_request_envelope_preserves_firmware_fields() -> None:
    client, transport = _logged_in({})
    real_post_form = transport.post_form

    def response_with_metadata(url: str, body: str) -> JsonObject:
        if "form=mode" in url:
            return transport._envelope(
                {
                    "result": {"workmode": "FAP"},
                    "error_code": 0,
                    "config_version": 42,
                    "vendor_extension": {"enabled": True},
                }
            )
        return real_post_form(url, body)

    transport.post_form = response_with_metadata  # type: ignore[assignment]

    response = client.request_envelope("admin/device", "mode", {"operation": "read"})

    assert isinstance(response, ApiResponse)
    assert response.result == {"workmode": "FAP"}
    assert response.config_version == 42
    assert response.payload["vendor_extension"] == {"enabled": True}


def test_request_envelope_uses_plain_transport_when_declared() -> None:
    client, transport = _logged_in({"envar": {"ui_language": "EN_US"}})

    response = client.request_envelope(
        "admin/system",
        "envar",
        {"operation": "read"},
    )

    assert response.result == {"ui_language": "EN_US"}
    assert any("form=envar" in url for url in transport.posted_urls)


def test_call_uses_endpoint_default_and_explicit_params() -> None:
    client, _ = _logged_in({"client_list": {"client_list": []}})
    endpoint = EndpointSpec(
        "admin/client",
        "client_list",
        "read",
        default_params={"device_mac": "default"},
    )

    default_response = client.call(endpoint)
    explicit_response = client.call(endpoint, {"device_mac": "AA:BB:CC:DD:EE:FF"})

    assert default_response.result == {"client_list": []}
    assert explicit_response.result == {"client_list": []}


def test_call_bootstrap_supports_only_plaintext_login_reads() -> None:
    transport = _FakeTransport(
        result_for_form={"check_factory_default": {"factory_default": False}}
    )
    client = _make_client(transport)
    endpoint = get_endpoint("login.check_factory_default.read")

    response = client.call_bootstrap(endpoint)

    assert response.result == {"factory_default": False}
    assert transport.posted_urls == [
        "https://192.0.2.1/cgi-bin/luci/;stok=/login?form=check_factory_default"
    ]
    assert not client.is_authenticated()
    with pytest.raises(ValueError, match="not a supported plaintext login read"):
        client.call_bootstrap(get_endpoint("domain_login.dlogin.read"))
    with pytest.raises(ValueError, match="not a supported plaintext login read"):
        client.call_bootstrap(get_endpoint("login.login.login"))


def test_domain_login_read_uses_authenticated_encrypted_call() -> None:
    client, transport = _logged_in({})
    endpoint = get_endpoint("domain_login.dlogin.read")

    with mock.patch.object(transport, "post_form", wraps=transport.post_form) as post:
        response = client.call(endpoint)

    assert response.result == {}
    assert f";stok={transport.login_stok}/domain_login?form=dlogin" in post.call_args.args[0]
    assert post.call_args.args[1].startswith("sign=")
    assert "&data=" in post.call_args.args[1]


def test_call_omits_form_selector_when_catalogued() -> None:
    client, transport = _logged_in({})

    client.call(get_endpoint("admin.route.route.read"))

    assert transport.posted_urls[-1].endswith("/admin/route")
    assert "?form=" not in transport.posted_urls[-1]


def test_call_directs_binary_endpoint_to_binary_method() -> None:
    client, _ = _logged_in({})
    endpoint = EndpointSpec(
        "admin/log_export",
        "save_log",
        "download",
        authentication="download",
        response_kind="binary",
        sensitivity="secret",
        media_type="application/octet-stream",
    )

    with pytest.raises(ValueError, match="use call_binary"):
        client.call(endpoint)

    response = client.call_binary(endpoint)

    assert response.endpoint == endpoint.name
    assert response.content == b"downloaded log\n"
    assert response.media_type == "application/octet-stream"
    assert response.size == 15
    assert len(response.sha256) == 64
    assert "content_base64" not in response.to_dict()
    assert response.to_dict(include_content=True)["content_base64"] == "ZG93bmxvYWRlZCBsb2cK"


def test_call_binary_rejects_json_endpoint() -> None:
    client, _ = _logged_in({})
    endpoint = EndpointSpec("admin/network", "performance", "read")

    with pytest.raises(ValueError, match="endpoint is not binary"):
        client.call_binary(endpoint)


def test_call_binary_sends_encrypted_operation_for_config_backup() -> None:
    client, transport = _logged_in({})
    endpoint = get_endpoint("admin.firmware.config.backup")

    with mock.patch.object(transport, "post_bytes", wraps=transport.post_bytes) as post:
        response = client.call_binary(endpoint)

    assert response.media_type == "application/octet-stream"
    assert "form=config" in post.call_args.args[0]
    assert post.call_args.args[1].startswith(b"sign=")
    assert b"&data=" in post.call_args.args[1]


def test_call_binary_sends_exact_multipart_backup_contract() -> None:
    client, transport = _logged_in({})
    endpoint = get_endpoint("admin.firmware.config_multipart.backup")

    response = client.call_binary(endpoint)

    assert response.content == b"encrypted backup"
    assert transport.multipart_posts == [
        (
            (
                "https://192.0.2.1/cgi-bin/luci/;stok=deadbeefstoktoken/"
                "admin/firmware?form=config_multipart"
            ),
            {"operation": "backup"},
        )
    ]
    with pytest.raises(ValueError, match="does not accept params"):
        client.call_binary(endpoint, {})


def test_probe_endpoints_classifies_results() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    endpoints = tuple(EndpointSpec("admin/test", f"form_{index}", "read") for index in range(5))
    supported = ApiResponse.from_api({"error_code": 0, "result": {"ok": True}})
    side_effects = (
        supported,
        ApiError(-7, "invalid args"),
        TransportError("Failed to POST endpoint: HTTP 404", status_code=404),
        TransportError("Failed to POST endpoint: timed out"),
        ValueError("invalid response"),
    )

    with mock.patch.object(client, "call", side_effect=side_effects):
        report = client.probe_endpoints(endpoints)

    assert isinstance(report, CapabilityReport)
    assert tuple(probe.status for probe in report.probes) == (
        "supported",
        "rejected",
        "not_found",
        "transport_error",
        "invalid_response",
    )
    assert report.probes[1].error_code == -7
    assert report.probes[2].http_status == 404
    assert report.supported_names == (endpoints[0].name,)
    assert report.to_dict()["supported"] == [endpoints[0].name]


def test_probe_endpoints_rejects_unsafe_specs_before_calling() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    endpoint = EndpointSpec(
        "admin/device",
        "factory",
        "write",
        safety="destructive",
    )

    with (
        mock.patch.object(client, "call") as call,
        pytest.raises(PermissionError, match="unsafe operations"),
    ):
        client.probe_endpoints((endpoint,))

    call.assert_not_called()


def test_probe_endpoint_passes_explicit_parameters() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    endpoint = get_endpoint("admin.wireless.power.read")
    response = ApiResponse.from_api({"error_code": 0, "result": {"enable": True}})

    with mock.patch.object(client, "call", return_value=response) as call:
        result = client.probe_endpoint(endpoint, {})

    assert result.status == "supported"
    call.assert_called_once_with(endpoint, {})


def test_probe_endpoint_rejects_secret_read_before_calling() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    endpoint = get_endpoint("admin.wireless.wlan.read")

    with (
        mock.patch.object(client, "call") as call,
        pytest.raises(PermissionError, match="unsafe operation"),
    ):
        client.probe_endpoint(endpoint)

    call.assert_not_called()


def test_observe_endpoint_schema_requires_opt_in_and_discards_values() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    endpoint = get_endpoint("admin.wireless.wlan.read")
    response = ApiResponse.from_api(
        {
            "error_code": 0,
            "result": {"band2_4": {"host": {"ssid": "private", "password": "secret"}}},
        }
    )

    with (
        mock.patch.object(client, "call", return_value=response) as call,
        pytest.raises(PermissionError, match="sensitive reads require explicit opt-in"),
    ):
        client.observe_endpoint_schema(endpoint)
    call.assert_not_called()

    with mock.patch.object(client, "call", return_value=response):
        observation = client.observe_endpoint_schema(endpoint, include_sensitive=True)

    payload = str(observation.to_dict())
    assert observation.status == "supported"
    assert "$.band2_4.host.password:string" in observation.schema_paths
    assert "private" not in payload
    assert "secret" not in payload


def test_observe_endpoint_schema_dispatches_bootstrap_read() -> None:
    client = DecoClient("192.0.2.1", "", "")
    endpoint = get_endpoint("login.check_factory_default.read")
    response = ApiResponse.from_api({"error_code": 0, "result": {"factory_default": False}})

    with mock.patch.object(client, "call_bootstrap", return_value=response) as call:
        observation = client.observe_endpoint_schema(endpoint)

    call.assert_called_once_with(endpoint, None)
    assert observation.status == "supported"
    assert observation.schema_paths == (
        "$.factory_default:boolean",
        "$:object",
    )


def test_observe_endpoint_schema_rejects_mutation() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    endpoint = get_endpoint("admin.network.wan_mode.write")

    with (
        mock.patch.object(client, "call") as call,
        pytest.raises(PermissionError, match="non-read operation"),
    ):
        client.observe_endpoint_schema(endpoint, include_sensitive=True)

    call.assert_not_called()


def test_discover_read_endpoints_uses_complete_safe_catalog() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")
    report = CapabilityReport("192.0.2.1", "2026-07-10T00:00:00Z", ())

    with mock.patch.object(client, "probe_endpoints", return_value=report) as probe:
        assert client.discover_read_endpoints() is report

    endpoint_specs = probe.call_args.args[0]
    assert get_endpoint("admin.device.mini_device_list.read") in endpoint_specs
    assert get_endpoint("admin.smart_network.patrol_filter.get") in endpoint_specs
    assert get_endpoint("login.auth.read") in endpoint_specs
    assert get_endpoint("login.check_factory_default.read") in endpoint_specs
    assert get_endpoint("login.default_info.read") not in endpoint_specs
    assert get_endpoint("admin.wireless.wlan.read") not in endpoint_specs


def test_new_p9_data_getters_return_complete_objects() -> None:
    payloads = {
        "switch_list": {"show_performance": True},
        "extra_component_info": {"enable_fast_xmit": True},
        "mobile": {"component_list": ["speed_test"]},
        "get_support": {"model": "P9"},
        "dhcp_info": {"startIpAddress": "192.168.68.100"},
        "lease": {"lease_list": []},
        "traffic_stat": {"client_list": []},
        "lan_ipv4": {"ip": "192.168.68.1"},
        "lan_ip": {"lan_ip": {"ip": "192.168.68.1"}},
        "ipv6": {"enable_ipv6": False},
        "routes_system": {"route_list": []},
        "gateway": {"supported": True},
        "system": {"nickname": "living_room"},
        "signal_level_list": {"signal_level_list": []},
        "led": {"enable": True},
        "bridge": {"status": "connected"},
        "ieee80211r": {"enable": True},
        "beamforming": {"enable": True},
        "operation_mode": {"mode": "mesh"},
        "igmp_setting": {"enable": True},
        "fast_xmit_setting": {"enable": True},
    }
    client, _ = _logged_in(payloads)

    results = (
        client.get_component_switches(),
        client.get_extra_component_info(),
        client.get_mobile_components(),
        client.get_wireless_support(),
        client.get_dhcp_info(),
        client.get_dhcp_leases(),
        client.get_traffic_statistics(),
        client.get_lan_ipv4(),
        client.get_lan_ip(),
        client.get_ipv6_config(),
        client.get_system_routes(),
        client.get_gateway_info(),
        client.get_device_system(),
        client.get_signal_levels(),
        client.get_led_settings(),
        client.get_bridge_status(),
        client.get_fast_roaming(),
        client.get_beamforming(),
        client.get_wireless_operation_mode(),
        client.get_igmp_settings(),
        client.get_fast_transmit_settings(),
    )

    assert all(result for result in results)


def test_p9_getters_use_observed_operation_aliases_and_default_time_shape() -> None:
    client = DecoClient("192.0.2.1", "admin", "secret")

    with mock.patch.object(client, "request", return_value={}) as request:
        client.get_traffic_statistics()
        client.get_bridge_status()
        client.get_time_settings()
        client.get_time_settings("AA:BB:CC:DD:EE:FF")

    assert request.call_args_list == [
        mock.call("admin/client", "traffic_stat", {"operation": "list"}),
        mock.call("admin/wireless", "bridge", {"operation": "read"}),
        mock.call("admin/device", "timesetting", {"operation": "read"}),
        mock.call(
            "admin/device",
            "timesetting",
            {
                "operation": "read",
                "params": {"device_mac": "AA:BB:CC:DD:EE:FF"},
            },
        ),
    ]


def test_request_propagates_api_error() -> None:
    transport = _FakeTransport()
    client = _make_client(transport)
    _login(client, transport)
    client.login()
    assert client._session is not None
    keys = client._session.keys
    transport.set_aes(keys.aes_key, keys.aes_iv)

    real_post_form = transport.post_form

    def error_post(url: str, body: str) -> JsonObject:
        if "form=mode" in url:
            inner = {"result": {}, "error_code": -5002}
            return transport._envelope(inner)
        return real_post_form(url, body)

    transport.post_form = error_post  # type: ignore[assignment]
    with pytest.raises(ApiError) as exc:
        client.get_device_mode()
    assert exc.value.error_code == -5002


def test_context_manager_logs_in_and_out() -> None:
    transport = _FakeTransport()
    client = _make_client(transport)
    _login(client, transport)
    with client as ctx:
        assert ctx is client
        assert client.is_authenticated()
    assert not client.is_authenticated()


def test_build_and_parse_roundtrip_matches_client_payload() -> None:
    """Sanity check that the protocol encode/decode the client relies on roundtrips."""
    keys = SessionKeys(
        aes_key="1234567890123456",
        aes_iv="6543210987654321",
        session_hash="a" * 32,
        seq=5,
    )
    from tplink_deco_api.models.rsa_key import RsaKey

    sign_key = RsaKey(n=_SIGN_N, e=0x10001)
    body = build_payload(keys, sign_key, {"operation": "read"})
    assert body.startswith("sign=")
    inner = {"result": {"ok": True}, "error_code": 0}
    envelope = {"data": aes_encrypt(keys.aes_key, keys.aes_iv, json.dumps(inner))}
    assert parse_response(envelope, keys) == {"ok": True}
