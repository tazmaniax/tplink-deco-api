"""High-level synchronous client for the TP-Link Deco HTTP API."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from . import endpoints
from ._json import JsonObject, JsonValue, get_int, get_object, get_str, get_str_tuple
from .auth.protocol import (
    build_payload,
    parse_encrypted_response,
    parse_plain_envelope,
    parse_response,
)
from .auth.session import SessionContext
from .auth.transport import HttpTransport
from .crypto import generate_aes_pair, md5_session_hash, rsa_encrypt
from .endpoint_catalog import (
    CAPABILITY_ENDPOINTS,
    DISCOVERABLE_READ_ENDPOINTS,
    P9_READ_ENDPOINTS,
)
from .exceptions import ApiError, AuthenticationError, DecoError, TransportError
from .models import (
    AddressReservationTable,
    ApiResponse,
    BinaryResponse,
    CapabilityReport,
    ClientDevice,
    Device,
    DeviceMode,
    DslStatus,
    EndpointObservation,
    EndpointProbeResult,
    InternetStatus,
    LoginResult,
    LogType,
    NetworkTotals,
    NodeClientList,
    Performance,
    SpeedTest,
    SystemLogPage,
    TimeSettings,
    WanInfo,
    WirelessPower,
    WlanConfig,
)
from .models.rsa_key import RsaKey
from .models.session_keys import SessionKeys

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from .endpoint_spec import AuthenticationMode, EndpointSpec

log: logging.Logger = logging.getLogger("tplink_deco_api.client")


class DecoClient:
    """High-level client that handles handshake, encryption and typed responses."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        timeout: float = 10.0,
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._transport = HttpTransport(timeout=timeout)
        self._session: SessionContext | None = None

    def __enter__(self) -> DecoClient:
        self.login()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self.logout()
            return
        try:
            self.logout()
        except DecoError as logout_error:
            log.warning("Failed to logout after an exception: %s", logout_error)

    def login(self) -> LoginResult:
        """Perform the RSA + AES handshake and obtain a session token."""
        auth_raw = self._transport.post_json(
            endpoints.login_url(self._host, "auth"),
            {"operation": "read"},
        )
        keys_raw = self._transport.post_json(
            endpoints.login_url(self._host, "keys"),
            {"operation": "read"},
        )

        sign_key_parts = get_str_tuple(_result(auth_raw), "key")
        pwd_key_parts = get_str_tuple(_result(keys_raw), "password")
        if len(sign_key_parts) < 2 or len(pwd_key_parts) < 2:
            raise AuthenticationError("Failed to login: RSA key handshake malformed")

        sign_key = RsaKey.from_hex(sign_key_parts[0], sign_key_parts[1])
        pwd_key = RsaKey.from_hex(pwd_key_parts[0], pwd_key_parts[1])
        seq = get_int(_result(auth_raw), "seq")

        aes_key, aes_iv = generate_aes_pair()
        session_hash = md5_session_hash(self._username, self._password)
        keys = SessionKeys(
            aes_key=aes_key,
            aes_iv=aes_iv,
            session_hash=session_hash,
            seq=seq,
        )
        self._session = SessionContext(sign_key=sign_key, pwd_key=pwd_key, keys=keys)

        password_encrypted = rsa_encrypt(pwd_key.n, pwd_key.e, self._password.encode())
        login_body = build_payload(
            keys,
            sign_key,
            {"operation": "login", "params": {"password": password_encrypted}},
        )
        raw = self._transport.post_form(endpoints.login_url(self._host, "login"), login_body)

        result = parse_response(raw, keys)
        stok = get_str(result, "stok")
        if not stok:
            raise AuthenticationError("Failed to login: missing stok in response")

        self._session.stok = stok
        log.info("Logged in to %s", self._host)
        return LoginResult(stok=stok, usr_lvl=get_int(result, "usrLvl", default=1))

    def logout(self) -> None:
        """End the server session and always forget local authentication state."""
        if self._session is None or not self._session.is_authenticated():
            return
        try:
            try:
                self.request_envelope(
                    "admin/system",
                    "logout",
                    {"operation": "write"},
                )
            except TransportError as exc:
                if exc.status_code != 404:
                    raise
                log.info(
                    "Server-side logout is unavailable on %s; cleared local session", self._host
                )
        finally:
            self.invalidate_session()

    def invalidate_session(self) -> None:
        """Forget local authentication state without making a router request."""
        if self._session is not None:
            self._session.invalidate()
        self._transport.clear_session()

    def is_authenticated(self) -> bool:
        """Return ``True`` while a valid session token is held."""
        return self._session is not None and self._session.is_authenticated()

    def request(
        self,
        path: str,
        form: str,
        data: Mapping[str, JsonValue],
    ) -> JsonObject:
        """Send an authenticated request and return the decrypted ``result``."""
        return self.request_envelope(path, form, data).result_object()

    def request_envelope(
        self,
        path: str,
        form: str,
        data: Mapping[str, JsonValue],
        *,
        authentication: AuthenticationMode | None = None,
        form_selector: bool = True,
    ) -> ApiResponse:
        """Send a request while preserving every field in the response envelope."""
        session = self._require_auth()
        url = endpoints.endpoint_url(
            self._host,
            session.stok,
            path,
            form if form_selector else None,
        )
        selected_authentication = authentication
        if selected_authentication is None:
            selected_authentication = (
                "plain" if endpoints.is_plain_endpoint(path, form) else "encrypted"
            )
        if selected_authentication == "plain":
            raw = self._transport.post_json(url, data)
            return parse_plain_envelope(raw)
        if selected_authentication != "encrypted":
            raise ValueError(
                f"Failed to call API: transport {selected_authentication!r} "
                "is not supported by the owner-session client"
            )
        body = build_payload(session.keys, session.sign_key, data)
        raw = self._transport.post_form(url, body)
        return parse_encrypted_response(raw, session.keys)

    def request_value(
        self,
        path: str,
        form: str,
        data: Mapping[str, JsonValue],
    ) -> JsonValue:
        """Send an authenticated request and return any JSON result shape."""
        return self.request_envelope(path, form, data).result

    def call(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
    ) -> ApiResponse:
        """Call a catalogued operation using its declared transport metadata."""
        if endpoint.response_kind == "binary":
            raise ValueError("Failed to call API: use call_binary() for a binary response")
        return self.request_envelope(
            endpoint.path,
            endpoint.form,
            endpoint.request_data(params),
            authentication=endpoint.authentication,
            form_selector=endpoint.form_selector,
        )

    def call_bootstrap(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
    ) -> ApiResponse:
        """Call one documented plaintext login read without creating a session."""
        if not endpoint.bootstrap_call_supported:
            raise ValueError(
                f"Failed to call bootstrap API: {endpoint.name} is not a supported "
                "plaintext login read"
            )
        raw = self._transport.post_json(
            endpoints.login_url(self._host, endpoint.form),
            endpoint.request_data(params),
        )
        return parse_plain_envelope(raw)

    def call_binary(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
    ) -> BinaryResponse:
        """Call a catalogued download endpoint without decoding its response."""
        if not endpoint.binary_call_supported:
            raise ValueError("Failed to download API response: endpoint is not binary")
        session = self._require_auth()
        url = endpoints.endpoint_url(
            self._host,
            session.stok,
            endpoint.path,
            endpoint.form if endpoint.form_selector else None,
        )
        if endpoint.authentication == "multipart":
            if params is not None:
                raise ValueError(
                    "Failed to download API response: multipart backup does not accept params"
                )
            content = self._transport.post_multipart_fields(
                url,
                {"operation": "backup"},
            )
        elif endpoint.authentication == "download":
            content = self._transport.post_bytes(url)
        else:
            body = build_payload(
                session.keys,
                session.sign_key,
                endpoint.request_data(params),
            )
            content = self._transport.post_bytes(url, body.encode())
        return BinaryResponse(
            endpoint=endpoint.name,
            content=content,
            media_type=endpoint.media_type,
        )

    def request_list(
        self,
        path: str,
        form: str,
        data: Mapping[str, JsonValue],
    ) -> list[JsonObject]:
        """Send an authenticated request and return the decrypted ``result`` as a list.

        Use instead of :meth:`request` when the endpoint returns a JSON array
        rather than a JSON object under the ``result`` key.
        """
        return self.request_envelope(path, form, data).result_list()

    def probe_endpoints(
        self,
        endpoint_specs: tuple[EndpointSpec, ...],
    ) -> CapabilityReport:
        """Probe explicitly supplied non-secret reads and report observed behavior."""
        unsafe = tuple(
            endpoint.name
            for endpoint in endpoint_specs
            if endpoint.safety != "read_only" or endpoint.sensitivity == "secret"
        )
        if unsafe:
            joined = ", ".join(unsafe)
            raise PermissionError(f"Failed to probe endpoints: unsafe operations: {joined}")

        probes = [self.probe_endpoint(endpoint) for endpoint in endpoint_specs]

        return CapabilityReport(
            host=self._host,
            observed_at=datetime.now(UTC).isoformat(),
            probes=tuple(probes),
        )

    def probe_endpoint(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
    ) -> EndpointProbeResult:
        """Probe one non-secret read with optional parameters and classify its outcome."""
        if endpoint.safety != "read_only" or endpoint.sensitivity == "secret":
            raise PermissionError(f"Failed to probe endpoint: unsafe operation: {endpoint.name}")
        return self._probe_endpoint(endpoint, params)

    def observe_endpoint_schema(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
        *,
        include_sensitive: bool = False,
    ) -> EndpointObservation:
        """Observe a read response schema while discarding all response values."""
        if endpoint.safety != "read_only":
            raise PermissionError(
                f"Failed to observe endpoint schema: non-read operation: {endpoint.name}"
            )
        if endpoint.sensitivity == "secret" and not include_sensitive:
            raise PermissionError(
                "Failed to observe endpoint schema: sensitive reads require explicit opt-in"
            )
        return EndpointObservation.from_probe(self._probe_endpoint(endpoint, params))

    def _probe_endpoint(
        self,
        endpoint: EndpointSpec,
        params: Mapping[str, JsonValue] | None = None,
    ) -> EndpointProbeResult:
        started = time.monotonic()
        try:
            response = (
                self.call_bootstrap(endpoint, params)
                if endpoint.bootstrap_call_supported
                else self.call(endpoint, params)
            )
        except ApiError as exc:
            return EndpointProbeResult(
                endpoint=endpoint,
                status="rejected",
                elapsed_seconds=time.monotonic() - started,
                error_code=exc.error_code,
                error=str(exc),
            )
        except TransportError as exc:
            return EndpointProbeResult(
                endpoint=endpoint,
                status="not_found" if exc.status_code == 404 else "transport_error",
                elapsed_seconds=time.monotonic() - started,
                http_status=exc.status_code,
                error=str(exc),
            )
        except (DecoError, TypeError, ValueError) as exc:
            return EndpointProbeResult(
                endpoint=endpoint,
                status="invalid_response",
                elapsed_seconds=time.monotonic() - started,
                error=str(exc),
            )
        return EndpointProbeResult(
            endpoint=endpoint,
            status="supported",
            elapsed_seconds=time.monotonic() - started,
            response=response,
        )

    def discover_capabilities(self) -> CapabilityReport:
        """Probe the firmware's dedicated non-secret capability endpoints."""
        return self.probe_endpoints(CAPABILITY_ENDPOINTS)

    def discover_p9_read_endpoints(self) -> CapabilityReport:
        """Probe the curated non-secret P9 read surface without invoking writes."""
        return self.probe_endpoints(P9_READ_ENDPOINTS)

    def discover_read_endpoints(self) -> CapabilityReport:
        """Probe every catalogued non-secret read supported by the owner-session client."""
        return self.probe_endpoints(DISCOVERABLE_READ_ENDPOINTS)

    def get_component_switches(self) -> JsonObject:
        """Return web-interface feature switches advertised by the firmware."""
        return self.request(
            "admin/component_control",
            "switch_list",
            {"operation": "read"},
        )

    def get_extra_component_info(self) -> JsonObject:
        """Return additional model-derived feature flags."""
        return self.request(
            "admin/web",
            "extra_component_info",
            {"operation": "get"},
        )

    def get_mobile_components(self) -> JsonObject:
        """Return the feature list used by the Deco mobile application."""
        return self.request(
            "admin/component_list",
            "mobile",
            {"operation": "read"},
        )

    def get_wireless_support(self) -> JsonObject:
        """Return radio and band capabilities advertised by the firmware."""
        return self.request(
            "admin/wireless",
            "get_support",
            {"operation": "read"},
        )

    def get_dhcp_info(self) -> JsonObject:
        """Return the DHCP server pool, DNS, gateway and usage state."""
        return self.request("admin/dhcp", "dhcp_info", {"operation": "read"})

    def get_dhcp_leases(self) -> JsonObject:
        """Return the firmware's current DHCP lease table."""
        return self.request("admin/client", "lease", {"operation": "get"})

    def get_traffic_statistics(self) -> JsonObject:
        """Return per-client speeds and cumulative traffic counters."""
        return self.request("admin/client", "traffic_stat", {"operation": "list"})

    def get_lan_ipv4(self, device_mac: str = "default") -> JsonObject:
        """Return the raw LAN IPv4 snapshot for one mesh node."""
        return self.request(
            "admin/network",
            "lan_ipv4",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )

    def get_lan_ip(self, device_mac: str = "default") -> JsonObject:
        """Return the LAN address and subnet configuration for one mesh node."""
        return self.request(
            "admin/network",
            "lan_ip",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )

    def get_ipv6_config(self, device_mac: str = "default") -> JsonObject:
        """Return the complete IPv6 WAN and LAN configuration."""
        return self.request(
            "admin/network",
            "ipv6",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )

    def get_system_routes(self) -> JsonObject:
        """Return routes created automatically by the firmware."""
        return self.request("admin/network", "routes_system", {"operation": "getlist"})

    def get_gateway_info(self) -> JsonObject:
        """Return gateway-role capabilities for the mesh."""
        return self.request("admin/device", "gateway", {"operation": "read"})

    def get_device_system(self, device_mac: str = "default") -> JsonObject:
        """Return raw system settings for one mesh node."""
        return self.request(
            "admin/device",
            "system",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )

    def get_signal_levels(self) -> JsonObject:
        """Return per-node backhaul signal levels."""
        return self.request("admin/device", "signal_level_list", {"operation": "read"})

    def get_led_settings(self, device_mac: str = "default") -> JsonObject:
        """Return LED state and schedule settings for one mesh node."""
        return self.request(
            "admin/device",
            "led",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )

    def get_bridge_status(self) -> JsonObject:
        """Return the Wi-Fi bridge and mesh backhaul status."""
        return self.request("admin/wireless", "bridge", {"operation": "read"})

    def get_fast_roaming(self) -> JsonObject:
        """Return the 802.11r fast-roaming configuration."""
        return self.request("admin/wireless", "ieee80211r", {"operation": "read"})

    def get_beamforming(self) -> JsonObject:
        """Return the beamforming configuration."""
        return self.request("admin/wireless", "beamforming", {"operation": "read"})

    def get_wireless_operation_mode(self) -> JsonObject:
        """Return the Wi-Fi subsystem operation mode."""
        return self.request("admin/wireless", "operation_mode", {"operation": "read"})

    def get_igmp_settings(self) -> JsonObject:
        """Return IGMP snooping and proxy settings."""
        return self.request("admin/network", "igmp_setting", {"operation": "read"})

    def get_fast_transmit_settings(self) -> JsonObject:
        """Return fast-transmit acceleration settings."""
        return self.request("admin/network", "fast_xmit_setting", {"operation": "read"})

    def get_device_list(self) -> list[Device]:
        """Return all Deco mesh nodes."""
        result = self.request("admin/device", "device_list", {"operation": "read"})
        return [Device.from_api(item) for item in _list_of_objects(result, "device_list")]

    def get_device_mode(self) -> DeviceMode:
        """Return the device operating mode (router / AP / mesh)."""
        result = self.request("admin/device", "mode", {"operation": "read"})
        return DeviceMode.from_api(result)

    def get_wlan_config(self) -> WlanConfig:
        """Return the full Wi-Fi configuration across all bands."""
        result = self.request("admin/wireless", "wlan", {"operation": "read"})
        return WlanConfig.from_api(result)

    def get_performance(self) -> Performance:
        """Return CPU and memory usage of the gateway node."""
        result = self.request("admin/network", "performance", {"operation": "read"})
        return Performance.from_api(result)

    def get_speed_test(self) -> SpeedTest:
        """Return the latest observed internet speed-test state and result."""
        result = self.request("admin/device", "speedtest", {"operation": "read"})
        return SpeedTest.from_api(result)

    def get_client_list(self, deco_mac: str = "default") -> list[ClientDevice]:
        """Return every client connected to ``deco_mac`` (or all nodes by default)."""
        result = self.request(
            "admin/client",
            "client_list",
            {"operation": "read", "params": {"device_mac": deco_mac}},
        )
        return [ClientDevice.from_api(item) for item in _list_of_objects(result, "client_list")]

    def get_client_totals(self, deco_mac: str = "default") -> NetworkTotals:
        """Return aggregated up/down speeds across all clients."""
        return NetworkTotals.from_clients(self.get_client_list(deco_mac))

    def get_clients_by_node(self) -> tuple[NodeClientList, ...]:
        """Query each mesh node separately and preserve client-to-node association."""
        return tuple(
            NodeClientList(
                node_mac=device.mac,
                clients=tuple(self.get_client_list(device.mac)),
            )
            for device in self.get_device_list()
            if device.mac
        )

    def get_address_reservations(self) -> AddressReservationTable:
        """Return the DHCP static-reservation table and its maximum size."""
        result = self.request(
            "admin/client",
            "addr_reservation",
            {"operation": "getlist"},
        )
        return AddressReservationTable.from_api(result)

    def get_internet_status(self) -> InternetStatus:
        """Return WAN connection status including IPv4, IPv6 and physical link state."""
        result = self.request("admin/network", "internet", {"operation": "read"})
        return InternetStatus.from_api(result)

    def get_wan_info(self, device_mac: str = "default") -> WanInfo:
        """Return WAN and LAN IP configuration for ``device_mac``."""
        result = self.request(
            "admin/network",
            "wan_ipv4",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )
        return WanInfo.from_api(result)

    def get_dsl_status(self, device_mac: str = "default") -> DslStatus:
        """Return DSL link status for ``device_mac``.

        Only meaningful on DSL-capable hardware. Some non-DSL models return an
        empty result, in which case every field defaults to an empty string or
        zero; others reject the ``dsl_status`` form and raise
        :class:`~tplink_deco_api.ApiError`. Callers targeting mixed hardware
        should be prepared to catch that exception.
        """
        result = self.request(
            "admin/network",
            "dsl_status",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )
        return DslStatus.from_api(result)

    def get_wireless_power(self, device_mac: str = "default") -> WirelessPower:
        """Return transmit power settings for ``device_mac``."""
        result = self.request(
            "admin/wireless",
            "power",
            {"operation": "read", "params": {"device_mac": device_mac}},
        )
        return WirelessPower.from_api(result)

    def get_time_settings(self, device_mac: str = "default") -> TimeSettings:
        """Return date, time and timezone settings for ``device_mac``."""
        data: dict[str, JsonValue] = {"operation": "read"}
        if device_mac != "default":
            data["params"] = {"device_mac": device_mac}
        result = self.request(
            "admin/device",
            "timesetting",
            data,
        )
        return TimeSettings.from_api(result)

    def get_log_types(self) -> list[LogType]:
        """Return the list of log categories available for export."""
        items = self.request_list("admin/log_export", "types", {"operation": "read"})
        return [LogType.from_api(item) for item in items]

    def get_system_log(self, index: int = 0, limit: int = 100) -> SystemLogPage:
        """Return one page of system logs without preparing or restarting logging."""
        if index < 0:
            raise ValueError("Failed to read system log: index must be non-negative")
        if not 1 <= limit <= 100:
            raise ValueError("Failed to read system log: limit must be between 1 and 100")
        result = self.request(
            "admin/log_export",
            "feedback_log",
            {
                "operation": "read",
                "params": {"index": index, "limit": limit},
            },
        )
        return SystemLogPage.from_api(result)

    def _require_auth(self) -> SessionContext:
        if self._session is None or not self._session.is_authenticated():
            raise AuthenticationError(
                "Failed to send request: not authenticated, call login() first"
            )
        return self._session


def _result(payload: JsonObject) -> JsonObject:
    return get_object(payload, "result")


def _list_of_objects(data: JsonObject, key: str) -> list[JsonObject]:
    value = data.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
