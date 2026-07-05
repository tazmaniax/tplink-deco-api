# TP-Link Deco — API & protocol documentation

Reference for the internal HTTP API exposed by TP-Link Deco mesh routers. It
covers the **local device API** (`http(s)://<router-ip>/…`) — the surface this
SDK talks to — and the separate **TP-Link cloud** endpoints used for remote
control, documented in [`protocol/cloud-api.md`](./protocol/cloud-api.md).

Everything here describes the local device API unless a page says otherwise.

---

## How the API is shaped

A single dispatcher serves every endpoint:

```
POST https://<router-ip>/cgi-bin/luci/;stok=<TOKEN>/<controller>?form=<form>
Content-Type: application/json

{ "operation": "<operation>", "params": { … } }
```

- **`<controller>`** — the request path segment, e.g. `admin/network`, `login`.
- **`form`** — selects a handler group inside the controller.
- **`operation`** — the verb inside that form (`read`, `write`, `get`, `set`,
  `add`, `remove`, …).
- Most requests are wrapped in an **AES + RSA** envelope; a small set is
  plaintext. See below.

The full request/response contract, the encryption envelope, error codes and
batching live in the protocol pages.

---

## Documentation map

### Protocol

| Page | What it covers |
|------|----------------|
| [`auth-protocol.md`](./auth-protocol.md) | RSA/AES handshake, login flow, `sign`/`seq`, crypto parameters |
| [`protocol/transport-and-dispatch.md`](./protocol/transport-and-dispatch.md) | URL layout, `form`/`operation`/`params`, response envelope, error codes, batch requests, plaintext endpoints |
| [`protocol/cloud-api.md`](./protocol/cloud-api.md) | TP-Link cloud hosts, account API and device passthrough |

### Endpoints (by functionality)

Start at the [**endpoint index**](./endpoints/README.md) for the complete
`controller → form → operation` table. Individual references:

| Area | Page |
|------|------|
| Login & session | [`endpoints/login.md`](./endpoints/login.md) |
| WAN / LAN / IPv6 / VLAN | [`endpoints/network.md`](./endpoints/network.md) |
| Static routing | [`endpoints/routing.md`](./endpoints/routing.md) |
| DHCP server | [`endpoints/dhcp.md`](./endpoints/dhcp.md) |
| Wi-Fi | [`endpoints/wireless.md`](./endpoints/wireless.md) |
| Deco nodes & speed test | [`endpoints/device.md`](./endpoints/device.md) |
| System (language, reboot, factory reset) | [`endpoints/system.md`](./endpoints/system.md) |
| Eco mode & time | [`endpoints/eco-mode-and-time.md`](./endpoints/eco-mode-and-time.md) |
| Clients & reservations | [`endpoints/clients.md`](./endpoints/clients.md) |
| Parental controls & QoS | [`endpoints/parental-control-and-qos.md`](./endpoints/parental-control-and-qos.md) |
| HomeShield security | [`endpoints/homeshield-security.md`](./endpoints/homeshield-security.md) |
| Firmware & upgrade | [`endpoints/firmware-and-upgrade.md`](./endpoints/firmware-and-upgrade.md) |
| Cloud & account | [`endpoints/cloud-and-account.md`](./endpoints/cloud-and-account.md) |
| IoT & smart home | [`endpoints/iot-smart-home.md`](./endpoints/iot-smart-home.md) |
| WPS | [`endpoints/wps.md`](./endpoints/wps.md) |
| VPN (client & server) | [`endpoints/vpn.md`](./endpoints/vpn.md) |
| NAT & port forwarding | [`endpoints/nat-port-forwarding.md`](./endpoints/nat-port-forwarding.md) |
| Dynamic DNS | [`endpoints/ddns.md`](./endpoints/ddns.md) |
| IPv6 firewall | [`endpoints/ipv6-firewall.md`](./endpoints/ipv6-firewall.md) |
| IPTV | [`endpoints/iptv.md`](./endpoints/iptv.md) |
| USB storage & Time Machine | [`endpoints/storage-usb.md`](./endpoints/storage-usb.md) |
| Administration & remote mgmt | [`endpoints/administration.md`](./endpoints/administration.md) |
| Onboarding & provisioning | [`endpoints/onboarding-and-provisioning.md`](./endpoints/onboarding-and-provisioning.md) |
| Logs & diagnostics | [`endpoints/logs-and-diagnostics.md`](./endpoints/logs-and-diagnostics.md) |
| Other services | [`endpoints/misc-services.md`](./endpoints/misc-services.md) |

### Example responses

Real, sanitised response payloads used as test fixtures live in
[`api-responses/`](./api-responses).

---

## Reading conventions

- **Operation** names are the JSON `operation` value. Where the device uses
  `read`/`write`, the app sometimes uses `get`/`set` for the same form — both
  are listed when a form registers them.
- **Auth = plaintext** means the request skips the AES/RSA envelope (plain
  JSON). Everything else uses the envelope from
  [`auth-protocol.md`](./auth-protocol.md).
- Forms are labelled **(web)**, **(app)** or **(both)** by which client they
  serve. Many `/admin/*` paths serve both: the dispatcher exposes the union of
  the web and app form sets at a single URL.
- Field names are quoted verbatim from the API. Fields whose meaning is
  inferred (not shown in an example response) are flagged.
</content>
