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
| [`mcp.md`](./mcp.md) | Agent-facing MCP server, tools, resources and safety gates |
| [`architecture/semantic-resource-routing.md`](./architecture/semantic-resource-routing.md) | Required source selection, fallback, resource boundaries and provenance policy |

The default MCP surface is protocol-neutral: agents see five semantic tools and
28 resources covering MCP state, live network status, sanitized configuration,
system LED state, mesh nodes and per-node traffic, WPS status, normalized and
filtered network-device views, client traffic, address reservations, LAN, DHCP,
QoS, VLAN, NAT, IPTV, SIP ALG, MAC
cloning, IPv4, IPv6
configuration/firewall/clients, log categories, capabilities and mutations. The server resolves
the connected controller and chooses HTTP/LuCI or TMP/AppV2; agents never supply
a live model or protocol. Set
`DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS=1` to add the protocol-specific catalogue and
evidence surface. Raw endpoint mutation visibility has a separate opt-in and
neither visibility flag authorizes writes.

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

The packaged `tmp_opcode_registry.json` records 600 TMP/AppV2 operations from
the signed TP-Link Deco Android 3.10.215 APK. The companion
`tmp_app_contracts.json` overlay combines signed 1.10.5 and 3.10.215 call-site
evidence, request-model names and candidate top-level keys. Neither file
contains app source code, request values or credentials. Candidate keys are
static planning evidence, not proof that a mutation works on P9 firmware.
The bundled P9 TMP overlay records exact value-free observations for all 246
conservative reads. The non-secret and control-validated sensitive 3.10.215
discovery passes retained only response status, schemas, digests and error
codes.
The remaining `IOT_CLIENT_LIST_GET_BY_MODULE` contract has an opt-in bounded
probe derived from opcode semantics and the signed app's serialized module
enum. It is recorded as inferred rather than as a recovered app call site and
returns no response values. MCP requires the TMP, sensitive-read and
unverified-TMP gates for this mode.
The complete TMP data tool has a separate `include_parameterized` opt-in. It
uses only the seven confirmed owner/version/IoT-list contracts and derives at
most three owner identifiers in memory, allowing all 55 positively observed
JSON datasets to be fetched without returning request parameter values.
The offline TMP mutation-verification queue ranks evidence and gaps while
keeping sensitive, deferred and destructive tiers behind explicit filters; it
never contacts the router. Three P9 current-value writes returned firmware
success and immediate post-read equality. Their observation status is
`same_value_immediate_verification_passed`, while their safety status remains
`safety_not_established`. A later mesh incident is temporally associated with
aggregate TMP activity but is not attributed to these writes or any other
opcode; causality is undetermined. MCP, REST and the deployed service now
hard-disable all TMP writes; TMP remains available only for explicitly enabled
experimental reads and offline analysis. The source-checkout lab harnesses
require a separate lab gate, exact confirmation and exact live controller
identity binding. See the
[incident record](./incidents/2026-07-12-p9-tmp-topology-loss.md).
The HTTP mutation surface has a separate offline queue covering all 23 P9
candidates. It proposes zero new verifications: four are already no-op-verified,
15 are high-risk deferred, three are destructive, and one lacks sufficient
parameter/rollback evidence.
A disabled-by-default MCP verifier can repeat only the P9-verified beamforming,
802.11r and time-settings current-value no-ops. It requires the ordinary
mutation gate, a dedicated HTTP-no-op gate and exact per-operation confirmation;
it accepts no desired values and latches off after any non-verified outcome.
Reservation modification remains excluded because table drift cannot be fully
rolled back.
The `BEAMFORMING_SET` (`0x421C`) and `MONTHLY_REPORT_MGR_SET` (`0x4223`)
current-value-only CLI harnesses both completed with immediate post-read
equality and no rollback. They remain absent from MCP execution. Mutation
ranking now requires every signed setter
candidate key to appear in the live P9 preflight schema; this blocks QoS mode
because its read omitted `qos_mode`.
Every secret candidate is now deferred by connectivity, security-policy,
ownership, or observed-capacity risk. The last reservation observation found
the P9 table full at 64 entries.

The value-free [P9 compatibility manifest](./api-responses/p9-compatibility.json)
records endpoint availability and response schemas observed on a five-node P9
mesh without retaining response values, client identities, addresses, names,
credentials or tokens.

The [P9 web-asset evidence](./api-responses/p9-web-assets.json) independently
records all controller/forms found in that firmware's public browser UI,
explicit operation strings, mutation field names, asset hashes, and value-free
live validation of newly discovered safe reads. Raw JavaScript is not retained
in the repository.

The [complete P9 sensitive-schema manifest](./api-responses/p9-all-sensitive-compatibility.json)
records the result shapes of all 55 explicitly opted-in secret JSON reads.
It contains field names and types—including fields named `password` or
`ssid`—but no field values, credentials, tokens, log lines, or binary content.

The supplemental
[domain-login observation](./api-responses/p9-domain-login-compatibility.json)
proves that `domain_login.dlogin.read` uses the normal encrypted owner session
on this P9 and returns an accepted null result. It retains neither response
values nor the public web source used to verify the transport.

The [multipart-backup contract](./api-responses/p9-multipart-backup-contract.json)
records the P9 web client's exact scalar-only `operation=backup` form and source
hashes without downloading configuration bytes. The SDK and MCP have a
binary call path protected by independent sensitive-read and bulk-secret gates,
while base64 export has a third gate. A live digest-only audit retained no
binary content: both backup routes raised transport errors, while log download
returned an unvalidated 44-byte `text/plain` response.
The P9 coverage resource distinguishes unresolved evidence from actionable next
steps. It records three completed read-only audits plus the completed TMP
beamforming and monthly-report no-op verifications. The authorization-ready
queue is now empty.

The probe's optional bounded fuzzy mode records a second set of observations
with the source catalogue operation, generated alias or parameter shape, both
attempt statuses, API/HTTP error codes and whether support was confirmed after
a fresh login. Session expiry is retried before an attempt is recorded. Fuzzy
manifests use schema version 2; version 1 manifests remain readable, and an
incomplete or inconsistent version 2 run can be resumed from its first affected
observation.

On the observed P9 firmware, the completed fuzzy pass tested 237 candidates
twice and found no additional data-returning endpoint. Forty variants were
accepted with a `null` result, 191 were rejected, and six consistently returned
HTTP 500; none changes the 31-operation supported-read profile.

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
