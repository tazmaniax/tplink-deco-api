# tplink-deco-api

[![CI](https://github.com/roquerodrigo/tplink-deco-api/actions/workflows/ci.yml/badge.svg)](https://github.com/roquerodrigo/tplink-deco-api/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tplink-deco-api)](https://pypi.org/project/tplink-deco-api/)

Python SDK for controlling **TP-Link Deco** mesh Wi-Fi routers via the internal HTTP API.

## Installation

```bash
pip install tplink-deco-api
```

## Usage

```python
from tplink_deco_api import DecoClient

with DecoClient("192.168.68.1", "admin", "your-password") as deco:
    for client in deco.get_client_list():
        print(client.name, client.ip, client.connection_type)
```

## Available methods

| Method | Returns |
|--------|---------|
| `login()` | `LoginResult` |
| `get_device_list()` | `list[Device]` |
| `get_device_mode()` | `DeviceMode` |
| `get_wlan_config()` | `WlanConfig` |
| `get_performance()` | `Performance` |
| `get_speed_test()` | `SpeedTest` |
| `get_client_list(deco_mac?)` | `list[ClientDevice]` |
| `get_clients_by_node()` | `tuple[NodeClientList, ...]` |
| `get_client_totals(deco_mac?)` | `NetworkTotals` |
| `get_address_reservations()` | `AddressReservationTable` |
| `get_internet_status()` | `InternetStatus` |
| `get_wan_info(device_mac?)` | `WanInfo` |
| `get_dsl_status(device_mac?)` | `DslStatus` |
| `get_wireless_power(device_mac?)` | `WirelessPower` |
| `get_time_settings(device_mac?)` | `TimeSettings` |
| `get_log_types()` | `list[LogType]` |

The public `request_envelope()` and catalogue-driven `call()` methods preserve
the complete firmware response, including model-specific fields that do not yet
have typed SDK models. `ENDPOINT_CATALOG` describes every catalogued operation's
transport, response shape, safety level, sensitivity, required parameters and
whether the SDK can execute it. Four documented plaintext login/bootstrap reads
have a separate call path. Domain login uses the encrypted owner session, and
the read-only multipart configuration backup has a dedicated binary path.
MCP binary downloads require independent sensitive-read and bulk-secret gates;
returning base64 content requires a third content-export gate.
Group-key, node-token and multipart mutation operations remain discoverable
without being misrepresented as executable owner-session calls.

```python
from tplink_deco_api import DecoClient, get_endpoint

with DecoClient("192.168.68.1", "admin", "your-password") as deco:
    endpoint = get_endpoint("admin.client.lease.get")
    response = deco.call(endpoint)
    print(response.result)
```

Plaintext login metadata can be read without opening an owner session:

```python
deco = DecoClient("192.168.68.1", "", "")
endpoint = get_endpoint("login.check_factory_default.read")
factory_state = deco.call_bootstrap(endpoint).result
```

`call_bootstrap()` accepts only the four catalogued `/login` read forms. It
rejects login operations, `/domain_login`, and every mutation. The observed P9
`domain_login.dlogin.read` operation instead uses the normal authenticated
encrypted owner session and is callable through `call()`.

## Models

Stable high-level methods return typed dataclasses. Catalogue-driven calls return
`ApiResponse`, which preserves raw model- and firmware-specific JSON for discovery.

```python
client.mac              # "AA:BB:CC:DD:EE:FF"
client.name             # "MacBook Pro"
client.ip               # "192.168.68.10"
client.connection_type  # "band6"
client.online           # True

device.device_model     # "BE65"
device.software_ver     # "1.2.10 Build 20251229"

wlan.band2_4.host.ssid      # "My Network"
wlan.band2_4.guest.password # "guest-password"

perf.cpu_usage  # 0.03
perf.mem_usage  # 0.42

reservations.max_count              # 64
reservations.is_full                # True
reservations.reservations[0].mac    # "AA:BB:CC:DD:EE:FF"
reservations.reservations[0].ip     # "192.168.68.10"
```

## Sanitized read-only probe

`examples/read_only_probe.py` retrieves mesh, network, client and address-reservation
data through a strict read-only request allowlist. It accepts `DECO_PASSWORD` or
prompts without echoing, excludes sensitive reads by default, and writes output files
with owner-only permissions.

```bash
uv run examples/read_only_probe.py --host 192.168.68.1 --output snapshot.json
```

To probe the complete non-secret owner-session surface and save a value-free
compatibility record alongside the private snapshot:

```bash
uv run examples/read_only_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --full-manifest \
  --output docs/api-responses/p9-discovery.json \
  --manifest-output docs/api-responses/p9-compatibility.json
```

Both files are created with owner-only permissions. The compatibility manifest
contains response field names and types but no response values.

An explicit P9-sensitive mode is limited to 11 secret JSON reads found in the
P9 web assets. It immediately reduces responses to field paths/types, retains no
values, excludes binary downloads, and cannot be combined with other probe
modes:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
  op run -- uv run examples/read_only_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --p9-sensitive-schemas \
  --manifest-output docs/api-responses/p9-sensitive-compatibility.json
```

Use `--all-sensitive-schemas` for all 57 secret JSON reads callable by the SDK:
56 owner-session reads plus the plaintext factory-identity bootstrap read. A
manifest checkpoint is written atomically after every endpoint. To seed or
resume the complete run from an earlier partial manifest:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
  op run -- uv run examples/read_only_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --resume-sensitive-manifest docs/api-responses/p9-sensitive-compatibility.json \
  --manifest-output docs/api-responses/p9-all-sensitive-compatibility.json
```

Pass `--discover-all` for the smaller curated P9 probe with complete response
values in the private snapshot. Pass `--full-manifest` for every catalogued
non-secret JSON read supported by the owner-session or plaintext-bootstrap
transport; this retains only operation status and response field types. Both
modes record rejection and timeout separately, and neither is treated as proof
that an endpoint is absent.

Pass `--per-node-clients` to query `client_list` separately for every mesh-node
MAC and retain the resulting node-to-client topology in the private snapshot.

Pass `--fuzzy-read-variants` for a bounded follow-up to the complete catalogue
pass. It tries only `read`, `get`, `getlist` and `list` aliases on an already
documented non-secret read form, plus omitted, empty and explicitly allowlisted
`device_mac: default` parameter shapes. Each candidate is rate-limited, repeated
after a fresh login, and recorded without parameter or response values:

```bash
uv run examples/read_only_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --fuzzy-read-variants \
  --output docs/api-responses/p9-fuzzy-discovery.json \
  --manifest-output docs/api-responses/p9-fuzzy-compatibility.json
```

The fuzzy pass has a hard limit of 300 candidates and a minimum 0.1-second
delay. It does not guess controller paths, probe secret reads, use special
authentication transports or invoke mutation-like verbs. An expired session or
an interrupted transport request triggers one fresh-login retry of that exact
read so authentication failures are not recorded as endpoint rejection.

If an older fuzzy manifest contains incomplete or inconsistent attempt evidence,
retry conservatively from the first affected observation through the end without
repeating the 146 exact catalogue calls:

```bash
uv run examples/read_only_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --retry-fuzzy-manifest docs/api-responses/p9-fuzzy-compatibility.json \
  --output docs/api-responses/p9-fuzzy-retry.json \
  --manifest-output docs/api-responses/p9-fuzzy-compatibility-retry.json
```

The Deco uses a self-signed certificate. The current SDK accepts that certificate and
therefore cannot authenticate the router endpoint; use it only on a trusted LAN.

## MCP server

Install the MCP and hidden-transport integrations with
`uv sync --extra mcp --extra tmp`, then configure
the process with `DECO_HOST`, `DECO_USERNAME` and `DECO_PASSWORD` through the MCP
client's environment/secret settings:

```bash
uv run tplink-deco-mcp
```

Non-secret reads are enabled by default. Sensitive reads, ordinary mutations,
destructive operations and internal firmware calls have independent environment
gates and default to disabled. See [the MCP guide](docs/mcp.md) for the tools,
resources and safety contract.

The default MCP surface contains ten protocol-neutral tools and seven semantic
resources: status, sanitized configuration, mesh nodes, network client devices,
address reservations, capabilities and mutations. The server detects the
connected controller model, selects HTTP/LuCI or TMP/AppV2, and reports its
choice in provenance. Six overlapping reads have explicit, live-evidenced
read-only fallback contracts; mutations never fall back.

`deco://mutations` lists 21 deduplicated semantic mutation intents, including
blocked and unverified candidates. `deco_plan_mutation` resolves one against the
connected controller and issues a short-lived one-shot plan ID only for an
eligible, fully gated current-value verification. `deco_execute_mutation`
checks the plan confirmation and controller identity, consumes the plan once,
and verifies or rolls back immediately. State-changing semantic execution
remains blocked because current P9 write evidence is limited to unchanged-value
tests.

Set `DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS=1` only when an expert agent needs the
48-tool, 16-resource protocol catalogue, discovery and evidence surface. Raw
endpoint execution is independently hidden behind
`DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS=1` and still requires every applicable risk
gate and exact confirmation. Network, WLAN, cloud, client-device and
address-reservation data continue to honor their sensitivity gates.

Controller- and category-scoped batch tools expose the complete positively
observed JSON surface without requiring an agent to coordinate dozens of calls:
59 P9-supported HTTP reads—56 owner-session and three plaintext bootstrap—and
55 data-returning TMP reads. HTTP secret operations require an explicit per-call
request plus the server secret gate; every TMP batch requires both the TMP and
secret-data gates. Forty-eight TMP reads need no parameters. Passing
`include_parameterized=true` derives at most three owner identifiers from
confirmed reads in memory and applies only the seven confirmed owner, version,
or IoT-list contracts, making all 55 datasets batch-callable. Request parameter
values are not returned.
The offline `deco_p9_access_coverage` matrix unifies HTTP, TMP, transport and
mutation evidence and lists every remaining gap without contacting the router.
It now includes an explicit unresolved ledger and five completed live-audit
records. The completed records cover the value-free `0x404B` inferred-module
probe, the digest-only binary audit, the 55-dataset TMP batch audit, and the TMP
beamforming and monthly-report no-ops. The authorization-ready queue is empty.
Rechecking the inferred MCP probe still requires the independent unverified-TMP
gate; enabling ordinary confirmed TMP reads is insufficient.
A digest-only MCP discovery tool can recheck the three audited P9 backup/log
downloads only when both secret-data and bulk-secret gates are enabled; it
never returns or persists their binary content.
A targeted discovery pass resolved all three previously untested HTTP reads
that were non-secret JSON and already used the owner-session transport. A
second schema-only pass confirmed all three non-secret bootstrap reads without
authenticating or retaining their values. The secret factory-identity bootstrap
read returned HTTP 403 on the configured P9, without exposing credentials.

Narrow verification harnesses were used for the completed reservation `modify`,
beamforming `write`, 802.11r `write` and time-settings `write` no-ops. They
require exact operation confirmation, reject firmware errors and verify the
relevant state after the request; none of the results broadens MCP execution
eligibility beyond `noop_only` evidence.
The three settings with complete rollback contracts now have a separately gated
MCP current-value verifier. It does not include reservation modification, does
not broaden generic execution eligibility, and has not yet been invoked live.
An offline HTTP mutation-verification queue now classifies all 23 candidates:
four verified no-ops, 15 high-risk deferred writes, three destructive writes,
and one evidence-blocked write. It has no execution path and currently proposes
zero new verification candidates.

The catalogue can overlay bundled P9 evidence on every operation, allowing an
agent to distinguish a live-observed call from an asset-only declaration, an
inferred mutation, or an entirely untested generic Deco route.

The MCP discovery surface also reports special HTTP transports and a separate
600-operation TMP/AppV2 opcode catalogue recovered from the signed TP-Link Deco
Android 3.10.215 app. The P9 exposes the documented TMP SSH
port. A value-free live audit authenticated, associated and negotiated AppV2,
then retrieved `DEVICE_LIST_GET`. `PLC_PAIR_GET` reached the firmware but was
rejected with AppV2 error 12 across five read-only parameter variants. The SDK
now includes a stream-based, CRC-checked AppV2 session whose public generic API
is read-only; an SSH adapter
with host-key pinning is also available through the optional `tmp` extra. MCP
tools expose the P9-observed read surface through independent TMP, secret-data,
and unverified-read gates. A complete value-free pass found 48 successful JSON
reads, one successful binary read, 11 payload-level rejections and 14 AppV2
rejections across all 74 read opcodes in the original 192-operation registry. A
subsequent contract pass recovered
three of those JSON reads. A second pass derived exact request models from the
TP-Link Deco Android 1.10.5 APK and recovered four more, bringing current
coverage to 55 data-returning reads and reducing payload-level rejections to
four. The newer signed registry adds 408 operations, including 175 additional
conservative GET-named operations. A value-free P9 pass tested 129 of them
across 166 bounded payload variants; a second, control-validated pass tested the
remaining 43 secret-classified reads across 71 variants. Every attempt returned
AppV2 error 12, retained exactly as `rejected`. Static workflow review
reclassified three GET-named set-dispatched actions as secret mutations. All
246 conservative reads now have exact P9 observations. The MCP surface now
inventories all 348 TMP writes and builds offline
preflight/verification/rollback plans. It exposes no generic TMP execution tool;
the only write surface repeats the verified 802.11r current-value no-op behind
three runtime gates. An
offline verification queue now classifies all three completed no-ops as
verified and proposes no additional candidates. Every unverified mutation
remains execution-ineligible.
Operation-specific beamforming and monthly-report harnesses have each verified
one current-value no-op and remain deliberately absent from MCP execution.
QoS mode is now
blocked because its P9 read omitted the setter's `qos_mode` candidate key.
All secret candidates are deferred: IPv4/IPv6 routing, firewall, ownership and
manager-permission writes are high-risk, while reservation add is deferred
because the last P9 observation found the 64-entry table full.
Static call sites across signed app versions 1.10.5 and 3.10.215 provide request
evidence for 315 writes: 274 with candidate top-level keys, 27 with null
payloads and 14 with model-only evidence. Thirty-three write declarations have
no app call site. One explicitly authorized current-value no-op verified the
`11R_SET` `enable` key on the P9: firmware returned `error_code=0`, the immediate
post-read matched the preflight state, and rollback was not needed. The other
345 writes remain untested, and no tool accepts a desired TMP state.
A separate bounded contract-discovery tool can derive candidate identifiers from
confirmed reads in memory and retry parameterized payload-level rejections while
returning only parameter-key names, status codes and schemas.
`examples/tmp_unverified_read_probe.py` covers any reads made untested by a
future registry or compatibility-overlay update;
it prints each opcode as activity, runs known-good value-free controls before
and after the batch, excludes secret-classified and app-dispatched set-path
reads by default, and persists only schemas, digests and error codes.

## Requirements

- Python 3.11+
- TP-Link Deco router reachable on the local network
