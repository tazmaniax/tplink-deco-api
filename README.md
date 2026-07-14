# TP-Link Deco API and MCP

[![CI](https://github.com/tazmaniax/tplink-deco-api/actions/workflows/ci.yml/badge.svg)](https://github.com/tazmaniax/tplink-deco-api/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/license/mit)

A model-aware REST and [Model Context Protocol](https://modelcontextprotocol.io/)
service for discovering, monitoring and safely controlling TP-Link Deco mesh
networks through their local interfaces.

The project presents agents with one semantic view of a Deco network. It detects
the connected controller, selects the supported HTTP/LuCI or TMP/AppV2 operation,
normalizes the response and reports the route and evidence used. Agents do not
need to choose between Deco protocols or model-specific endpoints.

REST, MCP and the typed Python SDK share one semantic service, router session,
safety policy and mutation-plan store. Reverse-engineered operation catalogues,
compatibility evidence and bounded hardware probes remain available for
developers and contributors.

> [!IMPORTANT]
> This is an unofficial community project. TP-Link does not publish or support
> these local interfaces, and firmware behaviour varies by model and version.
> The broad catalogue is not a claim that every operation is supported by every
> Deco. The P9 has the deepest live evidence in this repository.

## What it provides

- A protocol-neutral default MCP surface: 28 resources and five tools.
- An authenticated OpenAPI 3.1 REST surface under `/api/v1` with explicit
  typed response schemas, preflight, planning and idempotent execution resources.
- Frozen protocol-neutral response dataclasses shared by REST and MCP without a
  Pydantic dependency in the base SDK.
- Automatic controller identification over HTTP or gated TMP/AppV2 bootstrap,
  followed by evidence-based capability routing.
- Normalized network status, configuration, mesh, devices, traffic,
  reservations, logs, capabilities and mutation inventory.
- Local HTTP/LuCI support using TP-Link's RSA/AES owner session.
- Optional SSH/TMP/AppV2 support with mandatory host-key pinning.
- A catalogue of 376 HTTP operations and 600 TMP/AppV2 opcodes for diagnostics
  and compatibility research.
- Independent gates for sensitive reads, binary exports, mutations,
  destructive actions, internal operations and unverified TMP reads.
- One-shot mutation planning with controller binding, confirmation, immediate
  verification and rollback requirements.
- Read-only and value-free probe tools for extending model compatibility
  without retaining credentials or private network data.
- Stdio for local agent clients and authenticated Streamable HTTP for an
  always-on service.

## How agents see the network

Resources are the canonical read-only state views:

| Resource | Contents |
|---|---|
| `deco://mcp` | MCP configuration, connection state and enabled safety gates. |
| `deco://status` | Overall internet, controller and mesh health, including normalized firmware availability. |
| `deco://configuration` | Sanitized network and system configuration. |
| `deco://system/led` | System LED state and firmware-native night-mode schedule. |
| `deco://mesh` | Controller identity and all Deco nodes. |
| `deco://mesh/traffic` | Firmware-native upload and download rates for each Deco node. |
| `deco://wireless/wps` | Current WPS scan timer and per-node session state. |
| `deco://devices` | All known client devices with connectivity and access state. |
| `deco://devices/active` | Devices currently online. |
| `deco://devices/inactive` | Known devices currently offline. |
| `deco://devices/blocked` | Devices present in the block list. |
| `deco://traffic` | Per-device and aggregate traffic rates. |
| `deco://address-reservations` | DHCP address reservations. |
| `deco://network/lan` | LAN address, subnet, DNS and upstream addresses. |
| `deco://network/dhcp` | DHCP pool, gateway, DNS and address usage. |
| `deco://network/qos` | QoS mode details and configured bandwidth values. |
| `deco://network/vlan` | Internet VLAN state. |
| `deco://network/port-forwarding` | Port-forwarding rules and capacity. |
| `deco://network/iptv` | IPTV state and mode. |
| `deco://network/sip-alg` | SIP application-layer gateway state. |
| `deco://network/mac-clone` | WAN MAC-clone state. |
| `deco://network/ipv4` | Normalized IPv4 WAN and LAN configuration. |
| `deco://network/ipv6` | IPv6 WAN and LAN configuration. |
| `deco://network/ipv6/firewall` | Inbound IPv6 firewall rules and capacity. |
| `deco://devices/ipv6` | IPv6 client and neighbor inventory. |
| `deco://logs` | Available log levels and snapshot-preparation metadata without log contents. |
| `deco://logs/{index}` | One gated 100-entry page from the currently prepared system-log snapshot. |
| `deco://capabilities` | Reads available for the connected controller. |
| `deco://mutations` | Known mutation intents, evidence and eligibility. |

Mesh, status, configuration, devices, traffic and reservations select their
interface inside the service. HTTP supplies the richer response when available;
an eligible TMP cold start returns the validated subset with provenance and
explicit unavailable fields, without merging live data from both transports.
Wireless operation mode and bridge/PLC status use the same semantic source as
their surrounding WLAN or configuration response, including during TMP-only
startup.
IPv4 configuration uses normalized HTTP-to-TMP fallback, retaining TMP's
additional inbound-ping state and declaring that field unavailable when HTTP
is selected.
Eleven network and IPv6 resources use positively evidenced TMP-only routes and
remain lazy: startup validates configuration but opens TMP only when one is
read.
The system LED, per-node mesh traffic and WPS status resources follow the same
lazy policy through independently validated TMP-only routes. Mesh traffic rates
retain the firmware-native integer values because their units have not been
established. WPS remains read-only; this surface cannot start or cancel a
session.

Read-only resource templates provide bounded pagination without introducing a
duplicate tool. Tools are reserved for semantic reads that require richer
parameters or for actions:

| Tool | Behaviour |
|---|---|
| `deco_get_capability` | Resolve and read one semantic capability with provenance and bounded fallback. |
| `deco_get_wlan_state` | Read normalized WLAN state with HTTP-to-TMP fallback; passwords remain explicitly gated. |
| `deco_get_cloud_state` | Read opted-in DDNS with HTTP-to-TMP fallback and HTTP-only cloud-manager state when available. |
| `deco_plan_mutation` | Preflight one semantic mutation and, when eligible, issue a short-lived one-shot plan. |
| `deco_execute_mutation` | Consume an eligible plan with exact confirmation, verification and rollback controls. |

Protocol catalogues, raw reads, discovery probes and compatibility matrices are
available only through the opt-in diagnostic surface. They are deliberately
absent from the default agent interface.

See the [complete MCP reference](docs/mcp.md) for resource schemas, tool
parameters, routing provenance and diagnostic surfaces.

See the [REST API reference](docs/rest.md) for routes, authentication, error
responses, CORS behaviour and mutation semantics.

## Quick start with stdio

Requirements:

- Python 3.11 or newer
- [`uv`](https://docs.astral.sh/uv/)
- A Deco controller reachable on the local network
- The Deco owner password

Install the MCP dependencies:

```bash
uv sync --extra mcp
```

Add `--extra tmp` only when the hidden TMP/AppV2 interface is required:

```bash
uv sync --extra mcp --extra tmp
```

Start the stdio server:

```bash
DECO_HOST=192.168.68.1 \
DECO_USERNAME=admin \
DECO_PASSWORD='your-owner-password' \
uv run tplink-deco-mcp
```

Supply credentials through the MCP client's secret configuration or a secret
manager rather than committing them or placing them in retained shell history.
The [MCP guide](docs/mcp.md#codex-registration-with-1password) includes a Codex
and 1Password CLI example.

All sensitive and mutation gates are disabled by default. Ordinary non-secret
resources authenticate lazily when first read.

## Docker Compose

The included Compose service exposes authenticated Streamable HTTP MCP at
`/mcp` and REST at `/api/v1`. It can run on any suitable Docker host and does
not require host networking, elevated Linux capabilities or persistent
application storage.

From a source checkout:

```bash
cp .env.example .env
chmod 600 .env
# Replace every CHANGE_ME value and the example TEST-NET address in .env.

docker compose build --pull
docker compose up -d
docker compose ps
```

The service uses a deployment-scoped bearer token, DNS-rebinding protection, a
read-only root filesystem, no Linux capabilities and an unauthenticated process
liveness endpoint at `/healthz`. Cross-origin browser access is disabled unless
exact origins are configured. The supplied endpoint is plain HTTP and should
remain on a trusted, firewalled home network unless TLS is added in front of it.

See the [deployment guide](docs/mcp.md#docker-compose-on-a-home-network-host)
for the complete `.env`, network and TLS requirements.

## Safety model

The project treats endpoint discovery, read access and mutation authorization as
separate concerns:

- Catalogue presence means an operation was recovered from firmware or an app;
  it does not prove support on the connected model.
- Compatibility profiles record model and firmware evidence without embedding
  private response values.
- Sensitive reads, bulk secret reads and binary content each require their own
  opt-in gate.
- HTTP mutation paths require explicit gates and model evidence. Deployed MCP,
  REST and service paths hard-disable every TMP write.
- Destructive and firmware-internal operations have additional independent
  gates.
- Semantic mutations follow discover → plan → authorize → execute. Plans expire
  after five minutes, bind to the resolved controller and are consumed once.
- Fallback is allowed only for fifteen positively evidenced read capabilities.
  Mutations never fall back between protocols.

The repository inventories 21 semantic mutation intents, including blocked and
unverified candidates. Current P9 write evidence is limited to unchanged-value
verification requests. Desired state changes remain execution-ineligible in the
default semantic MCP workflow.

## Model compatibility

The MCP interface is designed for the Deco product range and resolves support
against the controller that is actually connected. It does not expose P9-named
default tools or require callers to supply a model name.

The P9 is currently the reference implementation because it has been exercised
against both local interfaces:

- 60 HTTP reads have positive P9 evidence, including 32 that returned data.
- 55 data-returning TMP/AppV2 reads have positive P9 evidence.
- All 246 conservatively classified TMP reads have a recorded P9 observation.
- Controlled current-value no-op evidence exists for HTTP address reservation,
  time settings, beamforming and 802.11r setters. Three TMP same-value writes
  passed immediate post-read verification, but operational safety was not
  established. A later P9 mesh incident is temporally associated with aggregate
  TMP activity but unattributed; causality is undetermined.

Other models can use generic routes immediately where their firmware matches,
but unobserved results are reported as unknown rather than silently treated as
unsupported. Compatibility evidence can be extended with the bounded probes in
`examples/`.

If HTTP is unavailable during initial identity discovery, an explicitly enabled
TMP/AppV2 session can resolve the mesh through the read-only device-list
contract. This requires configured TMP credentials and a pinned host key.
Unknown models may report their identity but do not inherit P9-specific TMP
capability evidence.

See:

- [Compatibility and evidence guide](docs/README.md)
- [HTTP endpoint index](docs/endpoints/README.md)
- [Transport and dispatch analysis](docs/protocol/transport-and-dispatch.md)
- [Authentication protocol](docs/auth-protocol.md)
- [Sanitized P9 response evidence](docs/api-responses/)

## Python SDK

The MCP server is built on the typed `tplink_deco_api` package. Existing Python
imports remain valid:

```python
from tplink_deco_api import DecoClient

with DecoClient("192.168.68.1", "admin", "your-password") as deco:
    for device in deco.get_device_list():
        print(device.device_model, device.software_ver)

    for client in deco.get_client_list():
        print(client.name, client.ip, client.connection_type)
```

High-level methods return typed dataclasses. Catalogue-driven `call()` and
`request_envelope()` APIs preserve model-specific response fields for
compatibility work. The public generic TMP API is read-only.

The original `tplink-deco-api` PyPI distribution represents the upstream SDK.
Until this fork completes its project rename and release setup, use `uv sync`
from this repository to run the expanded MCP implementation.

## Discovery and verification tools

The `examples/` directory contains the hardware-dependent tools used to build
the compatibility profiles. Important safeguards include:

- passwords are prompted without echoing or supplied through the environment;
- snapshot files are created with owner-only permissions;
- compatibility manifests retain response schemas rather than values;
- read probes use explicit allowlists and exclude mutations;
- fuzzy discovery is bounded, rate-limited and limited to read-like variants;
- mutation verification harnesses require an exact operation confirmation and
  perform an immediate post-read comparison.

Start with the sanitized read-only probe:

```bash
uv run examples/read_only_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --full-manifest \
  --output snapshot.json \
  --manifest-output compatibility.json
```

Hardware probes are never part of the normal test suite and must not be run
against a live network without understanding their data classification and, for
any write harness, obtaining explicit authorization.

## Development

Install all development dependencies:

```bash
uv sync --extra mcp --extra tmp
```

Run the same verification gates as CI:

```bash
uv run ruff format .
uv run ruff check . --fix
uv run mypy src
uv run pytest
```

The test suite is network-free by default. Router integration tests require an
explicit opt-in and configured credentials.

## Project history

This project began as a fork of
[`roquerodrigo/tplink-deco-api`](https://github.com/roquerodrigo/tplink-deco-api).
The upstream project established the Python SDK, authentication transport and
firmware endpoint documentation on which this work builds. This fork expands
that foundation into a model-aware MCP server, adds the TMP/AppV2 transport,
records P9 compatibility evidence and introduces an agent-oriented safety and
deployment model.

## License

Released under the MIT License.
