# MCP server

The optional MCP server presents protocol-neutral Deco capabilities while
enforcing the SDK's safety and sensitivity metadata. Agents select the data they
need; the server selects HTTP/LuCI or TMP/AppV2 and returns routing provenance.
Protocol-specific discovery tools are an opt-in diagnostic surface. The server
uses the stable 1.x MCP Python SDK over stdio by default and can expose an
authenticated Streamable HTTP endpoint for an always-on deployment.

## Installation

```bash
uv sync --extra mcp --extra tmp
```

The `tmp` extra is required only for the hidden SSH/AppV2 transport.

Configure the MCP process through its environment. Supply `DECO_PASSWORD`
through the MCP client's secret/environment configuration rather than putting it
in a committed file or a shell command that may be retained in history.

| Variable | Default | Purpose |
|---|---:|---|
| `DECO_HOST` | `192.168.68.1` | Gateway Deco address. |
| `DECO_USERNAME` | `admin` | Local API username. |
| `DECO_PASSWORD` | — | Owner password; required only when a tool connects. |
| `DECO_TIMEOUT` | `60` | Per-request timeout in seconds. |
| `DECO_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`; HTTP fails closed unless its security settings are complete. |
| `DECO_SERVER_HOST` | `127.0.0.1` | Shared HTTP bind address; Compose sets `0.0.0.0` inside the container. |
| `DECO_SERVER_PORT` | `8000` | Shared REST and MCP listen port. |
| `DECO_MCP_PATH` | `/mcp` | Streamable HTTP mount path; must be absolute, non-root and have no trailing slash. |
| `DECO_MCP_PUBLIC_URL` | — | Complete externally visible MCP endpoint URL, required for HTTP authorization metadata. |
| `DECO_SERVER_BEARER_TOKEN` | — | Deployment-scoped bearer token of at least 32 characters shared by REST and MCP. |
| `DECO_SERVER_ALLOWED_HOSTS` | — | Comma-separated permitted HTTP `Host` headers applied to both surfaces. |
| `DECO_SERVER_ALLOWED_ORIGINS` | — | Comma-separated browser origins allowed by Origin enforcement and REST CORS. |
| `DECO_SERVER_MAX_IN_FLIGHT_REQUESTS` | `32` | Shared upper bound for concurrent REST and MCP requests. |
| `DECO_REST_ENABLED` | off | Register the OpenAPI REST router under the configured prefix. |
| `DECO_REST_PREFIX` | `/api/v1` | REST prefix; must be absolute and have no trailing slash. |
| `DECO_REST_EXPOSE_DOCS` | off | Expose authenticated `/docs` and `/redoc`; disabled by default. |
| `DECO_ALLOW_SENSITIVE_READS` | off | Permit reads classified as `secret`. |
| `DECO_ALLOW_BULK_SECRET_READS` | off | Permit configuration backups, log downloads and paginated log content; also requires the sensitive-read gate. |
| `DECO_ALLOW_BINARY_CONTENT` | off | Permit base64 binary content in MCP results; digest-only reads do not require this gate. |
| `DECO_ALLOW_MUTATIONS` | off | Permit ordinary configuration mutations. |
| `DECO_ALLOW_HTTP_NOOP_VERIFICATION` | off | Permit only the three P9-verified HTTP setting current-value no-ops; also requires the ordinary mutation gate. |
| `DECO_ALLOW_DESTRUCTIVE` | off | Permit reboot, reset, removal and upgrade operations. |
| `DECO_ALLOW_INTERNAL` | off | Permit firmware-internal mesh/debug operations. |
| `DECO_TP_LINK_ID` | — | TP-Link account email used only to derive the TMP SSH username. |
| `DECO_TMP_HOST_KEY_SHA256` | — | Required pinned SSH host-key fingerprint for authenticated TMP connections. |
| `DECO_ALLOW_TMP_READS` | off | Permit TMP reads that have positive P9 evidence. |
| `DECO_ALLOW_UNVERIFIED_TMP_READS` | off | Additionally permit read-only opcodes not yet tested on the P9. |
| `DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS` | off | Register protocol-specific catalogue, raw read, discovery and mutation-analysis tools and resources. This changes discoverability only and is not a mutation authorization gate. |
| `DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS` | off | Register the raw endpoint mutation executor independently of diagnostics. All ordinary risk gates, model evidence and confirmations still apply. |

Run the installed entry point:

```bash
uv run tplink-deco-mcp
```

### Codex registration with 1Password

Codex stores stdio MCP launch commands and their environment in
`~/.codex/config.toml`. To avoid storing the resolved Deco owner password, run
the server through 1Password CLI and set `DECO_PASSWORD` to an `op://`
reference. From the repository root on Homebrew-based macOS:

```bash
codex mcp add tplink-deco \
  --env DECO_HOST=192.168.68.1 \
  --env DECO_USERNAME=admin \
  --env DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
  --env DECO_TIMEOUT=60 \
  --env DECO_ALLOW_SENSITIVE_READS=0 \
  --env DECO_ALLOW_BULK_SECRET_READS=0 \
  --env DECO_ALLOW_BINARY_CONTENT=0 \
  --env DECO_ALLOW_MUTATIONS=0 \
  --env DECO_ALLOW_HTTP_NOOP_VERIFICATION=0 \
  --env DECO_ALLOW_DESTRUCTIVE=0 \
  --env DECO_ALLOW_INTERNAL=0 \
  --env DECO_TP_LINK_ID='op://Private/tplinkdeco.net/tp_link_id' \
  --env DECO_TMP_HOST_KEY_SHA256='SHA256:TpmUAt8R9aKgOoas0FlZybt0YeLufHW3+JIEffm2/Ts' \
  --env DECO_ALLOW_TMP_READS=1 \
  --env DECO_ALLOW_UNVERIFIED_TMP_READS=0 \
  --env DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS=0 \
  --env DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS=0 \
  -- /opt/homebrew/bin/op run -- \
    /opt/homebrew/bin/uv run --project "$PWD" tplink-deco-mcp
```

Replace the absolute `op` and `uv` paths when they are installed elsewhere.
`op run` resolves the reference only in the child process environment; the
Codex configuration retains the reference rather than the password. Confirm
the redacted registration with `codex mcp get tplink-deco`. Start a new Codex
task or reload MCP configuration after changing the server's tool definitions,
because an already-open task may retain the earlier tool snapshot.

### Docker Compose on a home-network host

The included Compose profile runs one authenticated REST and Streamable HTTP MCP
replica and does not require host networking, elevated Linux capabilities or
persistent storage. A single replica intentionally owns the shared Deco login,
mutation latches, pending plans and process-local REST idempotency records.

Copy or clone the repository to the Linux host, then configure it:

```bash
sudo install -d -m 0750 /opt/deco-server
sudo chown "$USER":"$USER" /opt/deco-server
cd /opt/deco-server

# Clone or copy the repository contents here first.
cp .env.example .env
chmod 600 .env
```

Edit `.env`, replace every `CHANGE_ME` value and replace the example TEST-NET
address. Use the host's static LAN address for `DECO_SERVER_BIND_ADDRESS`, `DECO_MCP_PUBLIC_URL` and
`DECO_SERVER_ALLOWED_HOSTS`. Generate the bearer token independently of the Deco
password:

```bash
openssl rand -hex 32
```

Start and inspect the service:

```bash
docker compose build --pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 deco-server
```

The deployment does not depend on whether the Docker host is a Proxmox LXC, a
VM or an ordinary Linux machine. The MCP endpoint is the configured
`DECO_MCP_PUBLIC_URL`; REST is served under `DECO_REST_PREFIX`. Both surfaces
require
`Authorization: Bearer <DECO_SERVER_BEARER_TOKEN>`. The unauthenticated
`/healthz` and `/readyz` endpoints never contact the router. The MCP and REST
paths must not contain one another or overlap `/healthz`, `/readyz`,
`/openapi.json`, `/docs` or `/redoc`.
The container runs as UID/GID 10001, has a read-only root filesystem, drops all
Linux capabilities and uses only an ephemeral `/tmp` tmpfs.

Permit inbound TCP 8000 only from agent hosts. Permit outbound TCP 443 to the
Deco controller and, when TMP is enabled, TCP 20001. The supplied deployment is
plain HTTP and is suitable only for a trusted, firewalled home network. Put it
behind TLS before crossing an untrusted LAN, VLAN boundary or the internet.
The `.env` file is git-ignored but contains plaintext credentials; restrict the
host and Docker administrator accounts and include the file only in protected
backups. Avoid sharing the output of `docker compose config`, which expands the
environment and can print those values.

The P9 registration was audited on 2026-07-11 through a fresh MCP stdio client.
That historical live audit covered the then-current 43 tools and nine resources.
The current default surface exposes five protocol-neutral tools and 23
semantic resources. Setting `DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS=1` exposes 48
tools and 32 resources. `DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS=1` independently
adds the raw endpoint executor. With HTTP risk gates disabled and only
verified TMP reads enabled, the audit
confirmed lazy authentication, rejected sensitive WLAN access, rejected a
mutation before opening a router session, produced an offline reservation
mutation plan and inventory, and completed a read-only firmware-status request.
With the ordinary mutation gate enabled in a separate server process, the same
audit confirmed that a matching plan hash for an unverified P9 mutation was
still rejected without opening a router session.

The pinned TMP surface was then audited through another fresh MCP process.
`deco_tmp_host_key` matched the configured fingerprint without authenticating;
the P9-observed `DEVICE_LIST_GET` and digest-only `FW_PROG_GET` succeeded; and
the known-rejected `PLC_PAIR_GET`, a secret read, and a mutation opcode were all
rejected before invocation. The value-free result is in
[`p9-tmp-mcp-audit.json`](api-responses/p9-tmp-mcp-audit.json).

A live read-only reservation preflight reported the observed P9 table at its
64-entry capacity, so an `add` verification is not currently safe. The
preflight returned `mutation_invoked=false`. After separate authorization, a
controlled test selected one existing reservation and submitted its unchanged
MAC and IP as a logical no-op; the firmware returned `error_code=0` and the
complete reservation table remained identical.

The repository includes the narrowly scoped harness used for that verification:
`examples/verify_reservation_modify_noop.py`. It refuses to connect unless
`--confirm` exactly matches `admin.client.addr_reservation.modify`, requires a
MAC that resolves to exactly one existing reservation, submits that entry's
current MAC and IP unchanged, then reads the table again and requires complete
before/after equality. This command is a real write request despite its no-op
payload and must not be run without explicit authorization:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
DECO_TEST_RESERVATION_MAC='AA:BB:CC:DD:EE:FF' \
  op run -- uv run examples/verify_reservation_modify_noop.py \
  --host 192.168.68.1 \
  --confirm admin.client.addr_reservation.modify
```

A successful run is evidence only for the exact `modify` operation on the
observed firmware. It does not establish that `add`, `remove`, or other
mutations work.

The network, WLAN, cloud, client and system views were also exercised through
fresh MCP processes. Client and system views returned their complete expected
sections; the P9 client call took about 35 seconds. Network, WLAN and cloud
views succeeded with the sensitive-read gate enabled, and the default WLAN
result contained no password-bearing fields. Per-node mesh topology remains
covered by the earlier five-node client-association observation.

The server opens the router session lazily and reuses it until the MCP process
shuts down. Shutdown attempts the router's server-side logout endpoint before
discarding local session state; firmware such as the P9 that returns HTTP 404
falls back to local token and cookie invalidation.

Future resource and transport work must follow the
[semantic resource routing policy](./architecture/semantic-resource-routing.md).
It requires one data-producing interface per successful read, completeness-
ranked source selection, fallback only after an eligible failure, TMP identity
bootstrap for cold-start failover, and separate resources for single-source
datasets that would otherwise force a dual-interface fetch. Cold-start identity
bootstrap now follows that policy; the current ten HTTP-primary overlap routes,
ten TMP-only network routes and directly implemented canonical resources remain
a transitional subset of the wider design.

## Resources

The default resources describe the configured Deco mesh rather than a protocol.
Except for `deco://mcp`, reading one can authenticate to the router. Client
devices, traffic, address reservations, LAN, DHCP, port forwarding and all
three IPv6 resources additionally require `DECO_ALLOW_SENSITIVE_READS=1`.
Every resource under the TMP-only network set requires
`DECO_ALLOW_TMP_READS=1`, configured TMP credentials and a pinned host key.
System-log pages require both the sensitive gate and
`DECO_ALLOW_BULK_SECRET_READS=1`.

| Resource | Contents | Top-level response attributes |
|---|---|---|
| `deco://mcp` | MCP configuration, connection state, gates and mutation latches; no router login. | `schema_version`, `host`, `username`, `timeout`, `password_configured`, `tp_link_id_configured`, `tmp_host_key_sha256`, `allow_sensitive_reads`, `allow_bulk_secret_reads`, `allow_binary_content`, `allow_mutations`, `allow_destructive`, `allow_internal`, `allow_tmp_reads`, `allow_unverified_tmp_reads`, `allow_tmp_noop_verification`, `allow_http_noop_verification`, `tmp_writes_hard_disabled`, `tmp_transport_status`, `expose_diagnostic_tools`, `expose_raw_mutation_tools`, `mcp_transport`, `server_host`, `server_port`, `mcp_path`, `mcp_public_url`, `server_bearer_token_configured`, `server_allowed_hosts`, `server_allowed_origins`, `authenticated`, `tmp_connected`, `http_mutation_latched`, `tmp_mutation_latched`, `catalogued_operations`, `identity_resolved`, `pending_mutation_plan_count` |
| `deco://status` | Sanitized live health of the internet connection, controller and mesh; no client identities or passwords. | `schema_version`, `status`, `controller`, `internet`, `mesh`, `performance`, `firmware`, `speed_test`, `client_count`, `client_count_status`, `provenance`, `warnings`, `unavailable_sections`, `observed_at_epoch_seconds`, `passwords_included`, `client_identities_included`, `router_contacted`, `mutation_invoked` |
| `deco://configuration` | Sanitized current system configuration without passwords, clients or reservations. | `schema_version`, `controller`, `operating_mode`, `internet`, `wan`, `lan`, `dhcp`, `network_features`, `time_settings`, `wireless_features`, `nickname`, `nickname_status`, `provenance`, `related_sections`, `unavailable_sections`, `passwords_included`, `client_identities_included`, `address_reservations_included`, `router_contacted`, `mutation_invoked` |
| `deco://mesh` | Fresh controller identity and all Deco mesh nodes. | `schema_version`, `resolution_status`, `controller`, `nodes`, `node_count`, `mixed_model_mesh`, `identity_source`, `identity_interface`, `identity_attempts`, `fallback_used`, `profile_match`, `profile_name`, `cached`, `router_contacted`, `mutation_invoked` |
| `deco://devices` | Every known device normalized from client, per-node, block-list, traffic and reservation sources. | `schema_version`, `view`, `devices`, `device_count`, `all_device_count`, `source_counts`, `provenance`, `unavailable_sections`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://devices/active` | Normalized devices currently reported online. | Same as `deco://devices`, with `view="active"`. |
| `deco://devices/inactive` | Normalized known devices not currently reported online. | Same as `deco://devices`, with `view="inactive"`. |
| `deco://devices/blocked` | Normalized devices present in the block list, including blocked-only entries. | Same as `deco://devices`, with `view="blocked"`. |
| `deco://traffic` | Current normalized per-device and aggregate traffic speeds. | `schema_version`, `device_speeds`, `device_count`, `aggregate_speed`, `status`, `provenance`, `unavailable_sections`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://address-reservations` | Current DHCP address-reservation table. | `capability`, `schema_version`, `data`, `provenance`, `router_contacted`, `mutation_invoked` |
| `deco://network/lan` | Current LAN address, subnet, DNS and upstream address inventory. | `schema_version`, `status`, `ip`, `subnet_mask`, `dns_servers`, `wan_addresses`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/dhcp` | Current DHCP pool, gateway, DNS and address usage. | `schema_version`, `status`, `start_ip`, `end_ip`, `gateway`, `dns_servers`, `addresses_in_use`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/vlan` | Current Internet VLAN state. | `schema_version`, `status`, `enabled`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/port-forwarding` | Current port-forwarding rules and firmware capacity. | `schema_version`, `status`, `rules`, `rule_count`, `rule_limit`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/iptv` | Current IPTV state and mode. | `schema_version`, `status`, `enabled`, `mode`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/sip-alg` | Current SIP application-layer gateway state. | `schema_version`, `status`, `enabled`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/mac-clone` | Current WAN MAC-clone state. | `schema_version`, `status`, `enabled`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/ipv6` | Current normalized IPv6 WAN and LAN configuration. | `schema_version`, `status`, `enabled`, `wan`, `lan`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://network/ipv6/firewall` | Current inbound IPv6 firewall rules and firmware capacity. | `schema_version`, `status`, `rules`, `rule_count`, `rule_limit`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://devices/ipv6` | Current IPv6 client and neighbor inventory. | `schema_version`, `status`, `devices`, `device_count`, `provenance`, `observed_at_epoch_seconds`, `router_contacted`, `mutation_invoked` |
| `deco://logs` | Available log levels and snapshot-preparation metadata without reading actual log entries. | `schema_version`, `categories`, `category_count`, `selector_field`, `web_ui_default_level`, `all_level`, `preparation_mutation`, `status`, `unavailable_sections`, `log_contents_included`, `router_contacted`, `mutation_invoked` |
| `deco://logs/{index}` | One zero-based, 100-entry page from the currently prepared secret system-log snapshot. The firmware does not report which level prepared it. | `schema_version`, `current_index`, `total_pages`, `page_size`, `entries`, `entry_count`, `log_contents_included`, `prepared_level`, `level_reported_by_firmware`, `preparation_mutation`, `source_interface`, `router_contacted`, `mutation_invoked` |
| `deco://capabilities` | Semantic read catalogue for the connected controller. | `schema_version`, `resolution_status`, `controller`, `profile_match`, `capabilities`, `supported_count`, `unknown_count`, `unsupported_count`, `router_contacted`, `mutation_invoked` |
| `deco://mutations` | All known semantic mutation intents, including blocked and unverified candidates. | `schema_version`, `resolution_status`, `controller`, `profile_match`, `mutations`, `candidate_count`, `execution_counts`, `mutation_gate_status`, `router_contacted`, `mutation_invoked` |

Each `capabilities[]` item contains `name`, `description`, `category`,
`sensitivity`, `support_status`, `readable`, `source_configured`,
`source_connected`, `runtime_gate_enabled`, `mutable`, `read_operation`,
`related_mutations`, `evidence_level` and `reason_unavailable`. Configuration
and connection state are reported separately because the server does not probe
either transport at startup. Each
`mutations[]` item contains `name`, `description`, `category`, `risk`,
`sensitivity`, `scope`, `changes_schema`, `support_status`, `validation_status`,
`execution_scope`, `execution_status`, `required_gates`,
`confirmation_required`, `preflight_available`, `verification_available`,
`rollback_available`, `plan_operation`, `execute_operation` and `blockers`.
Each `devices[]` item contains `mac`, `ip`, `name`, `client_type`, `status`,
`active`, `access_status`, `blocked`, `reserved`, `prioritized`,
`reservation_ip`, `up_speed`, `down_speed`, `wire_type`, `connection_type`,
`interface`, `connected_node`, `space_id`, `access_host`, `owner_id`,
`remain_time`, `client_mesh` and `sources`. `status` is the connectivity state
`active` or `inactive`; blocking is an independent access state. Each
`device_speeds[]` item contains `mac`, `up_speed` and `down_speed`. Each log
`categories[]` item contains a firmware level `name` and `value`.
The P9 HTTP/TMP contracts for blocked clients and traffic expose identical
normalized fields. `deco://traffic` therefore uses evidence-backed HTTP-to-TMP
fallback. `deco://devices` reads blocking, traffic and reservations only from
the interface selected for its client inventory; a failed enrichment is marked
unavailable rather than being filled from the other interface.
Each `deco://devices/ipv6` device contains normalized `mac`, `ip`, decoded
`name` and `client_type` fields. IPv6 firewall `rules[]` preserve the
firmware-reported rule objects because the observed P9 table was empty and did
not provide evidence for a narrower populated-rule schema. Each port-forwarding
rule contains normalized `id`, `service_name`, `service_type`, `internal_ip`,
`internal_port`, `external_port` and `protocol` fields.
Compound-resource `provenance` identifies the selected source interface, the
source operation and attempts that selected it, whether fallback was used,
the preceding identity attempts, and confirms that one interface produced the
response data. When TMP is the only available interface, HTTP-only fields remain
absent and are listed in `unavailable_sections` with
`error_type="SourceUnavailable"`. Each `warnings[]` item contains
`code` and `message`; each `unavailable_sections[]` item contains `section`,
`status` and `error_type`.

`deco_get_cloud_state` returns `schema_version`, `status`, `ddns`, `manager`,
`provenance`, `unavailable_sections`, `observed_at_epoch_seconds`,
`router_contacted` and `mutation_invoked`. DDNS has an evidence-backed
HTTP-to-TMP fallback. If TMP supplies DDNS, `manager` is `null` and its HTTP-only
absence is recorded in `unavailable_sections`. `deco://status` reads speed-test
state from the same interface selected for the compound response, so a TMP-only
startup retains the last speed-test result.

Protocol and evidence resources are diagnostic-only:

| Diagnostic resource | Contents |
|---|---|
| `deco://diagnostics/operations` | Complete non-secret HTTP operation catalogue. |
| `deco://diagnostics/transports` | Implemented HTTP and TMP transport details. |
| `deco://diagnostics/routes` | Internal capability-to-protocol routes and fallback evidence. |
| `deco://diagnostics/http/mutations` | Raw HTTP mutation evidence and safety contracts. |
| `deco://diagnostics/tmp/opcodes` | Complete reverse-engineered TMP/AppV2 opcode catalogue. |
| `deco://diagnostics/tmp/mutations` | Raw TMP write, preflight, verification and rollback evidence. |
| `deco://diagnostics/coverage` | P9 HTTP/TMP evidence coverage and remaining gaps. |
| `deco://profiles/P9` | Stored P9 model and firmware evidence. |
| `deco://profiles/P9/operations` | Stored P9 evidence overlaid on raw operations. |

## Tools

By default agents see only the five non-duplicative protocol-neutral tools
below. Resources are the canonical state views. Default tools are retained only
for parameterized or specially gated reads and the mutation workflow. The
server resolves the connected controller and chooses implementations; the
agent never supplies a live model or protocol.

| Primary tool | Behaviour |
|---|---|
| `deco_get_capability` | Read any registered semantic capability, including mesh, clients, network state, wireless settings and TMP-only network configuration; normalize the result and report source interface, operation, attempts and fallback use. |
| `deco_plan_mutation` | Resolve one semantic mutation against the connected profile. State changes remain blocked; an eligible, fully gated current-value verification receives a one-shot five-minute plan ID. |
| `deco_execute_mutation` | Consume an eligible plan ID once, require its exact confirmation, verify controller identity, and execute with immediate verification and rollback without fallback. |
| `deco_get_wlan_state` | Return opted-in WLAN state with passwords omitted unless `include_passwords=true`. |
| `deco_get_cloud_state` | Return opted-in DDNS through schema-equivalent HTTP-to-TMP fallback and HTTP-only cloud-manager state when available. |

The legacy compound reads `deco_get_router_profile`,
`deco_get_network_overview`, `deco_get_mesh_overview`,
`deco_get_client_overview` and `deco_get_system_overview` remain available in
diagnostic mode for compatibility. They are excluded from the default surface
because their data is available through the semantic resources: configuration
contains the detailed network features, normalized device records contain
topology and blocking state, traffic has its own resource, status contains
speed-test and firmware state, and logs exposes levels without contents.
Client-bearing and private overview reads require
`DECO_ALLOW_SENSITIVE_READS=1` independently of diagnostic visibility.

Every tool publishes MCP annotations. Read tools advertise `readOnlyHint=true`;
the semantic planner is non-destructive but stateful because it may create a
one-shot plan; execution and verified no-op tools conservatively advertise
possible destructive effects. All tools operate against the configured Deco
mesh rather than an open-world target.

The semantic mutation workflow is discover, plan, authorize and execute:

1. Read `deco://mutations`. It includes all 22 known semantic intents, including
   unverified or blocked entries, without exposing duplicate HTTP forms or TMP
   opcodes.
2. Call `deco_plan_mutation` with a semantic name, `changes_json`, and mode.
   State-changing mode currently returns blockers because general semantic
   execution is not implemented. The verified `system_log_prepare` intent
   documents the required `level`, but remains unavailable through the default
   executor; diagnostic raw execution still requires its independent gates and
   exact reviewed plan hash. `mode="verify_current_value_noop"` accepts no desired
   changes and can issue a plan only for an exact connected P9 profile with all
   required gates enabled.
3. Review the returned model, scope, gates, blockers and exact confirmation.
4. Call `deco_execute_mutation` with only the plan ID and confirmation. Plans
   expire after five minutes, are bound to the controller identity, are consumed
   once and never fall back to another protocol.

Automatic fallback is limited to the six registry entries with live P9 schema
or boolean-contract equivalence. HTTP is currently preferred because it has the
stronger typed SDK façade. TMP fallback requires its ordinary read gate, pinned
host key and credentials; secret logical capabilities also require the single
sensitive-read gate before either transport is selected. Errors include only
the failed interface and exception type in successful fallback provenance.
When HTTP identity discovery fails with an eligible transport or invalid-shape
error, the resolver may bootstrap from read-only TMP opcode `0x400F`. HTTP
authentication failures never trigger that fallback, host-key mismatches fail
closed, and an unknown model is cached only for identity reporting rather than
authorizing P9-specific reads.
Mutations are never retried or routed automatically. Executable semantic
mutation routes are fixed to HTTP for beamforming, fast roaming and time
settings. TMP/AppV2 writes have no server route, including monthly report.

This first registry intentionally covers only overlaps with demonstrated
normalization equivalence. Protocol-unique datasets remain on the diagnostic
surface until they receive stable logical names and normalized schemas; the
router never invents equivalence merely to hide a transport distinction.

The remaining tools are registered only when
`DECO_MCP_EXPOSE_DIAGNOSTIC_TOOLS=1`. They support endpoint research, complete
batch access, compatibility audits and explicitly gated mutation analysis. The
flag does not authorize writes; all mutation gates and exact per-call
confirmations still apply independently.

| Tool | Behaviour |
|---|---|
| `deco_get_capability` | Protocol-neutral capability read; also remains present on the diagnostic surface. |
| `deco_plan_capability_mutation` | Legacy fixed no-op route inspection retained on the diagnostic surface. |
| `deco_verify_setting_noop` | Legacy direct semantic no-op verifier retained on the diagnostic surface; normal agents use plan and execute. |
| `deco_endpoint_catalog` | Filter operations and optionally add a model overlay with `model="P9"`. |
| `deco_p9_profile` | Return the bundled P9 observation summary and inferred, untested mutation candidates. |
| `deco_transport_capabilities` | Explain implemented, unsupported and detected Deco transports. |
| `deco_probe_p9_transport_services` | Check ports 22, 20001 and 20002 without authentication or payloads. |
| `deco_p9_tmp_opcode_catalog` | Filter AppV2 metadata and P9 evidence by safety, functional category, name, alias or opcode query. |
| `deco_p9_tmp_mutation_inventory` | List all TMP writes and their evidence gaps without opening a router session. |
| `deco_p9_access_coverage` | Explain all P9 read call paths, mutation evidence and remaining implementation or verification gaps offline. |
| `deco_plan_tmp_mutation` | Build one non-executable TMP preflight, verification and rollback plan offline. |
| `deco_p9_tmp_mutation_verification_queue` | Rank bounded TMP verification candidates offline; sensitive, deferred and destructive tiers require separate query opt-ins. |
| `deco_verify_p9_http_noop` | Repeat one of the three P9-verified HTTP setting no-ops using only live current values; requires the mutation and dedicated HTTP-no-op gates plus exact operation-specific confirmation. |
| `deco_tmp_host_key` | Read the TMP SSH fingerprint without authentication or a TMP payload. |
| `deco_tmp_read` | Invoke a gated read-only opcode; rejected P9 operations fail closed and untested reads require a second gate. |
| `deco_tmp_read_binary` | Read an observed binary response as size/SHA-256 metadata; base64 content requires the secret-read and binary-content gates. |
| `deco_discover_tmp_read_contracts` | Derive identifiers from confirmed reads in memory, try bounded parameterized GETs, and return only keys, codes and schemas; an opt-in mode tries inferred `0x404B` module-enum variants. |
| `deco_discover_tmp_unverified_reads` | Probe newly catalogued read-only opcodes with null/empty payloads and return only schemas, digests and error codes; requires the unverified-read gate. |
| `deco_get_p9_tmp_data` | Return complete responses for P9 TMP reads by category; `include_parameterized=true` resolves the seven confirmed parameterized contracts so all 55 JSON datasets are batch-callable. |
| `deco_p9_mutation_inventory` | Return all P9 mutation candidates with evidence, parameters, safety contracts, gates and execution eligibility. |
| `deco_p9_http_mutation_verification_queue` | Rank all 23 P9 HTTP writes offline; deferred, destructive and already-verified tiers require explicit query flags and no execution path is added. |
| `deco_operation_compatibility` | Explain generic metadata and model evidence for one operation. |
| `deco_get_p9_http_data` | Return complete envelopes for supported P9 HTTP reads, optionally scoped by controller; secret operations require two explicit opt-ins. |
| `deco_discover_p9_untested_http_reads` | Probe any remaining untested, non-secret P9 JSON reads using implemented owner-session or plaintext-bootstrap transport; currently none remain. |
| `deco_read_endpoint` | Call one read-only operation and return its complete firmware envelope. |
| `deco_validate_operation` | Check required parameters and SDK transport support without contacting the router. |
| `deco_plan_raw_mutation` | Build a raw endpoint-level preflight, verification and rollback plan without contacting the router. |
| `deco_preflight_mutation` | Evaluate a known mutation preflight against live read-only router state; never invokes a mutation. |
| `deco_read_binary_endpoint` | Download an opted-in binary read and return size/SHA-256 metadata; requires sensitive and bulk-secret gates, plus the content-export gate for base64. |
| `deco_discover_p9_binary_reads` | Recheck the three P9 backup/log candidates behind sensitive and bulk-secret gates and return digest metadata only. |
| `deco_discover_capabilities` | Probe the dedicated component/capability endpoints. |
| `deco_discover_p9_reads` | Probe the curated non-secret P9 read surface. |
| `deco_discover_all_reads` | Probe every catalogued non-secret owner-session or plaintext-bootstrap read and return complete response values. |
| `deco_discover_p9_sensitive_schemas` | Observe opted-in P9 secret schemas without returning values. |
| `deco_discover_all_sensitive_schemas` | Observe all 57 opted-in secret JSON schemas—56 owner-session plus factory identity—without returning values. |
| `deco_get_clients_by_node` | Query `client_list` separately for every Deco MAC and retain node-to-client associations. |
| `deco_build_compatibility_manifest` | Return a value-free P9 manifest; pass `full=true` to probe the complete supported non-secret HTTP read catalog. |
| `deco_compare_manifests` | Compare two saved manifests locally without contacting a router. |

`deco_invoke_mutation` is not part of either the default or ordinary diagnostic
surface. `DECO_MCP_EXPOSE_RAW_MUTATION_TOOLS=1` exposes it independently for
endpoint-level research; execution still requires the applicable mutation,
destructive or internal gate, an exact model-evidence contract, the reviewed
parameter-bound plan hash and exact operation-name confirmation.

`params_json` is a JSON object containing the endpoint's `params` fields. For
example, a node-targeted read can pass:

```json
{"device_mac":"AA:BB:CC:DD:EE:FF"}
```

`deco_read_endpoint` dispatches the four documented plaintext `/login` reads
through a separate bootstrap path and does not create an authenticated owner
session for them. `login.default_info.read` remains secret-gated because a
factory-state unit may return its printed Wi-Fi password and WPS PIN; on the
configured P9 it returned HTTP 403.
`domain_login.dlogin.read` is not a bootstrap call: the P9 confirms it uses the
normal encrypted owner session and therefore also requires the sensitive-read
gate.

## Complete observed data batches

`deco_get_p9_http_data` selects only read operations marked `supported` by the
bundled P9 overlay and supported by an implemented HTTP transport. All 60 such
reads—57 owner-session and three plaintext bootstrap—have an SDK call path.
Pass a controller such as `admin/network` or `login` to keep responses bounded.
Secret operations are skipped by default; including them
requires both `include_sensitive=true` and
`DECO_ALLOW_SENSITIVE_READS=1`. Results preserve each complete firmware
envelope and report per-call firmware or transport failures without aborting the
remaining batch.

`deco_get_p9_tmp_data` selects the 48 data-returning opcodes whose confirmed
contract requires no parameters by default. It can be scoped to categories such
as `network`, `clients`, `wireless`, `system` or `qos`. Because these responses
can contain private topology, client and account state, the tool requires both
`DECO_ALLOW_TMP_READS=1` and `DECO_ALLOW_SENSITIVE_READS=1`. It never
selects payload-rejected, AppV2-rejected, binary, mutation, destructive or
internal opcodes.

Passing `include_parameterized=true` also calls the seven positively observed
parameterized reads. Owner-scoped requests use at most three owner identifiers
derived in memory from confirmed client/owner-list reads; the remaining four
use only their live-confirmed signed-app version or empty IoT-list contracts.
Dependency responses are not added to a category-scoped result, request
parameter values are never returned, and a missing owner identifier produces a
labelled skip rather than a guessed payload. The unscoped batch can therefore
attempt all 55 observed JSON datasets. Both HTTP and TMP batch tools report
`mutation_invoked=false`.

Use `deco_p9_access_coverage` before selecting a lower-level tool. It derives
its counts from the bundled catalogues and P9 overlays without opening either
router transport. The matrix currently proves that all 60 supported HTTP reads,
55 data-returning TMP reads and the one TMP binary read have an agent-callable
path. It separately reports four payload-rejected TMP reads, 186 AppV2-rejected
TMP reads and zero untested TMP reads. All three bulk-secret HTTP binary
candidates have now been exercised: two failed at the transport boundary and
the log route returned an unvalidated 44-byte `text/plain` response. It also
reports 23
HTTP mutation candidates and 348 TMP write candidates. Positive read coverage
therefore does not imply complete API verification or mutation support.

The coverage resource also carries an explicit unresolved ledger and five
completed live-audit records. The beamforming and monthly-report current-value no-op harnesses have
now both completed and moved into the live-audit records; the authorization-ready
queue is empty. The same ledger records 19 untested HTTP writes, 345 untested TMP writes, four TMP payload-level
read rejections, and the one remaining unresolved TMP request contract. This is
planning metadata, not authorization.

The digest-only HTTP audit retained no binary content. Both configuration
backup paths raised transport errors. The log download returned 44 bytes of
`text/plain`; because this was not a validated log archive, it is classified
`invalid_response`, not supported. Agents should not treat any of the three as
a verified binary read. Domain login is separately confirmed as an authenticated
encrypted read returning null.

`deco_discover_p9_untested_http_reads` was the bounded follow-up for the HTTP
portion of that matrix. The completed pass selected `admin.firmware.upgrade.read`,
`admin.cloud.firmware_status.check` and
`admin.cloud.firmware_status.check_upgrade`; it excludes binary, multipart,
secret and mutation operations. The tool returns full non-secret
responses and isolated individual failures, with `mutation_invoked=false`.
The first operation returned HTTP 404; both firmware-status operations returned
data and are now in the bundled overlay. No safe generic JSON read remains
untested. After the plaintext bootstrap transport was implemented, a second
schema-only pass confirmed `login.auth.read`, `login.keys.read` and
`login.check_factory_default.read` without authentication or retained values.
The secret `login.default_info.read` returned HTTP 403 without exposing factory
credentials. The MCP tool therefore currently returns an empty non-secret
selection.
The equivalent terminal runner displays each endpoint and writes only status,
error-code and schema evidence:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
  op run -- uv run examples/p9_http_gap_probe.py \
  --host 192.168.68.1 \
  --output docs/api-responses/p9-http-gap-probe.json
```

Mutation calls must pass the endpoint's full dotted name twice: once as `name`
and again as `confirmation`. They must also copy `confirmation_sha256` from the
reviewed `deco_plan_raw_mutation` result into `plan_confirmation`. The hash binds the
operation name and exact JSON parameters, so changing parameters invalidates
the confirmation. Environment gates, the hash, and model verification are all
checked before a router connection is opened.

Call `deco_plan_raw_mutation` before considering a raw endpoint write. The planner validates the
parameters and transport, reports the model evidence and server gate, and
describes any known preflight read, success condition and rollback operation.
It never opens a router session. Address-reservation plans use `getlist` before
and after the proposed mutation; modify and remove rollbacks require the
preflight entry to be retained. A plan marked `ready_for_explicit_test` is only
mechanically eligible for a separately approved test: required parameters,
transport, server gate, preflight, verification and rollback contracts are all
present. It does not mean that the mutation has been verified on the P9.

For address reservations, call `deco_preflight_mutation` next. It reads the
current reservation table and reports capacity, duplicate MAC/IP conflicts,
target existence, whether a modify would be a logical no-op, and rollback
parameters. Invalid MAC/IP inputs and unsupported preflight families are
rejected or reported before a router connection. The result always includes
`mutation_invoked=false`; preflight does not require a mutation gate.

MCP execution is stricter than discovery: `deco_invoke_mutation` rejects an
operation unless the model overlay marks that exact mutation with
`mutation_test_scope="general"`. Reservation `modify`, beamforming `write`,
802.11r `write` and time-settings `write` each have one successful, explicitly
authorized unchanged-value test with before/after equality, recorded as
`noop_only`. That proves all four forms are callable but does not authorize
arbitrary changes. All 23 candidates therefore remain non-executable by an
agent—even if a mutation environment gate is accidentally enabled.

`deco_p9_mutation_inventory` provides the complete current decision surface in
one offline call. Every one of the 23 same-form candidates now identifies its
observed preflight/verification read. Ten reversible operations have complete
preflight, verification and rollback contracts: WAN mode, 802.11r,
beamforming, wireless operation mode, time settings, blacklist add/remove, and
address-reservation add/modify/remove. The other 13 remain capability clues
with incomplete safety contracts. LAN IP is deliberately incomplete because
the firmware asset and cross-model documentation disagree on parameter names.
None is execution-eligible: four have `noop_only` evidence and the other 19 have
no write evidence.

`deco_p9_http_mutation_verification_queue` applies the same bounded-verification
discipline used for TMP. Its default result is empty: none of the 19 untested
writes is presently safe to propose. Fifteen are high-risk connectivity,
runtime-action, access-policy, structured-state, regional, or observed-capacity
changes; three are destructive; and cloud nickname is evidence-blocked by its
missing parameter and rollback contracts. The four completed no-ops are kept in
a separate `verified_noop` tier. Query flags reveal these tiers for planning,
but the queue exposes no execution tool and generates no payloads.

All ten live preflight evaluators were exercised read-only on the P9. WAN mode,
802.11r, beamforming, wireless operation mode and time-setting preflights
recognized their current values as no-ops and captured rollback parameters. A
synthetic MAC was absent from the blacklist, so `add` passed preflight and
`remove` correctly failed. Reservation `add` correctly failed because the
table was full. Every preflight result reported `mutation_invoked=false`.

After explicit user authorization, the no-op reservation harness selected one
existing entry without displaying it, submitted its current MAC and IP
unchanged, received `error_code=0`, then required complete table equality. The
value-free evidence is in
[`p9-reservation-modify-noop.json`](api-responses/p9-reservation-modify-noop.json).

After separate explicit authorization, the bounded setting harness selected
beamforming, derived its mutation payload entirely from the current read, sent
the current boolean unchanged, received `error_code=0`, then required equality
of the relevant setting before and after the request. The value-free evidence
is in
[`p9-beamforming-noop.json`](api-responses/p9-beamforming-noop.json).

`examples/verify_setting_noop.py` also supports WAN mode, 802.11r, wireless
operation mode and time settings. For a selected operation it refuses to write
unless `--confirm` exactly matches the operation, rejects any nonzero firmware
error, then rereads and compares only the relevant setting fields. Every use is
a real write and requires separate explicit authorization. The completed
beamforming command was:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
  op run -- uv run examples/verify_setting_noop.py \
  --host 192.168.68.1 \
  --operation admin.wireless.beamforming.write \
  --confirm admin.wireless.beamforming.write
```

This establishes only that the P9 accepts the current beamforming value. It
does not prove that changing beamforming works or permit arbitrary values.

After another separate explicit authorization, the same harness sent the
current 802.11r boolean unchanged. The firmware returned `error_code=0` and the
verification read matched the original state. The value-free evidence is in
[`p9-ieee80211r-noop.json`](api-responses/p9-ieee80211r-noop.json). This is also
only `noop_only` evidence and does not prove arbitrary 802.11r changes.

After separate explicit authorization, the harness also sent the current
timezone, continent and region values unchanged. The firmware returned
`error_code=0` and all three fields matched afterward. The value-free evidence
is in [`p9-timesetting-noop.json`](api-responses/p9-timesetting-noop.json). This
does not prove that changing any time-setting field is safe or supported.

`deco_verify_p9_http_noop` can repeat only the already verified beamforming,
802.11r and time-settings current-value writes. Reservation modification remains
excluded because complete table equality can detect drift but cannot reliably
restore an arbitrary changed table. The tool accepts an operation name and its
exact confirmation string from `deco_p9_mutation_inventory`; it accepts no
desired value or request parameters. It requires both
`DECO_ALLOW_MUTATIONS=1` and
`DECO_ALLOW_HTTP_NOOP_VERIFICATION=1` before server startup.

Each call reads current state, writes only those exact fields, immediately
rereads them, and writes the preflight state again if verification mismatches or
fails. Results retain no setting or response values. Calls are serialized, and
any outcome other than `verified_noop` trips a process-lifetime latch that
rejects later HTTP no-op attempts until server restart. The generic mutation
tool still rejects all `noop_only` evidence, and changing any setting remains
unsupported. The scoped MCP path itself has been unit- and package-tested but
has not yet been invoked live.

The high-level network, WLAN and cloud tools require the sensitive-read gate.
The network view invokes the secret-classified `wan_ipv4` route, although its
serializer exposes only typed IP/interface fields and drops unknown dial
fields. The WLAN view's default response contains no Wi-Fi password fields.
Passwords are returned only when both the server gate is enabled and the tool
caller explicitly passes `include_passwords=true`.

Together, the agent-oriented network, mesh, WLAN, cloud, client and system
views cover all 26 P9 reads currently observed to return structured data. The
network view includes LAN IPv4, LAN IP, VLAN, MAC-clone and WAN-mode state; the
WLAN view includes bridge/backhaul, 802.11r, beamforming and wireless operation
mode. Generic endpoint tools remain available for complete envelopes and for
accepted-null or future firmware-specific reads.

## Safety model

The machine-readable catalogue currently describes 570 distinct operations
across 62 controller paths: 219 reads, 228 ordinary mutations, 35 destructive
operations and 88 internal operations.

- `read_only` operations retrieve state.
- `mutation` operations alter ordinary configuration or runtime state.
- `destructive` operations can interrupt service, remove devices/data, reset or
  upgrade the mesh.
- `internal` operations are intended for firmware components and mesh-to-mesh
  coordination rather than external automation.

Sensitivity is independent of safety. A read can still expose Wi-Fi passwords,
VPN keys, account tokens, logs or configuration backups and is therefore marked
`secret`.

Transport support is also independent. Owner-session encrypted/plain calls,
four plaintext login/bootstrap reads, both configuration-backup download paths
and the explicit log-download transport are implemented. Group-key discovery,
node-token sync and multipart restore/upload operations are catalogued so agents
can reason about them, but metadata marks them as unsupported by the available
call paths. The MCP server rejects those operations instead of attempting them
under the wrong authentication scheme.

## TMP/AppV2 and PLC discovery

[`tmpkit`](https://github.com/roger-/tmpkit) documents a separate Deco
TMP/AppV2 protocol, tested by that project only on X5000/AX5000 hardware. Its
transport opens Dropbear SSH on TCP 20001 using a TP-Link-ID-derived username,
then forwards to `127.0.0.1:20002`. Its reverse-engineered opcode catalogue
includes `PLC_PAIR_GET` and `PLC_PAIR_SET` as well as clients, leases,
reservations, VLAN, LAN, firmware and security operations.

The SDK preserves all 192 opcodes from that source and overlays the opcode map
from the signed TP-Link Deco Android 3.10.215 build 1484 APK. The combined
discovery catalogue contains 600 operations: 246 conservative reads, 277
mutations, 71 destructive operations and six protocol-internal operations. The
newer registry retains every original code, renames `0x400E` from the legacy
`TIME_SYNC` label to the app's `SYSTEM_TIME` label, and adds 408 codes. Removal,
clear and eject operations are classified destructive conservatively. All TMP
data is private or secret, and every entry retains an exact P9 observation
separate from its generic firmware catalogue entry.

The newer registry initially contributed 175 untested reads. The first
standalone value-free pass selected all 129 non-secret entries and exercised
166 null or empty-object variants. Every variant returned AppV2 error 12; none
reached a firmware JSON envelope. The exact result is recorded as `rejected`
without assigning a meaning to error 12. A second pass exercised the 43
secret-classified reads across 71 variants; both `DEVICE_LIST_GET` controls
returned data and all candidate variants returned AppV2 error 12. Static review
then reclassified three GET-named operations as secret mutations because the
signed app routes them through its set dispatcher to perform quick-setup
configuration synchronization, TSS network-configuration synchronization, or
OpenVPN certificate export. The runtime overlay now contains exact observations
for all 246 conservative reads: 55 returned JSON, one returned binary, four
reached firmware but rejected the payload, and 186 returned AppV2 error 12.

The probe prints every opcode and payload variant as activity and records only
status codes, response schemas, binary sizes and SHA-256 digests. Current runs
also execute value-free `DEVICE_LIST_GET` controls before and after the batch
to prove that the same session still accepts a known-good opcode. It sends one
null payload to operations whose signed-app call site uses null; other reads
also receive a bounded empty-object fallback. It never selects mutation,
destructive or protocol-internal opcodes. The initial non-secret evidence is in
[`p9-tmp-new-read-discovery.json`](api-responses/p9-tmp-new-read-discovery.json).
The control-validated sensitive pass was run as:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
DECO_TP_LINK_ID='op://Private/tplinkdeco.net/tp_link_id' \
DECO_TMP_HOST_KEY_SHA256='SHA256:TpmUAt8R9aKgOoas0FlZybt0YeLufHW3+JIEffm2/Ts' \
  op run -- uv run examples/tmp_unverified_read_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --include-sensitive \
  --output docs/api-responses/p9-tmp-sensitive-read-discovery.json
```

Secret-classified candidates are excluded unless `--include-sensitive` is
supplied. That opt-in can cause the router to return account, client, VPN,
telephony or backup data into process memory, although the probe still discards
all values and writes only value-free evidence. Use `--max-operations N` for a
short smoke pass. The equivalent MCP tool additionally requires
`DECO_ALLOW_TMP_READS=1` and
`DECO_ALLOW_UNVERIFIED_TMP_READS=1`; sensitive selection also requires
`DECO_ALLOW_SENSITIVE_READS=1`.

A P9 audit on 2026-07-11 first found TCP 20001 open while conventional SSH 22
and direct TMP 20002 were refused. A later value-free live probe authenticated
to that SSH service, opened the `127.0.0.1:20002` channel, associated TMP,
allocated a token and negotiated AppV2. `DEVICE_LIST_GET` returned data.
`PLC_PAIR_GET` reached the firmware but returned AppV2 error 12 for JSON null,
an empty object, `device_id=default`, a real node ID and a raw empty payload.
The meaning of error 12 remains unknown, so the exact observation is recorded
as `rejected`, not inferred to mean that the P9 lacks PLC. The sanitized
evidence is in
[`p9-tmp-read-matrix.json`](api-responses/p9-tmp-read-matrix.json).

The subsequent complete schema-only pass exercised all 74 semantic read
opcodes in the original registry. Forty-eight returned JSON with payload `error_code=0`,
`FW_PROG_GET` returned a 67-byte binary response, 11 returned JSON with payload
`error_code=1`, and 14 returned AppV2 error 12. Four initially
ambiguous eight-second results were retried at 60 seconds, leaving no timeout or
unknown result. No mutation opcode was invoked during that discovery pass and
no response values were persisted. A bounded follow-up tried empty-object,
raw-empty, pagination,
default-device and real-device variants as applicable to the rejected reads;
all retained error 12. `PLC_PAIR_GET` had already received five variants.
`SCAN_SSID_LIST_GET` was deliberately not fuzzed beyond its initial null request
because another shape may initiate an active radio scan. The full evidence is in
[`p9-tmp-discovery.json`](api-responses/p9-tmp-discovery.json) and the compact
runtime overlay is bundled as `p9_tmp_compatibility.json`.

The SDK implements a typed stream-based AppV2 session with association,
CRC-checked TMP framing, protocol negotiation, response reassembly and a hard
read-only check on every public generic call. Its optional `tmp` extra adds a Paramiko SSH adapter
with host-key pinning. `deco_tmp_read` exposes all 55 successful JSON reads
subject to the independent TMP and secret-data gates. `deco_tmp_read_binary` exposes
the one observed binary response as size and SHA-256 metadata by default;
returning its base64 content additionally requires both the secret-read and
binary-content gates. The
seven recovered operations require exact confirmed parameter-key sets; invalid
parameters fail before a session is opened. The 186 AppV2-level and four
payload-level rejected reads fail closed before opening a session.
`deco_probe_p9_transport_services` repeats only those TCP connection checks and
reports `authentication_attempted=false` and `payload_sent=false`.

Three of the four payload-rejected reads—`SECURITY_INFO_GET`,
`IOT_CLIENT_LIST_GET` and `IOT_PRODUCT_PROFILE_GET`—use a null request in the
reference app, exactly matching the payload rejected by the P9. They are
therefore classified as model/firmware rejection rather than a fuzzy parameter
miss. `IOT_CLIENT_LIST_GET_BY_MODULE` has no call site in either analyzed
signed app and remains the only payload-rejected read with an unresolved
request contract.

Static re-analysis found no direct or inlined `0x404B` call in either signed
app. The 3.10.215 app does, however, serialize the IoT module enum values used
throughout the adjacent client API. The resulting `{"module": <enum>}` shape is
an inference from opcode semantics plus a signed-app enum, not a recovered call
contract and not evidence that the P9 supports the operation.

`deco_discover_tmp_read_contracts` addresses the remaining payload-level read
gap without relaxing `deco_tmp_read`: it requires both the TMP-read and
sensitive-read gates, obtains owner identifiers from three confirmed reads,
retains at most three values in memory, and combines them with four exact
request shapes recovered from the signed TP-Link Deco Android 1.10.5 APK. It
tries no more than 60 semantically matched GET payloads, never invokes scan or
mutation opcodes, and never emits or persists source or response values.
With `include_inferred_iot_module_contract=true`, it adds exactly 11 `0x404B`
requests—one for each concrete 3.10.215 IoT module enum—and labels their weaker
evidence explicitly. For MCP, this inferred mode additionally requires
`DECO_ALLOW_UNVERIFIED_TMP_READS=1`; the ordinary exact-contract mode does
not. The terminal runner's explicit flag is its direct operator opt-in.
The equivalent terminal runner reports every attempted operation:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
DECO_TP_LINK_ID='op://Private/tplinkdeco.net/tp_link_id' \
DECO_TMP_HOST_KEY_SHA256='SHA256:TpmUAt8R9aKgOoas0FlZybt0YeLufHW3+JIEffm2/Ts' \
  op run -- uv run examples/tmp_read_contract_probe.py \
  --host 192.168.68.1 \
  --include-inferred-iot-module-contract \
  --output docs/api-responses/p9-tmp-contract-probe.json
```

That pass made 20 bounded attempts and confirmed 17 variants across seven
unique operations. In addition to `OWNER_GET`, `PARENT_CTRL_INSIGHTS_GET` and
`PARENT_CTRL_HISTORY_GET`, it recovered `DEFAULT_WEBSITE_APP_GET`,
`IOT_CLIENT_GET`, `SECURITY_CATEGORY_LIST_GET` and `SECURITY_RULE_LIST_GET`.
`owner_id` alone works for the first three; the two parental-control history
reads also accepted owner plus epoch-range or pagination keys. The four
app-derived reads require their exact version or IoT-list wrapper shapes. No
source or response values were retained. A subsequent value-free pass tried all
11 inferred `0x404B` module-enum variants. Every one returned firmware
`error_code=1`, so the bounded `{"module": <enum>}` hypothesis is rejected for
this P9 build. The exact request contract remains unresolved because neither
signed app contains a call site.

`deco_plan_tmp_mutation` and `deco_p9_tmp_mutation_inventory` remain offline
analysis only. They cover all 348 writes:
277 ordinary mutations and 71 conservatively destructive operations. Opcode-name
relationships provide 222 candidate preflight/verification reads, 70 of which
returned data on this P9, and 188 candidate rollback relationships. Eighty-one
preflight relationships and 24 rollback relationships are curated; the
remaining relationships are explicitly labelled signed-app opcode-name or
state-restore inferences. These are planning clues rather than proven
contracts. Across the two signed apps, 315 writes now have static call-site
evidence. The original direct analysis accounts for 291; a second pass recovered
24 more through virtual opcode dispatch. In total, 274 expose request models
with candidate top-level keys, 27 send null payloads and 14 retain model-only
evidence. Thirty-three write declarations still have no app call site.
Candidate keys are a
conservative union of serialized model fields and can include response-only or
conditionally omitted fields; they are not an executable JSON schema.

Three separately authorized P9 runs sent the current value for `11R_SET`
(`0x4209`), `BEAMFORMING_SET` (`0x421C`) and `MONTHLY_REPORT_MGR_SET`
(`0x4223`). Each setter returned firmware error code zero and its immediate
post-read matched. Those immediate observations are retained as
`same_value_immediate_verification_passed`, while all three safety statuses are
`safety_not_established`. A later mesh incident is temporally associated with
aggregate TMP activity but is not attributed to these writes or any other
opcode; causality is undetermined. The incident and containment decision are
recorded in
[`2026-07-12-p9-tmp-topology-loss.md`](incidents/2026-07-12-p9-tmp-topology-loss.md).

MCP, REST and the deployed service hard-disable every TMP write. There is no
`DECO_ALLOW_TMP_WRITES` or server TMP no-op gate, and enabling the retired
`DECO_ALLOW_TMP_NOOP_VERIFICATION` setting is a configuration error. The TMP
diagnostic surface exposes catalogues, plans and read operations only.

`deco_p9_tmp_mutation_verification_queue` converts that inventory into seven
agent-readable tiers without opening either router transport. `11R_SET`,
`BEAMFORMING_SET` and `MONTHLY_REPORT_MGR_SET` are retained in the
`safety_not_established` tier and are not eligible for server execution.
The default non-secret future-work view is empty. Eighty-one
active-workflow or connectivity-changing operations are
deferred, 193 are blocked by missing preflight, rollback, key-level parameter,
or preflight/schema key-coverage evidence, and all 71 destructive operations are excluded. Sensitive, deferred
and destructive tiers require explicit query flags. Every returned candidate
states that per-operation authorization is required, `router_contacted=false`,
`mutation_invoked=false` and `execution_eligible=false`.

The three operation-specific source-checkout harnesses remain available only
for future controlled-environment investigation. Before any credentials or TMP
session are opened, each requires `DECO_TMP_LAB_ALLOW_WRITES=1`, its exact
per-operation confirmation, and exact expected model, firmware and controller
MAC arguments that must match live opcode `0x400F` identity. They are not MCP,
REST or installed-service write paths and must not be used on a production mesh.

`QOS_MODE_SET` was removed from the
verification queue because the signed setter candidate keys are
`custom_detail,qos_mode`, while the P9 preflight schema contains only
`custom_detail`. The queue now requires live preflight schemas to cover every
candidate setter key before proposing a same-value or round-trip verification.
Of 67 mutations with both a data-returning P9 preflight and static setter keys,
19 have full top-level key coverage and 48 are blocked by at least one missing
candidate key. Risk, sensitivity, rollback and incident evidence still leave
all TMP writes execution-ineligible.

The risk audit defers every secret candidate. IPv4 and IPv6 setters are marked
as connectivity changes; IPv6 firewall writes are both connectivity and
security-policy changes; manager-permission and owner-list writes are access or
ownership changes. Reservation add is also deferred because the last P9
observation reported `is_full=true` and `max_count=64`; a future live preflight
must prove capacity before it can be reconsidered.

The catalogue records what firmware families document, not what every P9 build
implements. Use capability discovery and retain the resulting model, hardware
and firmware-specific observation before enabling mutation tools.

## Model compatibility overlay

The generic catalogue and model evidence are deliberately separate. The P9
overlay covers every catalogue operation and reports live availability, whether
a successful read returned data, web-asset presence, evidence confidence, any
model transport override, and whether the exact mutation has been tested.

The bundled P9 overlay currently contains 570 operations: 64 supported, 52
rejected, 100 not found, six transport failures, one invalid response, and 347
untested. Thirty-two
accepted reads returned data; 28 returned null. Ninety-four
catalogue operations share one of the 48 forms declared by the web assets.
Reservation, beamforming, 802.11r and time-settings mutations are marked tested
with `noop_only` scope. Asset presence and same-form inference never set
`verified_callable=true` by themselves.

Use `deco_operation_compatibility` before a call, or pass `model="P9"` to
`deco_endpoint_catalog`. `deco_validate_operation` includes the overlay and
reports the effective model transport without contacting the router.

The repository includes a value-free [observed P9 manifest](./api-responses/p9-compatibility.json)
for firmware `1.3.0 Build 20250804 Rel. 58832` on hardware revisions 1.0 and
2.0. The original complete manifest confirms 31 supported non-secret reads; 46
additional operations were
rejected by the controller, 67 controller/form paths returned HTTP 404, and two
returned HTTP 500. A subsequent asset-guided read confirmed
`admin.cloud.firmware_status.read`, bringing the curated set to 32 reads. The
targeted follow-up added `firmware_status.check` and `check_upgrade`, bringing
the curated set to 34; `admin.firmware.upgrade.read` returned HTTP 404. Three
live-confirmed plaintext bootstrap reads bring the curated set to 37.
Twenty-three non-read operations share a form with one of those supported reads
and are exposed as mutation candidates, but remain explicitly unverified until
a separately approved write test is performed.

A subsequent bounded fuzzy pass tested 237 operation and parameter variants
twice. All observations were internally consistent: 191 were rejected, six
returned HTTP 500, and 40 were accepted with a `null` result. None returned
additional data, so no fuzzy candidate was promoted into the P9 supported-read
set. One expired session was refreshed and the interrupted read was retried
before its evidence was recorded.

The P9 also supports querying `client_list` separately with each mesh node's
MAC. The observed per-node union exactly matched the default client set, with
each client assigned to one node. Consumers must use the outer `node_mac` from
`deco_get_clients_by_node` as the association: the response's `access_host`
value is opaque and did not match the node MAC or device ID.

Compatibility manifests retain operation status, error codes and response field
paths/types, but omit all response values. They can therefore record firmware
coverage and schema changes without copying client names, MAC addresses, IP
addresses, credentials or tokens from the mesh.

The standalone read-only probe can add bounded fuzzy observations to a version
2 manifest. These are deliberately separate from catalogue observations and
include their source operation, generated read alias or parameter shape, two
attempt statuses, error-code evidence and confirmation state. Session failures
are refreshed and retried once rather than being treated as endpoint evidence.
A fuzzy result is not promoted into the bundled P9 supported set until it has
been reviewed.

Static analysis of the observed P9 web UI added a separate source of evidence.
Its 39 public assets reference 48 forms across 18 controllers, including ten
forms missing from the earlier cross-model catalogue. Seven newly identified
non-secret reads were then tested: two accepted the call with a null result,
one returned firmware-status data, two returned API error 1, and two returned
HTTP 404. The firmware-status response uses JavaScript's non-JSON
`Number.NaN` token for an idle download; the protocol parser normalizes that
token to JSON `null` only when it appears outside a quoted string. The live P9
read confirmed the normalized response still has `error_code=0`. The value-free
route, operation, field and classification record is
[p9-web-assets.json](./api-responses/p9-web-assets.json). Asset-derived
mutation parameters are labelled `contract_source=firmware_asset`; none of
those mutations has been invoked.

The complete sensitive-schema pass used the nine asset-backed observations as
a resume seed, then queried the remaining 46 secret owner-session JSON reads.
It retained no response values and excluded binary downloads. Nineteen calls
were accepted, but only WAN IPv4, WLAN, cloud DDNS, and cloud-manager permissions
returned structured data; the other 15 returned null. Five were rejected, 30
returned HTTP 404, and IPv6 returned HTTP 500. The resulting
[value-free manifest](./api-responses/p9-all-sensitive-compatibility.json)
contains only operation status, field paths/types, and schema hashes.
The later bootstrap pass added three non-secret supported schemas; the secret
factory-identity form returned HTTP 403 and emitted no credential values. Its
value-free record is
[`p9-bootstrap-compatibility.json`](api-responses/p9-bootstrap-compatibility.json).

A subsequent targeted read resolved the remaining domain-login ambiguity. The
P9 public web model assigns `/domain_login?form=dlogin` to the ordinary
encrypted proxy and omits it from the plaintext allowlist. An authenticated
owner-session `read` returned `error_code=0` with a null result, so the endpoint
now has the same generic and MCP read path as other encrypted JSON operations.
The value-free evidence is in
[`p9-domain-login-compatibility.json`](api-responses/p9-domain-login-compatibility.json).

The complete mode checkpoints atomically after every endpoint. Resume preserves
supported, rejected, not-found, and explicit HTTP-status observations while
retrying missing, malformed, or connection-level failures:

```bash
DECO_PASSWORD='op://Private/tplinkdeco.net/password' \
  op run -- uv run examples/read_only_probe.py \
  --host 192.168.68.1 \
  --timeout 60 \
  --resume-sensitive-manifest docs/api-responses/p9-sensitive-compatibility.json \
  --manifest-output docs/api-responses/p9-all-sensitive-compatibility.json
```
