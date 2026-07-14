# Changelog

## [0.1.0] - Unreleased

This is the first release of the model-aware service. It retains the typed
`tplink_deco_api` SDK while adding REST and MCP interfaces, a second local Deco
transport, compatibility evidence and a conservative mutation workflow.

### REST API

* added an authenticated OpenAPI 3.1 API under `/api/v1` alongside MCP at `/mcp`
* shared one `DecoService`, router session, safety policy and application
  lifespan across both protocol adapters
* added semantic status, configuration, mesh, client, traffic, reservation,
  log-type, capability, WLAN, cloud and mutation resources
* added gated, bounded system-log pagination at `/api/v1/logs/{index}` without
  implicitly preparing or replacing the router's current log snapshot
* published named OpenAPI response schemas from frozen protocol-neutral
  dataclasses shared with MCP, without adding Pydantic to the base SDK
* replaced finite firmware JSON shapes with one canonical recursive SDK type
  and documented completeness-ranked, single-source semantic routing policy
* separated non-creating mutation preflight from short-lived plan registration
* added synchronous no-op plan execution with process-local idempotent replay
* returned a configurable `Location` header for created plans while keeping
  exact confirmations out of subsequent plan-status reads
* returned typed RFC 9457 errors for plan, confirmation, controller, router and
  idempotency failures
* applied bearer authentication, Host and Origin enforcement, explicit CORS,
  request IDs and fail-closed configuration to the composite HTTP service
* rejected overlapping, nested and reserved REST or MCP route configuration

### MCP server

* added a protocol-neutral MCP server over stdio and authenticated Streamable HTTP
* exposed 34 canonical resources for MCP state, network status, configuration,
  mesh nodes and per-node traffic, WPS status, all/active/inactive/blocked
  devices, client traffic, address reservations, system LED state, LAN/DHCP/
  QoS/VLAN/NAT/IPTV/SIP ALG/MAC-clone state, IPv4 and IPv6 configuration/
  firewall/clients, monthly report settings and history, log levels,
  capabilities and mutations
* added gated resource templates for bounded system-log pagination and
  owner-specific parental-control policy, insight and history reads without
  duplicating those reads as tools
* kept the default tool surface to five parameterized or action-oriented tools
  for capability reads, WLAN state, cloud state, mutation planning and mutation
  execution
* detected the connected controller and selected an evidence-backed HTTP/LuCI or
  TMP/AppV2 route without requiring agents to choose a model or transport
* added a gated, pinned-host-key TMP device-list bootstrap so controller identity
  and mesh inventory can resolve when HTTP is unavailable at cold start
* migrated status, configuration and device resources to single-interface
  semantic routing, returning validated TMP subsets and explicit unavailable
  sections when HTTP cannot establish the session
* reused TMP after TMP identity bootstrap without repeating a known-unavailable
  HTTP capability attempt, while keeping unmatched models fail-closed
* added validated traffic and blocked-client HTTP-to-TMP fallback while keeping
  every compound device response bound to one selected interface
* added schema-equivalent speed-test and DDNS HTTP-to-TMP fallback, making the
  latest speed-test result available in TMP-backed status and returning explicit
  cloud-manager unavailability when DDNS selects TMP
* normalized HTTP node firmware checks and TMP release records into one status
  contract with explicit source-unavailable fields and read-only fallback
* routed the existing WLAN tool through normalized HTTP-to-TMP fallback while
  preserving explicit password inclusion and reporting HTTP-only feature gaps
* added wireless operation-mode and bridge/PLC HTTP-to-TMP fallback, retaining
  TMP's supported-mode list and completing TMP-backed WLAN feature state
* added normalized IPv4 WAN/LAN HTTP-to-TMP fallback, preserving TMP-only
  inbound-ping state and restoring those sections during eligible TMP startup
* exposed the validated P9 TMP system LED and night-mode schedule as a default
  protocol-neutral read without adding LED mutation support
* exposed validated P9 per-node mesh traffic through protocol-neutral MCP, REST
  and SDK contracts without inferring firmware speed units or summing forwarded
  traffic
* exposed validated P9 WPS timers and per-node session state as a private,
  read-only semantic resource while leaving WPS writes hard-disabled
* separated private monthly-report enablement from secret report history,
  normalized the validated P9 report schema and corrected the raw opcode's
  sensitivity gate without enabling report mutations
* exposed validated P9 parental-control profiles, filter defaults, application
  catalogue, per-owner insights and browsing history through protocol-neutral
  MCP, REST and SDK contracts without enabling parental-control mutations
* exposed validated P9 manager roles and component-access policies as a secret
  protocol-neutral read while preserving firmware-native lock values and
  leaving permission mutations unavailable
* enriched TMP-backed device records with blocking and live speed data instead
  of hiding those positively evidenced reads behind diagnostics
* promoted twelve positively evidenced TMP-only network datasets into eleven
  default protocol-neutral MCP resources and REST routes without enabling
  diagnostics, combining the QoS mode and bandwidth contracts into one view
* kept HTTP and TMP sessions lazy while separately reporting whether each
  capability source is configured, connected and runtime-gated
* added fifteen bounded, positively evidenced read-only fallback contracts while
  prohibiting mutation fallback
* moved protocol catalogues, raw reads, discovery probes and compatibility
  matrices to an independently enabled diagnostic surface

### Deco transports and SDK

* expanded the HTTP/LuCI catalogue to 376 operations across 49 controllers with
  safety, sensitivity, authentication, parameter and response-shape metadata
* added catalogue-driven encrypted owner-session calls, plaintext bootstrap
  reads, binary responses, multipart backup contracts and server-side logout
  handling
* added typed models for reservations, generic responses, compatibility evidence,
  capabilities, routes, system-log pages, mutation plans and verification results
* recovered and live-validated the P9 web firmware's system-log pagination and
  level-specific snapshot-preparation contracts without retaining log values
* added a stream-based, CRC-checked TMP/AppV2 implementation and an SSH adapter
  with mandatory host-key pinning
* recovered and classified a 600-operation TMP/AppV2 catalogue from signed Deco
  Android applications while keeping the public generic TMP API read-only
* confirmed against Deco Android 3.10.215 that the existing TMP catalogue had no
  missing named opcodes and distinguished TMP feedback-bundle creation from the
  web UI's HTTP level-specific snapshot preparation

### Model compatibility and discovery

* added model and firmware compatibility profiles so catalogue presence is not
  mistaken for confirmed support
* recorded positive P9 evidence for 60 HTTP reads, including 32 data-returning
  reads, and 55 data-returning TMP/AppV2 reads
* recorded a P9 outcome for all 246 conservatively classified TMP reads and
  inventoried all 348 TMP writes
* added sanitized, value-free P9 compatibility manifests and live-audit records
  without credentials, tokens, client identities, addresses or response values
* added bounded read-only probes for exact catalogue reads, sensitive schemas,
  fuzzy variants, binary digests, bootstrap data, per-node topology, HTTP gaps
  and TMP request contracts
* distinguished supported null results, firmware rejection, timeout, transport
  failure and unknown support throughout discovery and compatibility reporting

### Mutation safety

* inventoried 22 deduplicated semantic mutation intents, including blocked and
  unverified candidates
* added discover, plan, authorize and execute semantics using short-lived one-shot
  plans bound to the resolved controller and exact confirmation
* required immediate post-read verification and a defined rollback contract for
  eligible executions
* added independent gates for ordinary mutations, destructive operations,
  firmware-internal calls and HTTP no-op verification
* recorded controlled P9 current-value no-op evidence for address reservation,
  time settings, beamforming, 802.11r and monthly-report setters
* recorded a controlled P9 general-scope test of the transient system-log
  snapshot preparation mutation at the official web UI's default `NOTICE` level
* kept configuration state changes execution-ineligible; the validated transient
  log preparation remains raw-diagnostic until general semantic execution exists
* hard-disabled TMP writes in MCP, REST and the deployed service because the
  earlier same-value results established only immediate field equality, not
  operational safety; a later P9 mesh incident is recorded as temporally
  associated with aggregate TMP activity but unattributed, with causality
  undetermined
* retained TMP write harnesses only for source-checkout lab validation with an
  explicit lab gate, exact confirmation and exact live controller identity

### Security and deployment

* added independent gates for sensitive reads, bulk secret reads, binary export,
  TMP reads and unverified TMP reads, all disabled by default
* redacted credentials and sensitive fields from MCP state and default resources
* authenticated Streamable HTTP with a deployment-scoped bearer token using
  constant-time comparison, allowed-host enforcement and origin checks
* added a process-only health endpoint that never contacts the router
* added a multi-stage non-root Docker image and hardened Compose service with a
  read-only root filesystem, dropped Linux capabilities and ephemeral temporary
  storage
* kept the deployment host-neutral without requiring host networking or
  container-type-specific privileges

### Documentation and testing

* rewrote the root README around the MCP-first project, semantic agent contract,
  safety model, compatibility status, deployment options and SDK foundation
* added a complete MCP reference and expanded the endpoint, protocol and evidence
  documentation
* added network-free coverage for capability routing, catalogues, compatibility,
  MCP resources and tools, transport security, mutation planning and
  verification, discovery probes, AppV2 framing and SSH transport
* verified the branch with 477 passing tests, 8 skipped hardware-dependent tests,
  strict type checking, Ruff, package builds and Compose configuration checks

## [1.2.1](https://github.com/roquerodrigo/tplink-deco-api/compare/v1.2.0...v1.2.1) (2026-07-06)


### Documentation

* document the Deco local HTTP API and protocol ([fa49ba9](https://github.com/roquerodrigo/tplink-deco-api/commit/fa49ba926bc378689be434a23987ed2f549ec787))

## [1.2.0](https://github.com/roquerodrigo/tplink-deco-api/compare/v1.1.2...v1.2.0) (2026-06-15)


### Features

* add network, wireless, time and log endpoints + HTTPS transport ([6832d0b](https://github.com/roquerodrigo/tplink-deco-api/commit/6832d0b239082f5327fa7fbdd001202dd3e03631))
* release 1.2.0 (network/wireless/time/log endpoints + HTTPS) ([0761428](https://github.com/roquerodrigo/tplink-deco-api/commit/0761428150847f434b184850842be154d5e06e2d))

## [1.1.2](https://github.com/roquerodrigo/tplink-deco-api/compare/v1.1.1...v1.1.2) (2026-05-25)


### Documentation

* add CI and PyPI badges ([b6dd7d1](https://github.com/roquerodrigo/tplink-deco-api/commit/b6dd7d16b744e09a4c44bc3d2f9780253782574d))
* add CI and PyPI badges ([c1b6deb](https://github.com/roquerodrigo/tplink-deco-api/commit/c1b6debac7f8145b4f6a244f98e84988c5d06085))

## [1.1.1](https://github.com/roquerodrigo/tplink-deco-api/compare/v1.1.0...v1.1.1) (2026-05-14)


### Documentation

* translate README, auth-protocol and pyproject description to English ([da74081](https://github.com/roquerodrigo/tplink-deco-api/commit/da7408178b28f7d609965cd785c00f7a423bd462))

## [1.1.0](https://github.com/roquerodrigo/tplink-deco-api/compare/v1.0.1...v1.1.0) (2026-05-11)


### Features

* add NetworkTotals for aggregated client speeds ([041c8b6](https://github.com/roquerodrigo/tplink-deco-api/commit/041c8b6ebf394067ec3ea767c73efaab998d24c9))


### Dependencies

* bump cryptography 47 → 48 ([b5917ca](https://github.com/roquerodrigo/tplink-deco-api/commit/b5917cacde1c4772c2d7293ccdb150b83dfdc364))


### Documentation

* standardize CODE_STYLE.md and switch CLAUDE.md to English ([b216c23](https://github.com/roquerodrigo/tplink-deco-api/commit/b216c23480c61407a9227a38d3050b2666c8b36a))
