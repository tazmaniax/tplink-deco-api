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
* exposed 13 canonical resources for MCP state, network status, configuration,
  mesh nodes, all/active/inactive/blocked devices, traffic, address reservations,
  log categories, capabilities and mutations
* kept the default tool surface to five parameterized or action-oriented tools
  for capability reads, WLAN state, cloud state, mutation planning and mutation
  execution
* detected the connected controller and selected an evidence-backed HTTP/LuCI or
  TMP/AppV2 route without requiring agents to choose a model or transport
* added six bounded, positively evidenced read-only fallback contracts while
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
  capabilities, routes, mutation plans and verification results
* added a stream-based, CRC-checked TMP/AppV2 implementation and an SSH adapter
  with mandatory host-key pinning
* recovered and classified a 600-operation TMP/AppV2 catalogue from signed Deco
  Android applications while keeping the public generic TMP API read-only

### Model compatibility and discovery

* added model and firmware compatibility profiles so catalogue presence is not
  mistaken for confirmed support
* recorded positive P9 evidence for 59 data-returning HTTP reads and 55
  data-returning TMP/AppV2 reads
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

* inventoried 21 deduplicated semantic mutation intents, including blocked and
  unverified candidates
* added discover, plan, authorize and execute semantics using short-lived one-shot
  plans bound to the resolved controller and exact confirmation
* required immediate post-read verification and a defined rollback contract for
  eligible executions
* added independent gates for ordinary mutations, destructive operations,
  firmware-internal calls, HTTP no-op verification and TMP no-op verification
* recorded controlled P9 current-value no-op evidence for address reservation,
  time settings, beamforming, 802.11r and monthly-report setters
* kept desired state changes execution-ineligible because current live P9 write
  evidence is limited to unchanged-value verification requests

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
* verified the branch with 436 passing tests, 8 skipped hardware-dependent tests,
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
