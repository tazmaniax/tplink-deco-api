# Semantic resource routing policy

This document defines the required architecture for presenting HTTP/LuCI and
TMP/AppV2 data through protocol-neutral MCP resources and REST operations. It is
the design contract for future capability routing; the current implementation
is transitional and does not yet implement every rule below.

## Goals

- Expose every positively evidenced dataset through a semantic resource rather
  than leaving useful TMP data available only through diagnostics.
- Keep interface selection below the service boundary so callers never select
  HTTP or TMP.
- Fetch the requested data from one interface, using another only after an
  eligible failure.
- Prefer the source with the greatest verified semantic completeness for the
  connected model and firmware.
- Preserve sensitivity gates, provenance and partial-availability evidence.
- Share one service result and response contract between MCP and REST.

Raw operations, unverified reads, protocol catalogues and compatibility
evidence remain diagnostic. Promoting a positively evidenced dataset does not
make private or secret values unrestricted.

## Routing invariants

One successful resource read has exactly one data-producing interface. The
router must not perform routine shadow reads, compare live HTTP and TMP values,
or merge dictionaries returned by both interfaces.

The alternative interface may be contacted only after the preferred source
fails with a fallback-eligible error. Provenance records every attempted source,
but only the successful source contributes response data.

Mutation execution never falls back. These rules apply only to read-only
semantic capabilities.

Resource names describe the data, not its transport. Names such as
`deco://tmp/ipv6` and REST paths such as `/tmp/ipv6` are prohibited. A caller
must be able to consume the same response contract regardless of which source
succeeded.

## Source contracts

Every semantic capability must declare one or more ordered source contracts.
Each source contract records:

- interface and operation;
- applicable model, hardware and firmware evidence;
- sensitivity and required runtime gates;
- normalized field coverage;
- completeness rank;
- response normalizer and validation contract;
- fallback eligibility and known degraded fields.

Completeness measures verified semantic field coverage, never payload size or
raw key count. A source with additional unnormalized keys is not automatically
more complete.

The source registry is offline metadata. Selecting an eligible preferred source
must not perform a transport health probe before the real read because that
would add another router request.

## Selection algorithm

For each resource read:

1. Resolve controller identity from the cache, HTTP identity discovery, or the
   gated TMP device-list bootstrap.
2. Exclude sources lacking applicable model evidence, credentials, host-key
   configuration or required authorization.
3. Rank the remaining sources by verified completeness, then stable declared
   priority.
4. Invoke the highest-ranked source.
5. Normalize and validate a successful result, then return immediately.
6. After a fallback-eligible failure, invoke the next eligible source.
7. Return structured partial or unavailable evidence when no source succeeds.

The first successful source ends selection. Sources must not be invoked in
parallel.

TMP identity bootstrap is restricted to the read-only `DEVICE_LIST_GET`
contract, requires `DECO_ALLOW_TMP_READS=1`, configured TMP credentials and a
pinned host key, and must validate the returned controller shape before caching
identity. Resolving an unknown model permits identity reporting but does not
authorize model-specific TMP reads without matching evidence.

## Fallback eligibility

Fallback may follow:

- connection refusal, timeout or transport unavailability;
- an endpoint or opcode known to be unsupported by the connected firmware;
- a router rejection covered by the source contract;
- an invalid source response envelope or normalized shape.

Fallback must not conceal:

- SSH host-key mismatch;
- sensitivity or authorization failure;
- conflicting controller identity;
- mutation-related failure;
- an internal normalization or programming defect.

A disabled interface is excluded before invocation. A disabled sensitivity gate
blocks the semantic capability rather than encouraging a less-protected route.

## Resource boundaries

Resources fall into two categories:

| Category | Required behaviour |
|---|---|
| Overlapping capability | Ordered sources, one preferred read and evidence-backed fallback. |
| Single-source capability | One source and no fallback; structured unavailability when that interface cannot be used. |

Data that would force an overlapping resource to contact both interfaces must
be split into a separate semantic resource. For example, core client inventory
may use HTTP/TMP fallback, while TMP-only IPv6 clients and HTTP-only topology
assignments belong in separate child resources.

Domain index resources may list child resources using local metadata, but must
not fetch every child dataset. This keeps discovery cheap and live reads lazy.

Expected organization includes:

| Resource family | Routing shape |
|---|---|
| Mesh and core clients | HTTP/TMP overlap with one selected provider. |
| Internet status and address reservations | HTTP/TMP overlap with one selected provider. |
| Fast roaming and beamforming | HTTP/TMP boolean overlap. |
| IPv6 clients and firewall | TMP-only child resources. |
| Performance, time settings and log categories | HTTP-only child resources. |
| Parental controls, security, IoT and automation | TMP-only gated resources until another proven source exists. |
| QoS, reports, firmware and speed tests | Independent resources with per-dataset source contracts. |

## Normalization and provenance

Model- and interface-specific field aliases are normalized before DTO creation.
Semantic DTOs expose one canonical name, not every firmware spelling. Raw keys
remain available only on explicitly raw diagnostic operations.

Known aliases require deterministic precedence. Conflicting values must produce
an unavailable section or normalization warning instead of silent selection.
Missing source fields must not be represented as meaningful empty strings,
zeros or false values without corresponding availability evidence.

Every live semantic response records:

- overall status: `available`, `partial`, `unavailable` or `gated`;
- successful source interface and operation;
- attempted sources and failure types;
- source evidence and completeness rank;
- unavailable or degraded fields;
- observation time and whether router contact occurred.

The response must not include credentials, parameter values used solely for a
read contract, or raw secret data outside its authorized semantic fields.

## Verification requirements

Every new or changed route requires tests for:

- preferred-source success without contacting the fallback;
- preferred-source eligible failure followed by fallback success;
- both sources unavailable;
- source disabled or ineligible without router contact;
- non-P9 or unmatched firmware evidence;
- identity discovery through HTTP and cold-start TMP bootstrap;
- host-key mismatch failing closed;
- normalized field aliases and conflicts;
- declared completeness and degraded fallback fields;
- identical MCP and REST serialization of one service result;
- DTO construction and validation from fixture-driven service payloads.

Captured fixtures must be sanitized and must identify their model, hardware,
firmware, source interface and operation. Schema-only evidence can justify a
gated firmware-native semantic leaf, but not a normalized field-equivalence
claim.

## Current implementation gap

Controller identity now resolves from cached state, HTTP discovery, or the
gated, pinned-host-key TMP device-list bootstrap. The bootstrap records both
attempts, validates the controller shape before caching it, permits unknown-model
identity reporting, and does not authorize P9-specific reads for an unmatched
profile.

The current registry still has only six HTTP-primary, TMP-fallback read
contracts. Most canonical resources call HTTP directly, and the positively
observed TMP-only datasets remain diagnostic. Future routing work must migrate
these paths toward this policy without weakening existing mutation or
sensitivity controls.
