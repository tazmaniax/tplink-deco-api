# REST API

The optional REST adapter exposes the same semantic Deco service used by MCP.
It never asks callers to select HTTP/LuCI or TMP/AppV2, and it preserves the
same capability provenance, sensitivity gates, mutation gates and no-fallback
mutation policy.

## Enable the API

Install and run the combined server:

```bash
uv sync --extra server --extra tmp
DECO_MCP_TRANSPORT=streamable-http \
DECO_SERVER_HOST=127.0.0.1 \
DECO_SERVER_PORT=8000 \
DECO_MCP_PATH=/mcp \
DECO_MCP_PUBLIC_URL=http://127.0.0.1:8000/mcp \
DECO_SERVER_ALLOWED_HOSTS=127.0.0.1:8000 \
DECO_SERVER_BEARER_TOKEN='<at-least-32-characters>' \
DECO_REST_ENABLED=1 \
uv run tplink-deco-server
```

The REST base path defaults to `/api/v1`. MCP remains at `/mcp`. The server
uses one process and one router-session owner; running multiple replicas for
the same Deco mesh is unsupported because plans, latches and idempotency
records are process-local.

The REST and MCP paths must be absolute, have no trailing slash, remain outside
one another, and not overlap `/healthz`, `/readyz`, `/openapi.json`, `/docs` or
`/redoc`.

The shared server admits at most `DECO_SERVER_MAX_IN_FLIGHT_REQUESTS` concurrent
REST and MCP requests. Excess requests receive `429 Too Many Requests` with a
short `Retry-After` value instead of consuming unbounded worker threads.

## Authentication and transport security

Every `/api/v1` request requires:

```http
Authorization: Bearer <DECO_SERVER_BEARER_TOKEN>
```

The raw `Host` header must exactly match one entry in
`DECO_SERVER_ALLOWED_HOSTS`. Requests carrying an `Origin` must exactly match
one entry in `DECO_SERVER_ALLOWED_ORIGINS`; requests without `Origin` remain
valid. Allowed browser origins receive CORS headers for `GET`, `POST` and
`OPTIONS`. Cookie credentials and wildcard origins are not enabled.

`/healthz` reports process liveness and `/readyz` reports whether the process
can accept requests. Neither endpoint authenticates to or contacts the router.

Authenticated OpenAPI is available at `/openapi.json` whenever REST is enabled.
Interactive documentation is disabled by default; set
`DECO_REST_EXPOSE_DOCS=1` to expose authenticated `/docs` and `/redoc` routes.
Browser use requires a trusted proxy or extension that supplies the bearer
header when fetching both the HTML and schema. Do not expose the service outside
a trusted network without TLS.

## Semantic reads

| Method | Path | Result |
|---|---|---|
| `GET` | `/api/v1/service` | Sanitized server settings, gates and connection state. |
| `GET` | `/api/v1/status` | Normalized internet, controller and mesh health. |
| `GET` | `/api/v1/configuration` | Sanitized network and system configuration. |
| `GET` | `/api/v1/mesh?refresh=false` | Controller and mesh-node inventory. |
| `GET` | `/api/v1/clients?view=all` | `all`, `active`, `inactive` or `blocked` clients. |
| `GET` | `/api/v1/traffic` | Per-device and aggregate traffic rates. |
| `GET` | `/api/v1/address-reservations` | DHCP address reservations. |
| `GET` | `/api/v1/log-types` | Available categories without log contents. |
| `GET` | `/api/v1/capabilities` | Read capability inventory and support evidence. |
| `GET` | `/api/v1/capabilities/{name}` | One capability value with routing provenance. |
| `GET` | `/api/v1/wlan?include_passwords=false` | Gated WLAN state. |
| `GET` | `/api/v1/cloud` | Gated DDNS and cloud-manager state. |
| `GET` | `/api/v1/mutations` | Mutation inventory and eligibility. |
| `GET` | `/api/v1/mutations/{name}` | One mutation candidate. |

Responses retain `schema_version` where the semantic service defines it.
Private and secret responses must not be cached or persisted unintentionally.

## Response contracts

Every successful operation references a named response schema in OpenAPI rather
than an unstructured JSON-document placeholder. Stable top-level fields are
explicitly typed, so generated clients, editors and schema validators can detect
missing fields and type changes. Firmware-dependent nested router data remains a
recursive JSON value where TP-Link models legitimately return different shapes.

The same contracts are exported as frozen standard-library dataclasses from
`tplink_deco_api.responses`. They are protocol-neutral and mapping-compatible,
so REST and MCP can serialize the same result without maintaining parallel
models. The base SDK therefore does not depend on Pydantic; FastAPI consumes the
dataclasses only at the REST boundary to generate and validate OpenAPI responses.
Future source selection and resource boundaries are governed by the shared
[semantic resource routing policy](./architecture/semantic-resource-routing.md),
so REST and MCP continue to expose one service result without adapter-specific
transport logic.

```python
from tplink_deco_api.responses import NetworkStatusResponse

status: NetworkStatusResponse
payload = status.to_dict()
```

## Mutation workflow

Real state changes are not currently execution-eligible. Only fixed,
current-value no-op verification routes can produce executable plans, and only
when their server-side gates and exact P9 evidence are present.

Assess an intent without creating a plan:

```http
POST /api/v1/mutation-preflights
Content-Type: application/json

{
  "name": "beamforming",
  "mode": "verify_current_value_noop",
  "changes": {}
}
```

The response is `200 OK` and always has `plan_id: null`. It reports eligibility,
required gates and blockers without registering process state.

Create a plan with the same request at `/api/v1/mutation-plans`. An eligible
request returns `201 Created`, a plan ID, exact confirmation and five-minute
expiry. Its `Location` header identifies the new plan-status resource. An
ineligible request returns `409 Conflict` with structured blockers.

Inspect a pending plan:

```http
GET /api/v1/mutation-plans/{plan_id}
```

The status view reports plan state and expiry but does not repeat the exact
confirmation returned only when the plan was created.

Execute it synchronously:

```http
POST /api/v1/mutation-plans/{plan_id}/executions
Idempotency-Key: <unique-key-at-least-8-characters>
Content-Type: application/json

{
  "confirmation": "<exact confirmation returned by plan creation>"
}
```

A successful call returns the terminal verified result with `200 OK`. Reusing
the same idempotency key for the identical request replays the result while the
process remains alive. Reusing it for different content returns `409 Conflict`.
Restarting the process clears plans and replay records. MCP execution retains
its one-shot behavior and does not use REST idempotency replay.

## Errors

Domain and upstream failures use `application/problem+json` with stable `code`
and `request_id` fields. Expected statuses include:

| Status | Meaning |
|---:|---|
| `401` | Missing or invalid bearer token. |
| `403` | Sensitivity gate, mutation gate or exact confirmation rejected. |
| `404` | Unknown mutation plan or resource. |
| `409` | Ineligible mutation, controller change or idempotency conflict. |
| `410` | Mutation plan expired. |
| `422` | Invalid request body, query value or semantic input. |
| `502` | Router API or protocol failure. |
| `503` | Router transport unavailable. |
| `504` | Router request timed out. |

The server never includes router credentials, complete session tokens or raw
decrypted router payloads in error responses.
