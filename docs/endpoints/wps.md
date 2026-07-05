# WPS — Wi-Fi Protected Setup

Endpoints: **`/admin/wps`** (app) and **`/admin/wpsd`** — the internal WPS daemon
endpoint. Both use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

WPS here is push-button (PBC) only. The factory WPS **PIN** is exposed
separately by [`/login?form=default_info`](./login.md).

Related: [README.md](./README.md), [wireless.md](./wireless.md),
[transport-and-dispatch.md](../protocol/transport-and-dispatch.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `status` | get | app | Read current WPS state + the list of clients that joined via WPS. |
| `state` | set | app | Start / cancel a PBC session. |

---

## `/admin/wps` · `status`

**get** → `{ "operation": "get" }`

Result:

| Field | Meaning |
|-------|---------|
| `wps_state` | `idle` (IDLE), `scanning` (ACTIVE), `active`, `busy` (BUSY). |
| `device_id` | Node handling the WPS session. |
| `scanning_time` / `remaing_time` | Countdown of the active window. |
| `wps_list` | Clients that connected via WPS this session. |
| `last_error_code`, `last_error_msg` | Last failure detail (`ERROR`, `TIMEOUT`, …). |

Success of a join surfaces as `REG_SUCCESS` / `SUCCESS` / `client_accessed`.
A hidden-SSID radio reports `HIDE`. The read takes a lock and returns `Busy` if
another WPS action holds it.

## `/admin/wps` · `state`

**set** → start or cancel PBC.

```json
{ "operation": "set", "params": { "dev": "<device_id>", "state": "pbc" } }
```

- `state: "pbc"` starts a PBC session.
- Cancelling clears it.

`params.dev` selects which mesh node runs WPS; omitting it targets the node
answering the request.

---

## `/admin/wpsd` — internal WPS daemon (internal)

`/admin/wpsd` is the daemon-facing endpoint, not an app API. It receives
**reports** from the WPS daemon about a running session and persists results.

| Form | Operations | Purpose |
|------|-----------|---------|
| `main` | report / dispatch | Ingest a PBC session report (`pbc` / `cancel`) with `code` + `data`; writes the result and, on smart-home models, uploads a `RULE_TRIGGER` property change. |
| `code` | — | WPS result/error code channel. |

Reports are validated against the active session (must be `ACTIVE`) and the
reporting `dev` id; mismatches are rejected ("Report with wrong dev_id or id
received"). Clients should use `/admin/wps`, not this endpoint.

---

## Notes

- Only PBC is exposed through the local API; there is no PIN-enrolment
  operation here (the factory PIN is read-only via `default_info`).
- `wps_state` maps internal daemon states (`IDLE`/`ACTIVE`/`BUSY`) to the
  lowercase values returned to the app.
- On smart-home-capable models a successful WPS join triggers a cloud property
  upload (cause `APP`/`VOICE`).
