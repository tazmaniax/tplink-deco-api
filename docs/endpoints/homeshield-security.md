# HomeShield security

Endpoints: **`/admin/security`** and **`/admin/camera_security`** (both
app-only). All forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

`/admin/security` is the HomeShield network-security engine (malicious-content /
intrusion / infected-device protection, threat categories, signature updates and
event history). `/admin/camera_security` is the separate smart-camera protection
feature (home / local-only camera modes and scheduled blocking).

Related: [parental-control-and-qos.md](./parental-control-and-qos.md) (HomeShield
parental controls & QoS), [clients.md](./clients.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `/admin/security` · `info` | read, write | app | Enable / read the security modules (`modules_status`). |
| `/admin/security` · `category` | read | app | Default threat-category list. |
| `/admin/security` · `rule` | read | app | Default signature-rule list. |
| `/admin/security` · `update` | write | app | Trigger a threat-signature DB update. |
| `/admin/security` · `history` | get, clear, remove | app | Security-event history. |
| `/admin/camera_security` · `camera_security` | get, set | app | Camera-security config (modes, cameras, triggers, auto-block). |
| `/admin/camera_security` · `camera_security_blocked_period` | get, set | app | Scheduled camera-block periods + block history. |

---

## `/admin/security` · `info`

**read** / **write** — the security feature state, carried under
**`modules_status`** (per-module enable flags).

## `category` / `rule`

**read** — `category` returns the default threat-category list; `rule` returns
the default signature-rule list. Both take a `version` param so the client can
skip a refresh when already up to date.

## `update`

**write** — kicks off a background threat-signature update.

## `history`

**get** / **clear** / **remove** — the log of detected / blocked security
events. `remove` takes a `history_list` of entries to drop.

## `/admin/camera_security` · `camera_security`

**get / set** — smart-camera protection. The `get` result aggregates the current
mode, the managed cameras, the clients that may reach them, and the live block
state:

| Field | Meaning |
|-------|---------|
| `status` | Current block state (`blocked` / `unblocked`). |
| `block.begin_sec` / `block.block_sec` | Start offset and duration of the active block window. |
| `internet_blocked` | Whether camera internet access is currently cut. |
| `home_mode` | Home-mode config: `mode`, `timing_block` (`enable`, `time_begin`, `time_end`, `custom_workday`), and schedule (`daily` / `workday` / `weekend`, `sched`). |
| `camera_list` | Managed cameras (`cam`), each with client info and traffic. |
| `trigger_client_list` | Detected trigger clients (`detect_dev`) allowed to reach the cameras. |
| `local_only_mode` | Local-only cameras (`local_only_cam`) — no cloud/internet. |
| `auto_block` | Auto-block toggle. |
| `home_mode_camera_max_count` / `local_only_mode_camera_max_count` / `trigger_client_max_count` | Capacity limits. |

Client info per camera / trigger device (`mac`, `name`, `client_type`) is
resolved through the client manager (see [clients.md](./clients.md)). `set`
rejects over-capacity requests with *"Camera up to limit for home mode"*,
*"… for local only mode"*, *"… for both mode"* or *"Trigger Client up to
limit"*.

## `/admin/camera_security` · `camera_security_blocked_period`

**get / set** — the scheduled camera-blocking periods, plus the block **history**
(bounded by `begin_sec` / `end_sec`). History entries carry a `status` of
`BLOCK`, `ALLOW` or `RESET` with `from`, `time_sec` and `end_time_offset`; the
response groups them under `blocked_period`.

---

## Notes

- Only the values in the Forms table are valid `?form=` targets.
- The two endpoints (`/admin/security` and `/admin/camera_security`) are
  independent; neither has a web-side counterpart.
- HomeShield security also has a **cloud** side: the security whitelist and
  service-state checks are reachable through
  [`/admin/smart_network` · `tmp_avira`](./parental-control-and-qos.md#tmp_avira--homeshield-cloud-bridge)
  (`get_sec_whitelist` / `add_sec_whitelist` / `remove_sec_whitelist`,
  `service_state_check`).
- HomeShield-family error codes (`-3401`, `-3403`, `-3404`, `-4101`…`-4105`,
  `-6101`, `-6102`) are surfaced by these features — see the
  [error-codes section](../protocol/transport-and-dispatch.md#known-error-codes).
