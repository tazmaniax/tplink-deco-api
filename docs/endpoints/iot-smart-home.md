# IoT & smart home

Endpoints (all app-only): **`/admin/iot_device`**, **`/admin/iot_automation`**,
**`/admin/iot_cloud`**, **`/admin/iot_client_mesh`**, **`/admin/msg_server`**.
All forms use the [encrypted envelope](../protocol/transport-and-dispatch.md).

This is the Deco smart-home surface: paired IoT devices (Hue, Zigbee, Matter,
TP-RA, Tapo, BLE), spaces/owners, automations (tasks, triggers, one-click
scenes) and the cloud/mesh bridges. Network Wi-Fi clients are covered in
[clients.md](./clients.md); this page is only the IoT sub-system.

Related: [README.md](./README.md),
[transport-and-dispatch.md](../protocol/transport-and-dispatch.md),
[wps.md](./wps.md), [vpn.md](./vpn.md).

---

## Endpoints & forms

Every form is app-only (`By` = app).

| Endpoint | Form | Operations | Purpose |
|----------|------|-----------|---------|
| `/admin/iot_device` | `iotdevice` | getlist, add, modify, remove, scan, begin_scan, end_scan, identify, getlist_by_mod, account_sync, `inner_*` | Paired IoT device inventory + pairing/scan lifecycle. |
| `/admin/iot_device` | `iotprofile` | get_and_update_pwd | Fetch / refresh the Tapo·TP-RA cloud-account password used to log in to those devices. |
| `/admin/iot_device` | `iotspace` | set, set_network_device, remove_network_device | Assign devices (IoT + network clients) to a room / space. |
| `/admin/iot_device` | `iotowner` | getlist, testcmd, inner_report_sensor, inner_network, form_network, remove_all | Owner/member list + Zigbee-coordinator network management (some ops internal). |
| `/admin/iot_device` | `iotrole` | get_init_info, get_avail_node_id, commission_complete, check_node_status, get_pairing_code, inner_update_config | Matter commissioner role (fabric init, node-id allocation, pairing codes). |
| `/admin/iot_automation` | `iotautomation` | get_tasklist, add_task, modify_task, modify_task_list, remove_tasklist, add_trigger, modify_trigger, remove_triggerlist | Scheduled/conditional automation rules (tasks + triggers). |
| `/admin/iot_automation` | `iotoneclick` | getlist, set, add_scene, modify_scene, remove_scene, add_action, modify_action, remove_actionlist, get_history, remove_history | One-click "shortcut" scenes + execution history. |
| `/admin/iot_cloud` | `iot_cloud_req` | index | Bridge to Alexa / IFTTT cloud apps. |
| `/admin/iot_client_mesh` | `client_mesh` | set, tss, sync_device_msg, sync_cloud_msg | Matter / mesh client sync + block/unblock. |
| `/admin/msg_server` | `coordinator`, `notify` | (event handlers) | Message-center notifications (coordinator reset, automation alerts). |

---

## `/admin/iot_device` · `iotdevice`

The central device registry. Each entry is normalised across protocols
(`hue`, `zigbee`, `matter`, `tpra`, `tapo`, `ble`) into a common shape.

**getlist** → `{ "operation": "getlist", "params": {} }`

Result carries `iot_client_list` plus `scan_status` and
`iot_count_per_cate_max`. Common device fields:

| Field | Meaning |
|-------|---------|
| `iot_client_id` | Stable per-device id (protocol-prefixed, e.g. `tpra_…`, `tapo_…`). |
| `module` | Protocol: `hue`, `zigbee`, `matter`, `tpra`, `tapo`, `ble`. |
| `brand`, `type_name`, `model`, `name` | Vendor / product identity + user label. |
| `category`, `subcategory` | Device class (`light`, `switch`, `thermostat`, `sensor`, `lock`, `occupancyTag`, …). |
| `inet_status` | `online` / `offline`. |
| `bind_status` | `new` / `binded` / `skipped`. |
| `space_id`, `owner_id` | Room and owner assignment. |
| `avatar`, `badge_number` | UI icon + counter. |
| `trigger_type` / `supportTriggers` | Automation triggers the device can raise. |
| `fixed` / `detail` | Typed attribute blocks (see value types below). |

Attribute values are typed: `INT`, `DOUBLE`, `STRING`, `BOOL`, `BASE64`,
`ARRAY`, `FIXED` (enum mapped through `valMap`), `DETAIL` (nested/encoded).

**Lifecycle operations**

| Operation | Effect |
|-----------|--------|
| `add` / `remove` | Link / unlink a device with the IoT center. |
| `modify` | Update attributes (name, isolation, link priority, band, …). |
| `scan` / `begin_scan` / `end_scan` | Poll / start / stop discovery. |
| `identify` | Blink a bulb/bridge to locate it. |
| `getlist_by_mod` | List filtered by protocol module(s). |
| `account_sync` | Push cloud-account credentials to Tapo devices (TSS). |

**`inner_*` operations** — internal mesh/bridge plumbing, not app-facing:
`inner_getlist`, `inner_remove`, `inner_modify`, `inner_scan`,
`inner_begin_scan`, `inner_inquiry`, `inner_begin_assoc`, `inner_get`,
`inner_act`, `inner_act_qr`, `inner_upnp_get`, `inner_dhcpd_get`,
`inner_file_pull`, `inner_file_push`, `inner_client_mgmt`,
`inner_client_netdev_req`. They proxy requests between mesh nodes (the RE/FAP)
and the IoT center and are dispatched node-to-node rather than from the app.

## `/admin/iot_device` · `iotspace` / `iotowner` / `iotrole`

- **`iotspace`** — `set` assigns IoT devices to a space; `set_network_device`
  / `remove_network_device` do the same for regular Wi-Fi clients (mapped into
  `client_list`). Space records carry `space_id`, `name`, `avatar`,
  `is_default`, and an optional `monitor` device.
- **`iotowner`** — `getlist` returns `owner_list` (`owner_id`, `name`,
  `blocked`, `internet_blocked`, `avatar`). The remaining operations
  (`form_network`, `remove_all`, `inner_network`, `inner_report_sensor`,
  `testcmd`) drive the **Zigbee coordinator** (form the network, wipe all
  paired devices, sensor reporting) and are internal.
- **`iotrole`** — Matter commissioner support: `get_init_info` (returns
  `deco_node_id`, `app_node_id`, `fabric_id`), `get_avail_node_id`,
  `commission_complete`, `check_node_status`, `get_pairing_code`
  (open a commissioning window and return a setup code), `inner_update_config`.

## `/admin/iot_automation` · `iotautomation`

Automation **tasks** with a time window and a set of **triggers** + **actions**.

**get_tasklist** → returns `task_list` with `task_count_max`,
`trigger_count_max`, `action_count_max`. Each task:

| Field | Meaning |
|-------|---------|
| `task_id`, `task_name` | Rule id + label. |
| `task_mode` (`timeMode`) | `normal` / `all_day`. |
| `from_time` / `to_time`, `repeat_time` | Active window + weekly repeat. |
| `is_enable` | Enabled flag. |
| `trigger_list`, `action_list` | Conditions and effects. |
| `logic_type` | `and` / condition combiner. |

Triggers are keyed by device `category` and expose per-category fields, e.g.
`thermostat` (`away_home_mode`, `amb_temp_*`, `humidity_*`), `light`
(`is_on`/`onoff`), `switch`, `network_device` (`connected`), `security`,
`sensor` (`co_smoke`, `alarm`, `presence`, `open`, `fire`, `water`, `smoke`),
`lock` (`lock_status`), `occupancyTag` (`is_arrival`/`ocpyTagStatus`). Actions
carry `hvac_mode`, `tgt_temp*`, `diming_degree`/`bri`, `color`/`rgb`,
`saturation`, `power_level`, plus `duration`/`delay` switches. The full
per-category schema is large and not enumerated exhaustively here.

Operations: `add_task`, `modify_task`, `modify_task_list`, `remove_tasklist`,
`add_trigger`, `modify_trigger`, `remove_triggerlist`.

## `/admin/iot_automation` · `iotoneclick`

One-click **scenes** (a named list of actions run on demand) and their history.

- `getlist` → `scene_list` (`scene_id`, `scene_name`, `scene_type`, `avatar`,
  `action_list`) with `scene_count_max`, `alexa_scene_count_max`,
  `action_count_max`.
- `set` — execute a scene (`click`); returns `is_success` + per-device
  `error_list`.
- `add_scene` / `modify_scene` / `remove_scene` — manage scenes.
- `add_action` / `modify_action` / `remove_actionlist` — manage a scene's
  actions.
- `get_history` / `remove_history` — execution log.

## `/admin/iot_cloud` · `iot_cloud_req`

**index** — dispatches by `params.type`: `alexa` or `ifttt`, forwarding
`params.data` to the matching cloud app. Thin bridge; the payload shape is
defined by the cloud app, not the endpoint.

## `/admin/iot_client_mesh` · `client_mesh`

Matter / mesh client synchronisation across nodes.

| Operation | Effect |
|-----------|--------|
| `set` | Block / unblock a matter client on the mesh. |
| `tss` | TSS (thumbprint) related sync. |
| `sync_device_msg` | AP uploads its provisionee list to the coordinator. |
| `sync_cloud_msg` | RE pulls / decodes cloud provisioning messages. |

Blocking here mirrors [`/admin/nrd`](./clients.md) but is keyed by Matter node.

## `/admin/msg_server` · `coordinator` / `notify`

Message-center push handlers:

- `coordinator` — signals that the Zigbee coordinator was reset.
- `notify` — automation loop alerts and trigger notifications. Params carry
  `device_id` and a base64/json `nickname` / payload.

These are inbound notification sinks rather than app query endpoints.

---

## Notes

- Protocols are addressed by `module`: `hue`, `zigbee`, `matter`, `tpra`,
  `tapo`, `ble`. Per-protocol models normalise device attributes into the
  common `iot_client_id` / `fixed` / `detail` shape.
- Most device operations forward to an out-of-process "IoT center" and return
  its result under `result` / `data`; failures surface `iotErrCode` values
  (e.g. `IOT_ERR_COORDINATOR_FAILED`).
- Automation, one-click scene, task and history writes are persisted on the
  device.
