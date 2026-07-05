# Parental controls & QoS — HomeShield smart network

Endpoint: **`/admin/smart_network`** (app). All forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

These forms drive QoS (bandwidth ceilings + priority), HomeShield parental
controls ("owners"/profiles, website filtering, time limits, usage insights) and
per-app time limits. The `tmp_avira` form bridges the same operations to the
Avira-backed HomeShield **cloud** service.

Related: [clients.md](./clients.md) (clients & QoS priority per device),
[homeshield-security.md](./homeshield-security.md) (network & camera security).

---

## Forms

| Form | Operations | Purpose |
|------|-----------|---------|
| `tm_qos` | read, write | QoS mode. |
| `bandwidth` | get, set | WAN up/down bandwidth ceilings. |
| `patrol_owner` | list, add, del, get, set, block | Parental-control profiles ("owners"). |
| `patrol_cli` | add, del | Assign / unassign clients to an owner. |
| `patrol_filter` | add, del, get | Website / content filter for an owner + defaults. |
| `patrol_insights` | get, remove, history | Usage-time insights per owner. |
| `patrol_owner_avatar` | get, set | Owner profile avatar. |
| `white_list` | get, add, remove | Content-filter whitelist (always-allowed sites). |
| `app_block_list` | read | Catalogue of DPI-recognised blockable apps. |
| `app_dpi` | add, modify, remove | Per-owner app time-limit / block rules. |
| `time_limit_add` | write | Add an app time-limit rule. |
| `time_limit_modify` | write | Modify an app time-limit rule. |
| `time_limit_remove` | write | Remove an app time-limit rule. |
| `tmp_avira` | (many, see below) | Avira / HomeShield **cloud** bridge. |

> The dispatcher for these forms may answer under `data` instead of `result`,
> and echoes `success` / `errorcode` / `msg` alongside the standard
> `error_code`.

---

## `tm_qos` / `bandwidth` (QoS)

- `tm_qos` — **read** / **write** the QoS operating mode.
- `bandwidth` — **get** / **set** the up/down WAN bandwidth ceilings used by
  QoS. A per-client priority (see [`client`](./clients.md)) has no effect until
  a ceiling is set (*"bandwidth unset"*).

## `patrol_owner`

Parental-control profiles. `params` key: **`owner_id`** (and `owner_list` /
`owner_id_list` in responses).

| Operation | Purpose |
|-----------|---------|
| `list` | List all owners. |
| `add` | Create an owner. |
| `del` | Delete an owner. |
| `get` | Read one owner (`owner_id`). |
| `set` | Update owner base info. |
| `block` | Pause internet for an owner's devices. |

`patrol_owner_avatar` (**get** / **set**) manages each owner's avatar.

## `patrol_cli`

**add** / **del** — attach or detach client devices (by MAC) to an owner's
profile. Mirrors the `owner_id` shown on each client in
[`client_list`](./clients.md).

## `patrol_filter` / `white_list`

- `patrol_filter` — **add** / **del** website-filter entries for an owner.
  **get** exposes the defaults and the available filter levels
  (`filter_level_list`, keyed by `version`).
- `white_list` — **get** / **add** / **remove** the content-filter whitelist;
  `params.whitelist` carries the entries. (Distinct from the Wi-Fi
  access-control `white_list` in [clients.md](./clients.md).)

## `patrol_insights`

**get** (by `owner_id`) / **remove** / **history** — per-owner online-time
usage and history.

## App limits — `app_block_list`, `app_dpi`, `time_limit_*`

- `app_block_list` — **read** the catalogue of DPI-recognised apps that can be
  blocked / time-limited. Read `params`: `start_index`, `amount`, `version`,
  `need_up_to_date`; response includes `all_return`.
- `app_dpi` — **add** / **modify** / **remove** per-owner app time-limit rules.
  `params`: `owner_id`, `dpi_app_limit`, `dpi_app_limit_id_list`.
- `time_limit_add` / `time_limit_modify` / `time_limit_remove` — **write**
  single-purpose forms for the same app time-limit rules.

## `tmp_avira` — HomeShield cloud bridge

A single form whose `operation` selects one of the Avira/HomeShield **cloud**
calls. Operations seen:

`getOwnerInList`, `addOwnerInList`, `delOwnerInList`, `modifyBaseInfo`,
`bonusTimeSet`, `ownerClientListSet`, `white_list_add`, `white_list_remove`,
`getFamilyTimeInfo`, `setFamilyTimeInfo`, `getTodayInsightTimeUsagePro`,
`getInsightData`, `ignoreReq`, `scanStart`, `scanStop`, `scanGet`,
`networkQualityStartOptimize`, `ispGet`, `service_state_check`,
`service_status_check`, `cloud_service_state_check`, `get_sec_whitelist`,
`add_sec_whitelist`, `remove_sec_whitelist`.

These mirror the local parental-control / QoS / security operations against the
cloud when `is_avira_support` is true; the network-security whitelist operations
feed [homeshield-security.md](./homeshield-security.md).

---

## Notes

- Feature-specific error codes returned by these forms include `-3401`,
  `-3403`, `-3404`, `-4101`…`-4105`, `-6101`, `-6102`; error messages include
  *"Unable to add. Maximum number exceeded."*, *"Already added."*, *"Unable to
  add because lacking of free profile."*, *"The id's owner doesn't exist"* and
  *"Failed to set to cloud"*.
- `owner_id` is the join key between parental controls and a client — see
  [`client_list`](./clients.md) and [`patrol_cli`](#patrol_cli).
