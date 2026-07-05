# Other services

Small, single-purpose endpoints that don't fit the larger feature pages:
TR-069 (CWMP), combo WAN/LAN port, the app component/feature list, Google
Assistant device info, the opcode subconfig proxy, captive-portal blocking &
customization, the connectivity indicator, and RE-node cloud disconnect.

All forms use the [encrypted envelope](../protocol/transport-and-dispatch.md).
Related: [system.md](./system.md), [network.md](./network.md),
[README.md](./README.md).

---

## `/admin/cwmp` — TR-069 / CWMP

Endpoint: **`/admin/cwmp`** (app-only).

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `cwmp` | get, set | app | ACS (auto-config server) connection. |

**get** → `{ enable, server_url }`. **set** → `params` `{ enable, server_url }`.
`enable` toggles the TR-069 client; `server_url` is the ACS URL.

## `/admin/combo_port` — combo WAN/LAN port

Endpoint: **`/admin/combo_port`** (app-only).

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `list` | read | app | List combo-port roles (self + other nodes). |
| `switch` | set | app | Change a port's WAN/LAN role. |

**list · read** → `combo_port_list` (each node's `self_combo_port_list`); can
query another node via an `opcode` + `target_type` `sync` request. **switch ·
set** → `params` `{ device_id, efficient_port }`; updates the local node then
forwards to the target node via an `opcode` + `target_id` `sync` request.

## `/admin/component_list` — app feature list

Endpoint: **`/admin/component_list`** (app-only).

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `mobile` | read | app | Feature/component list for the mobile app. |
| `bluetooth` | read | app | Component list for BT onboarding. |
| `profile` | read | app | Component profile. |

**mobile · read** returns a `component_list` of supported-feature flags, e.g.
`quick_setup`, `ver_code`, `vlan`, `pptp`, `l2tp`, `dslite`, `mac_clone`,
`mobile_cpe`, `pin`, `qs_isp`, `location_custom`, `speed_test`, `eco_mode`,
`wifi_schedule`, `matter`, filtered by model / hardware / country / operation
mode. **bluetooth · read** adds onboarding-time flags (`wireless_spec`,
`pppoe_service`, `fap_iptv_port`, `v6_plus`, `wireless_mlo`,
`quick_setup_ap_mode`, `wireless_band_6g`, …) keyed on the Bluetooth
onboarding `operation_mode`.

## `/admin/ga_info` — Google Assistant / device info

Endpoint: **`/admin/ga_info`** (app-only). Form `status`.

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `status` | read, write, get, get_internal | app | Device identity + Ethernet-port usage. |

- **get** → `device_id`.
- **read** → `ga_info_list`: per-node Ethernet-port usage (`port_usage` /
  `port_usage_for_deco_network`), link status, `parent_mac`,
  `second_parent_mac` and neighbor count, gathered across the mesh via an
  `opcode` + `sync` request.
- **get_internal** → internal port-usage info for one node.
- **write** → set `hw_ver`, only outside factory mode.

## `/admin/op_manager` — opcode subconfig proxy

Endpoint: **`/admin/op_manager`** (web). **Advanced / internal.**

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `read` | get, list, getlist | web | Inspect / forward opcode-scoped subconfig. |

Maps an `opcode` (e.g. `0xc401`, `0x4040`, `0x40e0`, …) to a set of config
files, then diffs them to detect user-config changes and, when needed, reloads
the affected config. A request can be relayed to mesh RE nodes (`opcode` +
`target_id`, `sync request`) and the results merged. `params` carry
`{ opcode, dev_id, config_version, change, data }`.

## `/blocking` — captive/portal blocking + version code

Endpoint: **`/blocking`** (web). Ties into HomeShield / Avira.

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `check` | get, set | web | Token-checked block/unblock of a client. |
| `vercode` | read, write | web | Verification code for blocking actions. |

- **check** — `params` `{ mac, token, time }` (and `owner_id` / `real_mac` /
  `website` for URL blocking); the one-time token is validated
  (`mac unmatched` / `token time out` / `token unmatched`) before the block is
  applied.
- **vercode · read** — validate the current code (time-out enforced). **write**
  — generate a fresh random code.

## `/admin/wifidog` — captive-portal customization

Endpoint: **`/admin/wifidog`** (web).

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `portal_content` | read, upload | web | Read / set the captive-portal page. |

**read** → `login_page`: `logo` (custom image, base64 PNG), `title`, `button`
(`bg_color`, `text`), `background` (color / image), `terms` / `pop_contents`,
plus `authentication` (`encryption_type`, `password`, `time_limit`),
`redirect_url` and MD5s. **upload** writes the portal config and stores the
logo/background images (`portal_logo`, `portal_back`), rejecting oversized
images. Images are synced to the other nodes.

## `/admin/conn-indicator` — connectivity indicator

Endpoint: **`/admin/conn-indicator`** (web). Form `internet`.

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `internet` | down, sync | web | Drive the connectivity-status indicator. |

**down** — mark internet down. **sync** — re-evaluate connectivity. Returns a
connection error if the indicator daemon is unreachable.

## `/admin/re_disconnect_cloud` — RE cloud disconnect

Endpoint: **`/admin/re_disconnect_cloud`** (web). Form `notify`.

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `notify` | write | web | Tell a RE node to drop its cloud connection. |

**write** — updates the node's cloud device status (`need_wait`) and restarts
the cloud bridge. Used during mesh re-role / offboarding so a former RE stops
talking to the TP-Link cloud.

---

## Notes

- `op_manager`, `arptbl`-style syncs, `combo_port` cross-node queries and
  `re_disconnect_cloud` are mesh-internal; they forward to RE nodes over the
  `sync` / `opcode` transport rather than acting only on the gateway.
- `wifidog` + `blocking` together back the captive-portal / guest-access flow:
  `wifidog` owns the portal page, `blocking` owns the token/verification gate.
- `cwmp` and `ga_info` are ecosystem integrations (ISP TR-069 provisioning and
  Google Assistant, respectively) and are only meaningful on models/regions
  that ship them.
