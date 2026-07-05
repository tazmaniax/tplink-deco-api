# Onboarding & provisioning — group creation, TIPC, discovery, mesh sync

Endpoints: **`/admin/quick_setup`**, **`/admin/tipc-controller`**,
**`/discover`**, **`/admin/sync`**. `/admin/quick_setup` and
`/admin/tipc-controller` use the
[encrypted envelope](../protocol/transport-and-dispatch.md); `/discover` is a
group-key-protected probe and `/admin/sync` is `TOKEN`-authenticated
node-to-node traffic (see Notes).

This is the first-run flow: create the mesh group on the master, add satellite
nodes, assign TIPC cluster addresses, discover neighbours, and keep config &
firmware in sync across the mesh. Related:
[`cloud-and-account.md`](./cloud-and-account.md) (group creation writes the
cloud account), [`firmware-and-upgrade.md`](./firmware-and-upgrade.md),
[`network.md`](./network.md) / [`device.md`](./device.md) (the WAN / Wi-Fi / time
settings that `newgroup` applies), [`login.md`](./login.md) (`mini_login`,
`check_factory_default`).

---

## `/admin/quick_setup`

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `newgroup` | write | app | Create the mesh group on the master (WAN + Wi-Fi + time + cloud). |
| `newdevice` | write | app | Add one satellite node to the group. |
| `batchdevices` | write | app | Add several nodes in one call. |
| `preconf` | read, write, add | app | Pre-configuration profile staged before nodes join. |
| `heartbeat` | (read) | app | Onboarding progress heartbeat. |
| `sync` | (write) | app | Trigger a mesh sync during setup. |
| `eponymous_detect` | (read) | app | Detect an existing same-SSID network. |
| `bluetooth` | write | app | Toggle BLE onboarding mode; seed the BLE/Zigbee mesh. |
| `dcmp_pre_config` | write | app | DCMP (carrier / co-managed) pre-configuration. |
| `tss` | write | app | TSS device-list snapshot for the app. |
| `sync_dev_list` / `get_dev_list` | write / read | app | Sync / fetch the TSS device list. |

### `newgroup`

The core "create your Deco network" call. In one request the master:

- sets the WAN (`network?form=wan_ipv4` write, plus VLAN, MAC-clone, IPTV) from
  `params.wan`;
- sets Wi-Fi (AP / backhaul / MLO, optional 6 GHz) from `params.wireless`;
- sets the clock (`device?form=timesetting`) from `params.date_time`;
- creates the cloud group (`cloud?form=group operation=create`) from
  `params.cloud_account` — see
  [`cloud-and-account.md`](./cloud-and-account.md);
- generates the group key, joins the group and registers itself, then writes
  the TIPC config.

`params` (decrypted) carries `wan`, `wireless` (`ssid`, `password`,
`encryption`), `cloud_account` (`username`, base64 `password`), `date_time`
(`timezone`, `tz_region`) and `nickname`; credentials are `tmp_decrypt`-decoded.

### `newdevice` / `batchdevices`

Add satellite node(s) to an existing group. `newdevice` joins one node to the
group (checks `sync_version` / `product_level`, then binds it); `batchdevices`
adds several over a `device_list` of `{ device_id, mac, … }`, binding each over
the sync channel. `params` carries `group_id`, `group_key`,
`master_device_id`, `front_wireless`, `cloud_account`.

### `preconf`

Pre-configuration: stage a group/Wi-Fi/WAN profile so nodes self-configure when
they appear. `read` returns the staged profile; `write` stores it; `add`
attaches a specific node (`preconfig_device_list`). `dcmp_pre_config` is the
carrier-driven variant that also sets the WAN dial (`pppoe` / `l2tp` / `pptp` /
`dynamic_ip`).

### `tss` / `get_dev_list` / `sync_dev_list`

"TSS" node/device-list surface used by the app during setup: `tss` returns the
bound + discoverable node list (`tss_bind_device_list`, `sync_boost`);
`get_dev_list` / `sync_dev_list` fetch / sync it over the internal `tss`
channel.

---

## `/admin/tipc-controller`

| Form | Operations | Purpose |
|------|-----------|---------|
| `newdevice` | write | Allocate the next TIPC address for a joining node. |
| `sync` | write | Apply / sync the TIPC config. |

TIPC (Transparent Inter-Process Communication) is the mesh's internal cluster
bus. `newdevice` hands a joining node its `cluster` / `zone` / `node` address;
`sync` applies a supplied config. `params` requires `device_id`.

---

## `/discover`

| Form | Operations | Purpose |
|------|-----------|---------|
| `_discover` | read | Device discovery / probe (identity, model, channels). |
| `sync_config` / `sync_config_emmc` | read | RE-side config-version check on discovery. |
| `sync_slave_check` | read | Slave-side onboarding / pre-config check. |
| `sync_master_check` | read | Master-side onboarding check + pull RE in. |

**`_discover`** returns the node's probe record:

| Field | Meaning |
|-------|---------|
| `mac` | Node MAC (uppercased). |
| `device_id` | Node device id. |
| `device_model` | Model string. |
| `firmware_ver` | Running firmware version. |
| `channel_2g` / `channel_5g` / `channel_5g_2` / `channel_6g` | Current radio channels. |
| `hardware_version`, `role`, `group_id` / `group_name` | Identity + mesh role/group. |

The probe payload is protected by the group secret (keyed by the group key), so
only same-group nodes (and the app holding the key) can decode it.
`sync_master_check` / `sync_slave_check` drive pre-config onboarding.

---

## `/admin/sync` — mesh config & firmware sync

Node-to-node surface that keeps configuration and firmware consistent across the
mesh. Handlers are internal and `TOKEN`-gated; request shapes are
node-generated, so only the purpose is documented here.

| Form | Purpose |
|------|---------|
| `sync_check` / `sync_config` | Compare & pull the latest user-config version. |
| `sync_emmc_check` / `sync_emmc_config` | Same for the eMMC-stored config. |
| `sync_get_info` / `sync_get_cfg` | Export a node's component list / config to a peer. |
| `sync_subconfig` / `sync_update_dev_list` | Per-opcode sub-config merge + device-list refresh. |
| `sync_detect_slave` | Probe slave nodes. |
| `check_firmware` / `sync_firmware` / `sync_upgrade` / `force_upgrade` | Distribute & flash firmware across nodes. |
| `sync_download_bigfirm` / `sync_download_status_bigfirm` | Download a large firmware image + progress. |
| `sync_download_lte` / `sync_download_status_lte` / `force_upgrade_lte` | LTE-modem firmware download / flash. |
| `sync_isp_profile` | Distribute the ISP profile. |
| `sync_re_handle_fap_fdb` | RE FDB / loopback-port handling. |

---

## Notes

- `/admin/quick_setup` is the app's onboarding endpoint; a fresh unit is
  reached via [`login.md`](./login.md) `mini_login` / `check_factory_default`
  before `newgroup` runs.
- `newgroup` composes other endpoints' write forms (`network`, `wireless`,
  `device timesetting`, `cloud group`) into one transaction — those forms are
  documented on their own pages.
- `/discover` and `/admin/sync` are primarily **node-to-node** (mesh) traffic;
  they are documented for completeness but are not part of the app/SDK's normal
  request surface. `/admin/sync` auth is an internal `TOKEN` env var, not the
  `stok` session.
- TIPC addresses assigned by `/admin/tipc-controller` back the sync bus used by
  `/admin/sync` and `/discover`.
