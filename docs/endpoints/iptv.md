# IPTV

Endpoint: **`/admin/iptv`** (app-only). Uses the
[encrypted envelope](../protocol/transport-and-dispatch.md).

Related: [network.md](./network.md) (WAN `vlan` form also carries IPTV VLAN
fields), [README.md](./README.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `iptv` | get, set | app | IPTV / ISP VLAN profile for set-top boxes. |

---

## `iptv`

**get** — reads the current IPTV profile:

| Field | Meaning |
|-------|---------|
| `enable` | IPTV enabled. |
| `mode` | ISP profile / mode. |
| `type` | `normal` or `bridge`. |
| `vlan_id` | IPTV VLAN id. |
| `vlan_priority` | 802.1p priority. |
| `isp_name` | ISP profile name. |
| `port_mode` | Uplink mode (`WAN`). |
| `uplink_port` / `uplink_device` | Uplink port. |
| `port` / `ports` | LAN ports assigned to IPTV/bridge (multi-port). |
| `device_id` | Device identifier. |

**set** — missing `enable` → `"invalid args"`.

```json
{
  "operation": "set",
  "params": {
    "enable": 1,
    "mode": "custom",
    "type": "normal",
    "vlan_id": 100,
    "vlan_priority": 4,
    "isp_name": "",
    "tag_802_1q": 1
  }
}
```

Params `enable`, `mode`, `vlan_id`, `vlan_priority`, `type`, `bridge`,
`isp_name`, `priority`, `tag_802_1q` configure the VLAN; on multi-port hardware
the per-port assignments (`port`, `port_mode`, `uplink_port`, `device_id`) are
applied as well.

---

## Notes

- Port mapping between hardware ports and app indices is handled internally;
  multi-port IPTV and fixed-WAN-port behaviour depend on the hardware model.
- The WAN [`vlan`](./network.md#vlan) form on `/admin/network` also exposes IPTV
  VLAN fields (`iptv_enable`, `iptv_mode`, `iptv_id`, `iptv_priority`,
  `iptv_port`); an IPTV VLAN id cannot collide with the WAN VLAN id.
