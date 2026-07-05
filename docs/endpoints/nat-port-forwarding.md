# NAT, port forwarding & ALG

Endpoint: **`/admin/nat`** (app-only). All forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

Related: [network.md](./network.md) (UPnP port mappings), [vpn.md](./vpn.md)
(external-port conflict check), [README.md](./README.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `setting` | read, write | app | Global NAT: software/hardware NAT + NAT boost. |
| `vs` | getlist, add, modify, batch_remove, remove | app | Virtual servers (port-forwarding rules). |
| `pt` | load, insert, update | app | Port-triggering rules. |
| `dmz` | read, write | app | DMZ host. |
| `alg` | get, write | app | Per-protocol ALG toggles. |
| `sip_alg` | get, set | app | SIP-ALG on/off shortcut. |

---

## `setting`

**read / write** — global NAT engine flags.

| Field | Meaning |
|-------|---------|
| `enable` | NAT enabled. |
| `hw_enable` | Hardware NAT / offload. |
| `boost_enable` | NAT boost. |

Invalid input → `"Invalid form value"`.

## `vs` — virtual servers (port forwarding)

**getlist** enumerates rules; **add** / **modify** / **remove** operate on one
rule; **batch_remove** takes a list of ids (`port_forwarding_id`).

| Field | Meaning |
|-------|---------|
| `enable` | Rule enabled. |
| `service_name` / `name` | Label, base64, ≤ 32 chars. |
| `service_type` | `dns`, `ftp`, `gopher`, `http`, `nntp`, `pop3`, `pptp`, `smtp`, `sock`, `telnet`, `custom`. |
| `protocol` | `tcp`, `udp`, `all`. |
| `external_port` | Port or range (`portrange`). |
| `internal_port` | Port or range. |
| `internal_ip` | LAN target (`ip4addr`). |
| `external_ip` / `external_subnet` | Source restriction (DCMP models). |

Limits & checks: max 64 rules →
`"The maximum number of port forwarding is 64."`; a VPN clash →
`"The External Port has been used by VPN."`; `"Invalid Service Type."`,
`"Invalid Internal IP."`, `"Invalid External Port."`.

## `pt` — port triggering

**load** returns options; **insert** / **update** write a rule.

| Field | Meaning |
|-------|---------|
| `enable` | Rule enabled. |
| `name` | Label. |
| `trigger_port` | Outbound trigger port/range. |
| `trigger_protocol` | Trigger protocol. |
| `external_port` | Incoming (opened) port/range. |
| `external_protocol` | Incoming protocol. |

Invalid input → `"invalid protocol."`, `"invalid external port."`. (No explicit
`remove` operation is exposed; disable via `update`.)

## `dmz`

**read / write** — single DMZ host.

```json
{ "operation": "write", "params": { "enable": 1, "ipaddr": "192.168.68.100" } }
```

Bad address → `"Invalid ipv4 address"`.

## `alg` / `sip_alg`

**`alg` get / write** — independent ALG toggles: `ftp`, `tftp`, `h323`, `rtsp`,
`sip`, `pptp`, `l2tp`, `ipsec`.

**`sip_alg` get / set** — convenience view of the SIP ALG bit only (a `set`
preserves the other `alg` toggles). `get` reports `"sip_alg is on"` /
`"sip_alg is off"`.

---

## Notes

- `alg.sip` and the `sip_alg` form are two views of the same firewall bit.
- UPnP-created port mappings are read via
  [`/admin/network?form=upnp`](./network.md), not through `nat`.
