# DHCP server

Endpoint: **`/admin/dhcp`** (app). All forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

Related: [network.md](./network.md) (LAN IP, WAN DHCP dial),
[clients.md](./clients.md) (address reservations), [README.md](./README.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `dhcp_info` | read, write | app | LAN DHCP server address pool + DNS handed to clients. |
| `dhcp_dial` | set | app | WAN DHCP-client unicast toggle. |
| `dhcp_ap` | get, set | app | AP-mode SmartIP DHCP. |

---

## `dhcp_info`

**read** → `{ "operation": "read" }`

Result (app keys are camelCase):

| Field (wire) | Meaning |
|--------------|---------|
| `startIpAddress` | Pool start address. |
| `endIpAddress` | Pool end address. |
| `defaultGateway` | Gateway handed to clients. |
| `primaryDns` | Primary DNS. |
| `secondaryDns` | Secondary DNS. |
| `ip_amount_in_use` | Active leases. |

**write** — same fields. Validated against the current LAN IP:

- Start/end required → `"Start ip or end ip cannot be blank."`
- Format → `"Start IP is invalid."`, `"End IP is invalid."`
- Same subnet as LAN →
  `"Start ip or end ip should be in the same subnet with LAN IP."`
- Ordering / size → `"Start ip should larger than end ip."`,
  `"IP pool size should be larger than 20."`
- DNS format → `"Primary DNS server format is not right."` /
  `"secondary DNS server format is not right."`

## `dhcp_dial`

**set** — toggles the WAN DHCP client between unicast and broadcast discovery.

```json
{ "operation": "set", "params": { "enable_unicast": true } }
```

(The WAN-side DHCP *dial* is also reachable via
[`/admin/network?form=dhcp_dial`](./network.md).)

## `dhcp_ap`

**get / set** — SmartIP DHCP used when the node runs in AP / bridge mode.

```json
{ "operation": "set", "params": { "enable": 1 } }
```

`get` returns `{ "enable": 0|1 }`.

---

## Notes

- The DHCP **reservation** (static-lease) list is *not* here — it lives at
  [`/admin/client?form=addr_reservation`](./clients.md).
