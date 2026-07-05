# IPv6 firewall

Endpoint: **`/admin/ipv6_firewall`** (app-only). Uses the
[encrypted envelope](../protocol/transport-and-dispatch.md).

Related: [network.md](./network.md) (IPv6 WAN/LAN), [clients.md](./clients.md),
[README.md](./README.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `firewall` | read, write, remove, modify | app | Inbound IPv6 firewall rules (allow-list). |
| `client` | read | app | IPv6 clients / neighbor table. |

---

## `firewall`

| Operation | Purpose |
|-----------|---------|
| `read` | List rules + limit. |
| `write` | Add a rule. |
| `modify` | Edit a rule. |
| `remove` | Delete a rule. |

Requests/responses carry a `firewall_list` array; `read` also returns
`firewall_list_limit`.

Rule fields:

| Field | Meaning |
|-------|---------|
| `name` | Rule label. |
| `port` | Port (or range) opened. |
| `protocol` | Transport protocol. |

Over-limit on add → `"rule num exceeds max num limit"`.

## `client`

**read** — refreshes the IPv6 neighbor table, then returns `client_list`:

| Field | Meaning |
|-------|---------|
| `name` | Client name, base64. |
| `mac` | MAC (upper-case). |
| `ip` | IPv6 address. |
| `client_type` | Category (`other`, `UNKNOWN`, …). |

---

## Notes

- Rule changes take effect after the IPv6 firewall service reloads.
- Link-local (`fe80`) neighbors are filtered out of the client list; entries
  are pinged to populate the table.
- Changing the IPv6 WAN/LAN protocol (see [network.md](./network.md)) flushes
  these rules.
