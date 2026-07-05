# Static routing

Endpoints: **`/admin/route`** (web) and the app forms `routes_static` /
`routes_system` on **`/admin/network`** (app). Both use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

`/admin/route` is addressed without a `?form=` selector. The app exposes the
same route table through `/admin/network`; see [network.md](./network.md).

Related: [network.md](./network.md), [dhcp.md](./dhcp.md),
[README.md](./README.md).

---

## Forms

| Form / endpoint | Operations | By | Purpose |
|-----------------|-----------|-----|---------|
| `/admin/route` | read, insert, update, delete | web | Static IPv4 route table. |
| `/admin/network?form=routes_static` | getlist, add, modify, remove | app | Same route table via the app API. |
| `/admin/network?form=routes_system` | getlist | app | System (auto) routes, read-only. |

---

## `/admin/route` (web)

Each route entry has five fields, validated on `insert` / `update`:

| Field | Validation | Meaning |
|-------|-----------|---------|
| `target` | IPv4, may be absent | Destination network. |
| `netmask` | Netmask (loose) | Destination mask. |
| `gateway` | May be empty | Next hop. |
| `name` | Printable, length-limited | Route label. |
| `interface` | One of `wan`, `lan`, `internet` | Egress interface. |

Additional per-entry fields: `enable` (`1`/`0`), `key` (generated id), `mask`.

**read** — enumerate the static route table; the web side also surfaces the
system (auto) routes.

**insert**

```json
{
  "operation": "insert",
  "params": {
    "enable": 1,
    "name": "to-lab",
    "target": "10.0.0.0",
    "netmask": "255.255.255.0",
    "gateway": "192.168.68.2",
    "interface": "wan"
  }
}
```

**update** — same shape plus the entry `key`. **delete** — `{ "key": "<id>" }`.

Server-side checks on `insert` / `update` / `delete`:

- Count cap on the number of static routes →
  `"Unable to add. Maximum number exceeded"`.
- Duplicate detection →
  `"Duplicated route static entry"`.
- Overlap with WAN/LAN addressing →
  `"Target network is conflicting with Wan/Lan IP"`.

## `routes_static` / `routes_system` (app)

Served at `/admin/network`; these expose the same route table via the app API:

- `routes_static` — `getlist`, `add`, `modify`, `remove` on the static route
  table.
- `routes_system` — `getlist` for the auto/connected routes (read-only).

Field set matches the web endpoint above. See [network.md](./network.md#forms).

---

## Notes

- The gateway is optional for interface-scoped routes.
- Route changes are persisted on the device.
