# Dynamic DNS

Endpoint: **`/admin/ddns`** (app). Uses the
[encrypted envelope](../protocol/transport-and-dispatch.md).

Related: [cloud-and-account.md](./cloud-and-account.md) (TP-Link cloud DDNS),
[network.md](./network.md) (WAN binding), [README.md](./README.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `ddns` | get, set | app | DDNS provider configuration + status. |

Providers (`provider` / `mode`):

| Provider | `provider` | `mode` | Backend |
|----------|-----------|--------|---------|
| TP-Link | `tp-link` | `tp_link` | TP-Link cloud. |
| No-IP | `no-ip` / `noip` | — | DDNS update daemon. |
| DynDNS | `dyndns` | `dynamic` | DDNS update daemon. |

---

## `ddns`

**get** → returns `ddns_info` for the configured provider:

| Field | Meaning |
|-------|---------|
| `ddns_enable` | Service on/off. |
| `provider` | See table above. |
| `mode` | `tp_link` for TP-Link. |
| `domain` / `domain_name` | Bound hostname. |
| `isBind` | `1`/`0` — bound state (from `ddns_status`, TP-Link). |
| `connection_status` | `success` / `connecting` / `fail`. |
| `username` | Account (No-IP / DynDNS). |
| `password` | Base64-encoded. |
| `update_interval` | Refresh interval in hours; `never`. |
| `update_time` | Last update; `never`. |
| `wan_bind` / `wan_binding` | `enable` / `disable`. |

For TP-Link, `get` fetches the bound domain list from the cloud →
`"fail to get binded domain"` on error.

**set** → params: `ddns_status` (enable flag), `domain_name`, `provider`/`mode`,
`username`, `password` (base64), `update_interval`, `wan_binding`.

```json
{
  "operation": "set",
  "params": {
    "ddns_status": 1,
    "mode": "tp_link",
    "domain_name": "myhome.tplinkdns.com"
  }
}
```

- TP-Link: bind / unbind / delete domains against the cloud →
  `"fail to bind domain"`, `"fail to close ddns service"`.
- No-IP / DynDNS: register with the provider →
  `"domain name has been occupied"`, `"domain name register failed"`;
  missing input → `"invalid parameters:no domain"`, `"invalid mode param!"`.

---

## Notes

- Credentials are stored/transported base64-encoded.
- `wan_binding` ties the DDNS update to a specific WAN interface.
