# VPN — client, server & connections

Endpoints (all app): **`/admin/vpn_client`**, **`/admin/vpn_server`**,
**`/admin/vpnconn`**. All forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

`/admin/vpn_client` dials outbound tunnels, `/admin/vpn_server` hosts inbound
ones, and `/admin/vpnconn` reports/controls live connections. Shared VPN types
across all three: `pptpvpn`, `l2tpvpn`, `openvpn`, `wireguardvpn`.

Related: [README.md](./README.md), [network.md](./network.md),
[transport-and-dispatch.md](../protocol/transport-and-dispatch.md).

---

## Forms

| Endpoint | Form | Operations | By | Purpose |
|----------|------|-----------|-----|---------|
| `/admin/vpn_client` | `config` | read, write, load, insert, update, remove | app | Outbound VPN-client profiles + protocol selection. |
| `/admin/vpn_server` | `server` | read, insert, remove, update | app | Inbound VPN-server instances. |
| `/admin/vpn_server` | `accounts` | insert, remove, update | app | Server user accounts (PPTP/L2TP). |
| `/admin/vpn_server` | `cert` | set, get | app | Server certificate material. |
| `/admin/vpn_server` | `key` | renews, renewc, gets, getc | app | Renew/fetch server (`s`) and per-client (`c`) keys/configs. |
| `/admin/vpnconn` | `conn` | list, disconnect | app | Live VPN-client connection status + teardown. |
| `/admin/vpnconn` | `cert` | sync | app | Sync OpenVPN certs between mesh nodes. |

---

## `/admin/vpn_client` · `config`

One active client tunnel selected by `proto`. `write` sets the protocol and its
fields; `insert`/`update`/`remove` manage stored profiles; `load` returns
capability data (`is_vpn_client_support`, `vpn_client_support_list`,
`max_servers`).

**Common fields:** `name`, `proto`, `conn_mode` (`auto` / `demand` /
`manually`), `mtu`.

**wireguardvpn**

| Field | Meaning |
|-------|---------|
| `address` | Local tunnel address. |
| `private_key` / `public_key` | Local key / peer key. |
| `listen_port` | Local WireGuard port. |
| `endpoint_address` / `endpoint_port` | Peer endpoint. |
| `allowed_ips` | Routed subnets. |
| `preshared_key` | Optional PSK. |
| `persistent_keepalive` | Keepalive interval. |
| `wg_dns` / `wg_dns_bk` | DNS + backup DNS. |
| `nat`, `mtu` | NAT toggle, MTU. |

**pptpvpn / l2tpvpn**

| Field | Meaning |
|-------|---------|
| `server` | VPN server host. |
| `username` / `password` | Credentials. |
| `encryption` | PPTP MPPE encryption (`pptpvpn`). |
| `psk` | IPsec pre-shared key (`l2tpvpn`). |

**openvpn** — `filename`: the uploaded `.ovpn` profile; the config's
certificate is validated by MD5.

A `write` applies the protocol and reports `conn_state` (`connecting` /
`disconnecting`). Reads expose `status`, `vpntype`, and the tunnel DNS.

## `/admin/vpn_server` · `server`

`read` returns `server_list` / `server_config` (with per-type caps such as
`client_max_count` / `account_max_count`). `insert` / `update` / `remove`
require `type` (one of the four `vpntype`s) and a `name`.

**wireguardvpn** server fields: `address`, `private_key`, `public_key`,
`allow_ips` (`allowed_ips`), `endpoint_address`, `endpoint_port`,
`persistent_keep_alive` (`persistent_keepalive`), `nat_enable` (`nat`),
`dns1`/`dns2` (`wg_dns`/`wg_dns_bk`), `mtu_size` (`mtu`), `preshared_key`.

**pptpvpn / l2tpvpn** server fields: `username`, `password`, `server`, `enable`,
`encryption` (PPTP), `psk` + `ipsec` (L2TP), `status`.

**openvpn** server uses an uploaded cert file; `cert_ver` tracks the stored
certificate version.

## `/admin/vpn_server` · `accounts` / `cert` / `key`

- **`accounts`** (`insert` / `remove` / `update`) — manage `account_list`
  entries (`username`, `password`) for PPTP/L2TP servers.
- **`cert`** (`set` / `get`) — set or fetch server certificate material for the
  selected `vpntype`.
- **`key`** (`renews` / `renewc` / `gets` / `getc`) — renew or fetch the
  **s**erver-side and per-**c**lient keys/configs (`renewc`/`getc` take an
  `account_id`). Used for OpenVPN/WireGuard credential provisioning.

All four are keyed by `params.type`; an unsupported type returns `Unsupported
VPN type`.

## `/admin/vpnconn` · `conn` / `cert`

- **`conn` · list** → active client connections grouped by type
  (`openvpn` under `vpn_clients`, plus `pptpvpn` / `l2tpvpn` /
  `wireguardvpn`). Each entry carries a `connid` / `conn_id`.
- **`conn` · disconnect** → tear down one connection, keyed by `type` +
  `connid`; returns "Can't find current VPN client connection" if unknown.
- **`cert` · sync** → propagate OpenVPN certificates between mesh nodes.
  Internal mesh operation.

---

## Notes

- The three endpoints share the same four `vpntype` values; `vpn_client`
  additionally uses `conn_mode` (`auto`/`demand`/`manually`).
- WireGuard field names differ between client and server configs (e.g.
  `allowed_ips` vs `allow_ips`, `persistent_keepalive` vs
  `persistent_keep_alive`, `mtu` vs `mtu_size`) — the tables above list both.
- OpenVPN profiles/certs are uploaded, not built here; the device stores them
  and encrypts the bundle into non-volatile storage.
