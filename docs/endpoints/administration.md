# Administration & remote management

Endpoint: **`/admin/administration`**. All forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

Covers the admin account/password, the password-recovery (e-mail) settings,
local-management restriction (an allowlist of LAN devices permitted to reach the
management UI), remote (WAN-side) management, and login preemption. The admin
password itself is RSA-encrypted inside `params`, same key flow as
[login.md](./login.md).

Related: [login.md](./login.md) (session + password RSA key),
[cloud-and-account.md](./cloud-and-account.md) (TP-Link cloud account),
[storage-usb.md](./storage-usb.md) (USB share credentials), [README.md](./README.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `account` | read, write, set, appset, appget, mcu_read, mcu_write, mcu_check | web | Admin username / password. |
| `recovery` | read, update | web | Password-recovery e-mail (SMTP) settings. |
| `mode` | local, remote | web | Select local-only vs remote management mode. |
| `local` | load, insert, update, remove, view | web | Local-management device allowlist. |
| `remote` | read, write | web | Remote (WAN) management access. |
| `login` | read, write | web | Login preemption behaviour. |

---

## `account`

The admin credential handlers. Several operations exist because the web UI, the
mobile app, and the MCU/onboarding paths each encrypt (or don't) differently:

| Operation | Notes |
|-----------|-------|
| `read` | Return current admin username. |
| `write` | Change password: `params` `{ old_acc, old_pwd, new_acc, new_pwd, cfm_pwd }`, `new_pwd` RSA-encrypted. Invalidates other sessions and re-syncs the USB-share (Samba/FTP) credentials. |
| `set` | Set account (`new_acc`, RSA `new_pwd`) for the initial/admin case. |
| `appset` | App path: `new_acc` / `new_pwd` sent plaintext-in-envelope. |
| `appget` | Return `{ username, password }`. |
| `mcu_write` | MCU path: change `old_acc` / `new_acc` / `old_pwd` / `new_pwd` without envelope encryption; re-syncs USB-share credentials. |
| `mcu_read` | Return `{ acc, pwd }`. |
| `mcu_check` | Verify `old_acc` / `old_pwd`. |

Every successful password change invalidates other sessions and re-syncs the
USB-share (Samba/FTP) credentials — see [storage-usb.md](./storage-usb.md).

## `recovery`

**read** → recovery config with the password hidden:

| Field | Meaning |
|-------|---------|
| `enable_rec` | Password-recovery enabled. |
| `authentication` / `enable_auth` | SMTP auth enabled. |
| `from` / `smtp` | Sender address + SMTP server. |
| `username` / `password` | SMTP credentials (`password` RSA-encrypted on write). |

**update** — validate (e-mail format, range lengths, on/off flags) then persist.

## `mode`

Selects which management mode is active by writing `mode.local` (`all` /
`partial`):

- **local** — enable local-management restriction; `all` lets any LAN host
  manage, `partial` limits to the `local` allowlist.
- **remote** — hand control to the `remote` form (WAN management).

The caller's own IP is checked against the LAN.

## `local`

The allowlist of LAN devices permitted to reach the management UI when
local-management restriction is `partial`. The entry count is capped by a
per-device limit.

| Operation | Notes |
|-----------|-------|
| `load` | Load supporting data + current entries. |
| `insert` | Add `{ mac, description, enable }`; validates the MAC and enforces the max-entry cap; applied in the firewall. |
| `update` | Modify an entry (removed and re-added in the firewall). |
| `remove` | Delete entries (removed from the firewall). |
| `view` | List entries joined with the client list (`mac`, `name`, `hostname`). |

## `remote`

**read** → `{ enable, port, ipaddr }`.

**write** — `params` `{ enable ("off"), port, ipaddr, mode ("all"|"partial") }`.
`all` opens remote management to any WAN source; `partial` restricts to
`ipaddr`. Validated (unicast IPv4, LAN check, port range) and applied in the
firewall.

## `login`

**read** → `{ preempt }`.
**write** — set `login.preempt`: whether a new admin login may preempt (kick) an
existing session.

---

## Notes

- All password fields sent to `account.write` / `account.set` and
  `recovery.update` are RSA-encrypted with the key from
  [`/login?form=keys`](./login.md) and decrypted server-side.
- `mode` + `local` together implement "who can manage this Deco from the LAN";
  `remote` governs the separate WAN-side management channel. Both are enforced
  in the firewall.
- This endpoint is web-only; the `appset` / `appget` / `mcu_*` operations are
  the app / MCU entry points into the same account model.
