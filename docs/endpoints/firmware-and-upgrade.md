# Firmware & upgrade — config backup / flash / MCU

Endpoints: **`/admin/firmware`**, **`/admin/isp`**, and **`/mcu_upgrade`**.
`config` and `upgrade`
use the [encrypted envelope](../protocol/transport-and-dispatch.md);
`config_multipart` is
[plaintext multipart](../protocol/transport-and-dispatch.md#plaintext-endpoints).

Node **reboot** and **factory reset** live on the device endpoint — see
[`device.md`](./device.md) (`reboot`, `factory`). Cloud/OTA firmware is
[`cloud-and-account.md`](./cloud-and-account.md); mesh firmware distribution is
the sync surface in
[`onboarding-and-provisioning.md`](./onboarding-and-provisioning.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `config` | read, check, backup, restore | web | Local config-file backup & restore. |
| `config_multipart` | upload, backup, restore | web | Multipart config transfer. |
| `upgrade` | read, write | web | Read installed versions or flash a staged image. |
| `isp_upgrade` (`/admin/isp`) | read, upgrade | web | ISP profile image status/upload. |
| `mcu_upgrade` (`/mcu_upgrade`) | check | web | Finalise an MCU firmware upgrade. |

The reboot delay after a flash comes from a device profile value.

---

## `config`

Local (offline) backup and restore of the router's user configuration.

**read** → `{ "operation": "read" }` — current config snapshot.

**check** → `{ "operation": "check" }` — poll a running restore/upgrade:

| Field | Meaning |
|-------|---------|
| `error_code` | `0` while OK / on success. |
| `ops` | Operation being tracked (`restore`, …). |
| `upgrade_type` / `totaltime` | Upgrade class and the reboot countdown (seconds). |

**backup** → `{ "operation": "backup" }` — builds an **encrypted** backup blob,
prepends the product-info MD5 and returns it as a file download
(`Content-Type: application/octet-stream`, `Content-Disposition: attachment`) —
not a JSON envelope.

**restore** → uploads a previously-downloaded backup; the device verifies the
product-info MD5, decrypts it, applies it and reboots. Poll `check` for progress
/ `restore_error`.

## `config_multipart`

Plaintext `multipart/form-data` transfer used for configuration backup/restore
and firmware uploads. Listed in
[plaintext endpoints](../protocol/transport-and-dispatch.md#plaintext-endpoints).
The P9 web client submits backup as a hidden form containing only the scalar
field `operation=backup`; there is no file part. `DecoClient.call_binary()`
implements that exact read-only contract and returns the encrypted backup bytes.
The live P9 response remains intentionally untested because it contains a bulk
secret configuration export. Restore and firmware upload remain unsupported.
The static value-free contract is recorded in
[`p9-multipart-backup-contract.json`](../api-responses/p9-multipart-backup-contract.json).

## `/admin/isp` · `isp_upgrade`

The P9 web UI declares `read` and multipart `upgrade`. The observed P9 build
returned HTTP 404 for the safe `read`, so the page is present in the shared UI
bundle but its handler is not enabled on that device.

## `upgrade`

**write** — flash a firmware image already staged on the device. On success the
device performs a delayed reboot and reports `totaltime` (the reboot countdown
in seconds).

## `/mcu_upgrade` · `mcu_upgrade`

**check** → `{ "operation": "check" }` — finalises an MCU (co-processor)
firmware upgrade: on `mcu_update_finish == "yes"` it clears the upgrade flag and
returns `mcu_finish`.

---

## Notes

- `config backup`/`restore` move an **encrypted, product-locked** blob: the
  product-info MD5 is prepended and checked, so a backup only restores onto the
  same product line.
- Restore/upgrade progress is tracked server-side; poll `config` with
  `operation=check`.
- Firmware bytes reach the device either via `config_multipart` (local file) or
  via the cloud/mesh path
  ([`cloud-and-account.md`](./cloud-and-account.md),
  [`onboarding-and-provisioning.md`](./onboarding-and-provisioning.md) sync);
  `upgrade` only flashes what is already staged.
- `reboot` / `factory` are **not** here — they are on
  [`/admin/device`](./device.md).
