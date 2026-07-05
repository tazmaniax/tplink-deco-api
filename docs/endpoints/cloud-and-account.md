# Cloud & account — TP-Link cloud channel, binding, remote control

Endpoints: **`/admin/cloud`** (served by both the web UI and the app) and
**`/admin/cloud_account`**. Forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md), except
`/admin/cloud?form=firmware`, which is
[plaintext](../protocol/transport-and-dispatch.md#plaintext-endpoints).

This is the **router's end** of the TP-Link cloud channel: binding the device to
a TP-Link account, cloud/OTA firmware, mesh-group cloud sync, and the
`cloud_pass_through` remote-control tunnel. For the cloud side (hosts, gateway
RPC, app passthrough) see [`../protocol/cloud-api.md`](../protocol/cloud-api.md).
Related: [`firmware-and-upgrade.md`](./firmware-and-upgrade.md) (local flash),
[`onboarding-and-provisioning.md`](./onboarding-and-provisioning.md) (group
creation writes the cloud account), [`login.md`](./login.md) (`cloud_login`).

---

## `/admin/cloud` — cloud service on the device

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `nickname` | read, write | both | Device/node alias shown in the cloud group. |
| `firmware` | check, upgrade, download, firmware_status, sync_check_firmware, local_upgrade, get_sync, auto_upgrade | both | Cloud/OTA firmware check, download & flash across the mesh. |
| `group` | create, add, get, set, update, remove, report, message, iot_read, push, push_weekly | both | Cloud group (mesh) lifecycle + monthly/weekly report push. |
| `system` | bind, unbind, remove_all, proxy, account, notify, transfer, sync | both | Account binding lifecycle + cloud proxy connection. |
| `ddns` | (get / set) | both | Cloud-backed DDNS domain bind/unbind. |
| `manager` | (get / set) | both | Cloud "manager" permission profile. |
| `homecare_service` | (get) | app | HomeShield/HomeCare service info. |

`get_sync` / `auto_upgrade` and `push_weekly` are app-only operations; `iot_read`
reads IoT messages through the `group` form.

### `group`

Cloud/mesh group management. `create` builds the group (`group_id`,
`group_key`, `cloud_account`, master role); `add` joins a node; `set` /
`update` / `get` / `remove` maintain membership;
`report` / `message` / `push` / `push_weekly` drive the monthly/weekly report and
message centre. Called during onboarding — see
[`onboarding-and-provisioning.md`](./onboarding-and-provisioning.md).

### `system`

Account/binding lifecycle. `bind` / `unbind` / `remove_all` attach or detach the
device (and mesh) from the account; `account` updates the stored cloud owner;
`transfer` moves ownership to another account (app); `proxy` opens the cloud
proxy connection; `notify` / `sync` propagate to other mesh nodes.

### `firmware`

**Plaintext.** Cloud firmware info & OTA: `check` / `sync_check_firmware` query
the cloud for a newer image per `hw_id` / `oem_id`; `download` fetches it;
`upgrade` / `local_upgrade` flash it across the group and report `status` /
`download_progress`. Overlaps with the local flash path in
[`firmware-and-upgrade.md`](./firmware-and-upgrade.md) and the node-to-node sync
in [`onboarding-and-provisioning.md`](./onboarding-and-provisioning.md).

---

## `/admin/cloud_account` — account login, token, passthrough

Handles the router's TP-Link account credentials (RSA-encrypted via
`read_keys`), cloud firmware, and the remote-control passthrough.

| Form | Operations | Purpose |
|------|-----------|---------|
| `read` | read_keys, get_device_token, get_deviceInfo | RSA public key + device token / device info for account handling. |
| `login` | user_login, cloud_bind_and_login | Log the device into a TP-Link account (optionally binding at once). |
| `check_internet`, `check_device`, `check_connection`, `check_login`, `check_cloud_connection`, `check_support` | read | Connectivity / login / capability probes. |
| `bind_owner` / `unbind_owner` | write | Bind / unbind the account owner. |
| `get_dev_info` / `set_dev_info` | read / write | Device info exchanged with the cloud (`deviceId`, alias, model, MAC…). |
| `cloud_pass_through` (+ `tmp_cloud_pass_through`) | write | Device end of cloud remote-control (see below). |
| `upgrade` / `cloud_upgrade` / `load` | write / read | Cloud firmware upgrade + download status / progress + firmware list. |
| `get_token` | read | Cloud token. |
| `tmp_cmd` | write | Temporary cloud command relay. |
| `write` | write | Generic write. |

> The exact form ↔ operation split on this endpoint is approximate; treat the
> boundary as a guide.

### `read_keys` (RSA)

`read` with `operation=read_keys` returns the RSA public key the app uses to
encrypt the account password before `login` / `bind_owner`. Account credentials
on this endpoint are decrypted with the same key.

### `cloud_pass_through`

The **device end of cloud remote control**. When the app drives the router
through the cloud (see [`../protocol/cloud-api.md`](../protocol/cloud-api.md) →
*Device passthrough*), the cloud gateway relays the wrapped local request to the
router, where it lands here. The request is reassembled from its serialized
parts (`currentSerialNumber` / `startSerialNumber` / `endSerialNumber`),
`method` + `params` + `deviceId` are decoded, the request is run locally and its
result is cached and returned. `tmp_cloud_pass_through` is the
un-cached/temporary variant.

The **endpoint catalogue is identical locally and remotely** — passthrough only
changes the outer transport.

---

## Notes

- `/admin/cloud` and `/admin/cloud_account` are the router-side counterpart to
  the cloud gateway in [`../protocol/cloud-api.md`](../protocol/cloud-api.md);
  this SDK is local-only and does not implement the cloud tier.
- Account credentials are RSA-encrypted (`read_keys`) and base64-wrapped; the
  device stores a hashed cloud password used by local `cloud_login` — see
  [`login.md`](./login.md).
- Cloud firmware (`/admin/cloud?form=firmware`,
  `/admin/cloud_account?form=upgrade`) and mesh sync overlap; the actual flash
  still goes through the firmware/sync paths in
  [`firmware-and-upgrade.md`](./firmware-and-upgrade.md) and
  [`onboarding-and-provisioning.md`](./onboarding-and-provisioning.md).
- `group create` / `add` and `system account` are invoked during onboarding when
  the master creates the mesh group.
