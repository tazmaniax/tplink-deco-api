# USB storage & Time Machine

Endpoints: **`/admin/usbshare`**, **`/admin/time_machine`** (both app), and the
web-only **`/admin/folder_sharing?form=tree`**. All
forms use the [encrypted envelope](../protocol/transport-and-dispatch.md).

`/admin/usbshare` manages USB disks and the Samba / FTP / DLNA sharing servers;
`/admin/time_machine` manages macOS Time Machine (AFP/Bonjour) backups onto a
USB volume. The `_list` / `content` / `sync` operations fan out to mesh nodes so
an app can enumerate USB storage on every Deco, not just the gateway.

Related: [administration.md](./administration.md) (`usbshare_update` re-applies
Samba credentials when the admin account changes), [README.md](./README.md).

---

## Forms

| Form | Operations | By | Purpose |
|------|-----------|-----|---------|
| `device` | scan, list, remove, list_all, remove_list | app | Enumerate / eject USB disks & partitions. |
| `server` | read, write, read_list, write_list | app | Samba / FTP / DLNA sharing + media-server config. |
| `status` | read | app | Current USB scan status. |
| `sync` | read | app | Aggregate USB device list across mesh nodes. |
| `settings` | read, write | app | Time Machine enable + target volume / quota. |
| `info` | read | app | Time Machine capability + per-disk usage. |
| `content` | read | app | Time Machine backup listing across nodes. |
| `tree` (`/admin/folder_sharing`) | read | web | Storage topology used by the network map. |

`list_all` / `remove_list` / `read_list` / `write_list` are the multi-node
variants of `list` / `remove` / `read` / `write`; they forward to the other
mesh nodes and merge the results.

The shared P9 web assets include the `tree` store, but the observed P9 returned
HTTP 404. It is catalogued as a private read because enabled models may return
device and filesystem paths.

---

## `/admin/usbshare` · `device`

**scan** — kick off a USB rescan in the background.

**list** → `{ "operation": "list" }`

Result `usb_device_list[]`, one entry per USB disk:

| Field | Meaning |
|-------|---------|
| `device_id` | Stable disk id. |
| `serial` | Disk serial. |
| `model` | Disk model (base64). |
| `name` | Device node name (base64). |
| `pid` | Partition/volume id prefix. |
| `capacity` / `max_space` | Total size. |
| `available_space` | Free space. |
| `partitions` / `volumns[]` | Per-partition list, each with `uuid`, `label`, `path_prefix`, `capacity`, `used`, `free`. |

**remove** — safely unmount / eject a disk; `params` identify the disk.
**list_all** / **remove_list** do the same across mesh nodes.

## `/admin/usbshare` · `server`

**read** → `{ "operation": "read" }`

Result:

| Field | Meaning |
|-------|---------|
| `server_name` | Advertised share/server name. |
| `authentication` | `{ enable, username, password, account, auth_all }` — share auth (`auth_all` = anonymous access). |
| `media_server` (`dlna`) | DLNA / media-server enable. |
| `network_neighbour` (`samba`) | Samba / SMB enable. |
| `ftp_local` / `ftp_internet` | FTP over LAN / over WAN (`ftpex`) enable. |
| `port` / `ftpex_port` | FTP LAN / internet ports. |
| `device_id` | Owning node. |
| `is_usb_reduction_support` / `interference_reduction` (`reduction`) | USB 3.0 interference-reduction toggle. |

**write** — set the above. Validates `svrname` (non-empty) and each `port`
(numeric). **read_list** / **write_list** target mesh nodes.

## `/admin/usbshare` · `status`

**read** → scan state: `state` (`idle` / `scanning`), `scan_time`.

## `/admin/usbshare` · `sync`

**read** — returns the merged USB device list gathered from all mesh nodes.

---

## `/admin/time_machine` · `settings`

**read** → `{ "operation": "read" }`

Result `settings[]`, one entry per candidate volume:

| Field | Meaning |
|-------|---------|
| `enable` | Whether Time Machine is on for this volume (`off` = disabled). |
| `uuid` | Volume UUID (target selector). |
| `limitsize` | Backup size cap. |
| `disk_status` | Per-volume status. |
| `label` / `path_prefix` / `mntdir` | Volume identity / mount point. |
| `capacity` / `free` / `used` | Volume space. |
| `serial` | Disk serial. |

**write** → `params: { "enable": …, "uuid": "…", "limitsize": … }`. Rejects an
unknown `uuid` ("Invalid uuid, maybe your disk is unplugged").

## `/admin/time_machine` · `info`

**read** → capability + usage snapshot:

| Field | Meaning |
|-------|---------|
| `device_id` | Node id. |
| `enable` | Time Machine enabled. |
| `max_space` (`capacity`) / `available_space` (`free`) | Disk space. |
| `storage_limit` (`limitsize`) | Configured quota. |
| `disk_status` / `uuid` | Active target volume. |
| `usb_list[]` | Candidate USB volumes: `{ enable, uuid, mntdir, limitsize, storage_limit }`. |

## `/admin/time_machine` · `content`

**read** — enumerate Time Machine backups across nodes; merges per-node results
and reports `failed_device_id_list` on partial failure. Returns "No
time-machine" when none is configured.

---

## Notes

- USB sharing is off unless a disk is present and a server (`samba` / `dlna` /
  `ftp`) is enabled.
- Time Machine relies on AFP + Bonjour; writing `settings` restarts these
  services.
- Changing the admin account elsewhere calls `usbshare_update` (see
  [administration.md](./administration.md)) so Samba/FTP credentials stay in
  sync with the login when share auth reuses the admin user.
