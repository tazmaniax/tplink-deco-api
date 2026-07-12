# Logs & diagnostics

Remote syslog, log export / feedback bundles, low-level debug daemons,
connectivity self-tests, ARP-table sync and telemetry collection. Endpoints:

| Endpoint | By |
|----------|-----|
| `/admin/log` | app |
| `/admin/log_export` | web + app |
| `/admin/syslog` | web |
| `/admin/debug` | web + app |
| `/admin/auto_test` | app |
| `/admin/arptbl` | app |
| `/admin/telemetry_collect` | app |

All forms use the [encrypted envelope](../protocol/transport-and-dispatch.md)
**except** `/admin/log_export?form=save_log`, which is a
[plaintext](../protocol/transport-and-dispatch.md#plaintext-endpoints) file
download. Related: [system.md](./system.md), [README.md](./README.md).

---

## Forms

| Endpoint · Form | Operations | By | Purpose |
|-----------------|-----------|-----|---------|
| `/admin/log` · `log` | read, write, load | app | Remote syslog server config + read the log. |
| `/admin/log_export` · `types` | read | web | Available log levels. |
| `/admin/log_export` · `save` | write | web | Apply export level / restart logging. |
| `/admin/log_export` · `save_log` | (download) | web · **plain** | Download the log as a file. |
| `/admin/log_export` · `feedback_log` | read, build | web + app | Read paginated logs or build a feedback bundle. |
| `/admin/syslog` · `mail` | read, write | web | SMTP and scheduled-email settings. |
| `/admin/syslog` · `log` | mail | web | Send the current log by email. |
| `/admin/debug` · `qlog` | start, stop | app | QLog modem-trace daemon (port 9000). |
| `/admin/debug` · `simplecom` | start, stop | app | `simplecom` serial daemon (port 9999). |
| `/admin/debug` · `tty2tcp` | start, stop | app | Bridge a serial port to TCP. |
| `/admin/debug` · `tm` | start, stop | app | Time Machine debug. |
| `/admin/auto_test` · `test` | nat, upnp, dhcp, wifi, all_info | app | Local self-test / device-info snapshot. |
| `/admin/arptbl` · `syn` | tbl_op | app | Push/sync ARP entries (RE nodes). |
| `/admin/telemetry_collect` · `telemetry_device` / `_client` / `_system` / `_usb` | read | app | Collect telemetry categories. |
| `/admin/telemetry_collect` · `telemetry_control` | write | app | Enable / disable telemetry. |

---

## `/admin/log` · `log`

Remote syslog configuration.

**read** — return the current log.
**load** — return editable ranges (`log_size` range).
**write** → `params` `{ log_ip, log_port, log_size }` — remote syslog target
IP/port and local ring-buffer size.

## `/admin/log_export`

Web-UI log export + feedback bundle. Log levels (`types` → read):
`EMERG`, `ALERT`, `CRITICAL`, `ERROR`, `WARNING`, `NOTICE`, `INFO`, `DEBUG`
(plus a synthetic `ALL`); each returned as `{ name, value }`.

- **`save` (write)** — set the export log level and restart logging, rebuilding
  the exported log file.
- **`save_log` (download, plaintext)** — streams the prepared log file as an
  HTTP attachment: `Content-Disposition: attachment; filename="log-<YYYY-MM-DD>.log"`,
  `Content-Type: text/plain`. See
  [plaintext endpoints](../protocol/transport-and-dispatch.md#plaintext-endpoints).
- **`feedback_log` (build)** — collects the log and encrypts it into a bundle
  with a key derived from the AP SSID (default `TP-LINK`), producing a
  `feedback.log` file. The app side exposes only `feedback_log` / `build`.

> The web side also has internal `read` (paginated lines: `content`,
> `totalNum`, `currentIndex`, `logList`) and `remove` operations used by the
> in-UI log viewer.

The P9 `mail` model exposes SMTP credentials and is therefore classified
`secret`. Its fields are `from`, `auth`, `password`, `smtp_server`, `port`,
`to`, `auto_mail`, `auto_mail_type`, `every_day_time`, `every_hours`, and
`mail_again`. Automatic discovery never invokes either syslog form.

## `/admin/debug`

Low-level trace daemons (app-only). Each form takes `start` / `stop`:

| Form | Notes |
|------|-------|
| `qlog` | Cellular-modem QLog trace on TCP 9000. |
| `simplecom` | Serial console daemon on TCP 9999. |
| `tty2tcp` | Bridge a serial port to TCP; `params` `{ ipaddr, port }`. |
| `tm` | Time Machine share debug. |

`start` first checks whether the daemon is already running and returns its
`pid`. The **web** `/admin/debug` endpoint is a single handler that opens a
`file` param and returns its bytes as `data` (with an optional `wait`) — a raw
file-read diagnostic.

## `/admin/auto_test` · `test`

Local connectivity / capability self-test. Operations:

| Operation | Returns |
|-----------|---------|
| `nat` | Hardware-NAT state (`enable`, `hw_enable`). |
| `upnp` | UPnP enable + active mappings (`is_enabled`, `description`, `external_port`, `internal_port`, `client_ip`, `protocol`, `leasetime`). |
| `dhcp` | LAN DHCP server snapshot (`gateway`, `domain`, `lease_time`, `dns1`, `dns2`, `start_ip`, `end_ip`, `need_reboot`). |
| `wifi` | Advanced wireless settings. |
| `all_info` | Aggregate device snapshot: `wifi` (ssid/password/encryption/mode), `wanDetect`, `bluetooth`, `lan` (ipaddr/mask/mac), `plc_mac`, `pin`, `model`, `hardware_ver`, `software_ver`, default password, `oem_id`, `country`, group id/key, `imei`, mobile ISP/LTE versions. |

## `/admin/arptbl` · `syn`

**tbl_op** — push ARP entries into the kernel so a RE node's ARP table matches
the gateway. Returns "RE: not support arp_syn" on hardware without ARP-agent
support. Internal / mesh use.

## `/admin/telemetry_collect`

Collects diagnostic telemetry; each read connects to the target node
(`ip_ap_addr` / MAC) and returns the encoded blob:

| Form | Operation | Returns |
|------|-----------|---------|
| `telemetry_device` | read | Device / backhaul info. |
| `telemetry_client` | read | Client STA list. |
| `telemetry_system` | read | System info. |
| `telemetry_usb` | read | USB info. |
| `telemetry_control` | write | Enable / disable telemetry. |

`telemetry_control` read reports the current telemetry enable flag.

---

## Notes

- `save_log` is the only plaintext endpoint here — it is a browser download, so
  it bypasses the AES/RSA envelope and returns raw `text/plain`.
- The `feedback_log` bundle is encrypted with a key derived from the AP SSID,
  not the session key; it is meant to be uploaded to TP-Link support.
- `debug`, `arptbl` and `telemetry_collect` are diagnostic/internal surfaces —
  several actions spawn or kill daemons and are RE-node oriented; treat them as
  advanced.
