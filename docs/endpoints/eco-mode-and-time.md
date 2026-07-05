# Eco mode & time

Power-saving scheduler and time/DST handling. Endpoints: **`/admin/eco_mode`**
(app), **`/admin/time_setting`** (DST/sync) and the device-level `timesetting` /
`systime` forms on [`/admin/device`](./device.md). All forms use the
[encrypted envelope](../protocol/transport-and-dispatch.md).

Related: [device.md](./device.md) (`timesetting` read/write, node `eco_mode`
v1), [network.md](./network.md), [README.md](./README.md).

---

## Forms

| Endpoint | Form | Operations | By | Purpose |
|----------|------|-----------|-----|---------|
| `/admin/eco_mode` | `eco_mode` | read, write | app | Eco / power-saving schedule (v2). |
| `/admin/eco_mode` | `get_period` | read | app | Current saving-power period. |
| `/admin/eco_mode` | `skip_schedule` | write | app | Skip the active schedule once. |
| `/admin/time_setting` | `request` | read | web | DST table. |
| `/admin/time_setting` | `notify` | write | web | Time/DST sync. |
| `/admin/device` | `timesetting` | read, write | both | Node date / time / timezone (SDK `TimeSettings`). |
| `/admin/device` | `systime` | read | app | System-time snapshot. |

---

## `/admin/eco_mode?form=eco_mode`

Eco mode v2. (The older v1 scheme is on
[`/admin/device?form=eco_mode`](./device.md).)

**read** → `{ "operation": "read" }`

| Field | Meaning |
|-------|---------|
| `enable` | Eco mode on/off. |
| `user_set` | User has configured eco mode. |
| `has_set_eco_mode` | Whether a schedule has ever been saved. |
| `power_mode` / `type` | `normal_power` / `low_power` / `super_low_power`. |
| `schedule_mode` | `daily` / `workday` / `weekend` / `custom` (or `always`). |
| `daily_enable` / `workday_enable` | Per-mode enable flags. |
| `daily_time` | `{ forenoon, afternoon }` windows. |
| `workday_time` / `weekend_time` | Work-day / weekend windows. |
| `custom_time` | Per-day windows keyed `Sun`…`Sat`. |
| `workday_config` | Which weekdays count as work days. |
| `duration` / `eco_mode_duration` | Configured saving duration. |
| `system_time` / `timezone` / `tz_region` | Time context for the schedule. |
| `is_active` | Whether saving is currently in effect. |
| `can_skip_schedule` | Whether `skip_schedule` is allowed now. |
| `saving_period` | Current/next saving window. |

**write** — mirrors the read fields: `enable`, `user_set`, `power_mode`/`type`
(`normal_power`/`low_power`/`super_low_power`), `schedule_mode`
(`always`/`daily`/`workday`/`weekend`/`custom`) with the matching
`daily_time` (`forenoon`/`afternoon`), `workday_time`, `weekend_time` or
`custom_time` (`Sun`…`Sat`), and `stop_schedule`. On unsupported hardware it is
force-disabled ("New Deco device does not support eco_mode v2").

## `/admin/eco_mode?form=get_period`

**read** — returns the resolved saving-power window (`saving_power_period`)
for the active `schedule_mode` (`always` / `schedule`, with `date` / `time`
and the daily/workday/custom breakdown).

## `/admin/eco_mode?form=skip_schedule`

**write** — sets `stop_schedule` so the currently running saving schedule is
skipped for this occurrence.

---

## `/admin/time_setting`

Internal time/DST plumbing:

- **`request`** — returns the full DST table.
- **`notify`** — a satellite/AP notifies the master of a time update, and DST
  changes are propagated across the mesh.

These are consumed by the firmware itself; the SDK reads/writes time through
the device `timesetting` form below.

## `/admin/device` — `timesetting` & `systime`

**`timesetting`** (both) — **read / write** node date, time and timezone. SDK
model: `TimeSettings` (`get_time_settings()`).

```json
{ "operation": "read", "params": { "device_mac": "default" } }
```

| Field | Meaning |
|-------|---------|
| `time` | Current time-of-day. |
| `date` | Current date. |
| `timezone` | POSIX/offset timezone string. |
| `tz_region` | Region id (e.g. `Continent/City`). |
| `continent` | Continent parsed from `tz_region`. |
| `dst_status` | Daylight-saving state. |

Write applies `date_time` / `timezone` / `tz_region`.

**`systime`** (app) — **read** a lighter snapshot: `date`, `time`, `timezone`,
`dst_status`.

---

## Notes

- Two eco-mode implementations coexist: **v1** on
  [`/admin/device?form=eco_mode`](./device.md) (schedule modes `custom` /
  `all_day`) and **v2** here (schedule modes `daily` / `workday` / `weekend` /
  `custom`). Newer firmware uses v2.
- Day keys are `Sun` `Mon` `Tue` `Wed` `Thu` `Fri` `Sat`; power tiers are
  `normal_power` / `low_power` / `super_low_power`.
- `eco_mode`, `led` and `wifi_schedule` share the underlying scheduler, so a
  reboot or a schedule change can affect all three (`led_control_duration`,
  `wifi_schedule_duration`).
