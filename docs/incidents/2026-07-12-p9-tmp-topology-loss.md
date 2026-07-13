# P9 TMP activity followed by mesh topology loss

## Status

The later mesh failure is temporally associated with the aggregate TMP/AppV2
test activity, but the available evidence does not attribute it to any
individual read, write, opcode or session. Causality is undetermined. The three
writes retain the observation `same_value_immediate_verification_passed`, while
their safety status is `safety_not_established`. Server-side TMP writes are
hard-disabled as a containment measure. TMP reads remain experimental and
opt-in.

## Timeline

On 11 July 2026, three separately authorized P9 validation runs sent the exact
boolean value returned by the corresponding preflight read:

| Read | Write | Setting |
|---|---|---|
| `0x4208` | `0x4209` | 802.11r |
| `0x421B` | `0x421C` | beamforming |
| `0x4222` | `0x4223` | monthly report |

Each setter returned firmware error code zero, and its immediate scalar
post-read matched the preflight value. Those checks established only immediate
field equality; they did not establish the absence of delayed, distributed or
resource side effects.

The wider test activity also included TMP sessions, reads and rejected probes.
The retained evidence cannot isolate one operation or operation class as the
cause of the later incident.

On 12 July 2026, all four satellite P9 nodes were reported offline by the Deco
app and then disappeared from the controller web topology. The satellite LEDs
were initially red and became white after individual restarts. The satellites
still answered network probes and their wireless radios remained observable,
so the symptom was a control-plane or mesh-membership failure rather than
simple loss of power.

The last pre-restart controller log contained repeated low-memory and relay
failures: 177 `tmpsvr` free-memory-below-15-MB messages, 102 TDP relay errors,
78 TMP relay errors, 90 short CGI messages and 51 CGI read errors. It contained
no observed OOM-killer, segmentation-fault or kernel-panic record. The retained
log did not span the original write time, so it cannot establish causation.

Restarting the main controller restored all five mesh nodes. The available
post-restart log did not repeat the TMP low-memory, relay or CGI failure pattern.

## Containment

- MCP, REST and the deployed `DecoService` cannot execute TMP writes.
- `DECO_ALLOW_TMP_NOOP_VERIFICATION` is retired and rejected when enabled.
- TMP reads remain behind their existing experimental opt-in gates.
- Source-checkout write harnesses remain available only for controlled lab
  validation. They require `DECO_TMP_LAB_ALLOW_WRITES`, exact per-operation
  confirmation and an exact live match for expected model, firmware and
  controller MAC address.
- The three value-free artifacts retain the immediate observations but no
  longer assert `verified_noop` or server execution eligibility.

No credentials, controller addresses, MAC addresses or response values are
recorded in this incident note.
