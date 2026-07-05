# TP-Link cloud API

The Deco app can reach a router two ways: **locally** (everything else in this
documentation) and **remotely through the TP-Link cloud**. This page maps the
cloud side. The cloud is out of scope for this SDK, which is local-only — but
understanding it explains the remote-control path and the account/binding
lifecycle.

> This page catalogues the cloud hosts, methods and REST paths. Field-level
> request/response payloads are out of scope.

---

## Hosts

| Host | Role |
|------|------|
| `n-wap-gw.tplinkcloud.com` | Primary WAP gateway — account login, device list, **passthrough** to devices. Regional variants: `n-aps1-wap-gw`, `n-use1-wap-gw`. |
| `n-da.tplinkcloud.com` | Device-access / data endpoint. |
| `api.i.tplinknbu.com` | NBU (next-gen) app API. |
| `homecare-v2.tplinknbu.com`, `api-homecare-cloud.i.tplinknbu.com` | HomeShield / HomeCare services. |
| `api-alexa-router.tplinknbu.com`, `api-ifttt-router.tplinknbu.com`, `api-nest-deco.tplinknbu.com` | Third-party integrations (Alexa, IFTTT, Nest). |
| `ota.i.tplinkcloud.com` | Firmware OTA. |
| `dcmp-api.i.tplinkcloud.com` | DCMP (co-managed / carrier) provisioning. |
| `account-captcha.tplinkcloud.com`, `account-delete.tplinkcloud.com` | Account captcha & deletion. |
| `deventry-beta.tplinkcloud.com`, `*-beta.*` | Beta/staging tier. |

Region is chosen at login time; the app rewrites the WAP gateway host to the
regional prefix returned by the account service.

---

## Account / gateway RPC

The classic TP-Link cloud gateway speaks a JSON-RPC-like protocol: `POST` to
the WAP gateway host with a body of `{ "method": "<method>", "params": { … } }`
plus a `?token=<token>` query once authenticated.

| `method` | Purpose |
|----------|---------|
| `login` | Authenticate a TP-Link ID → returns `token`. |
| `register` | Create a TP-Link account. |
| `getToken` | Refresh / exchange a token. |
| `getDeviceList` | List devices bound to the account (each with `deviceId`, `appServerUrl`, alias, MAC…). |
| `bindDevice` / `unbindDevice` | Attach/detach a device to the account. |
| `passthrough` | Tunnel a **local** device request through the cloud (see below). |
| `securePassthrough` | Passthrough wrapped in the app-layer secure channel. |

## NBU REST API

The newer app tier uses REST paths on the NBU/api hosts:

| Path | Purpose |
|------|---------|
| `/api/v1/account`, `/api/v2/account/getAccountStatusAndUrl` | Account status and the per-account service URL. |
| `/api/v2/common/helloCloud` | Reachability / capability probe. |
| `/api/v2/data/app/uploadBasicData`, `/api/data/app/uploadBasicData` | Telemetry / basic-data upload. |
| `/api/v2/tool/…` | Misc tooling endpoints. |

---

## Device passthrough (remote control)

Remote control does **not** invent new device endpoints. The app wraps a normal
local request:

```
POST https://<router-ip>/cgi-bin/luci/;stok=<TOKEN>/admin/<controller>?form=<form>
{ "operation": "…", "params": { … } }
```

…inside a cloud `passthrough` call addressed to the device's `deviceId`. The
cloud relays it to the router (which keeps a persistent connection to the WAP
gateway) and returns the device's response. In other words:

- **The endpoint catalogue in [`../endpoints/`](../endpoints) is the same
  locally and remotely.** Only the outer transport differs.
- On the device side, the endpoints [`/admin/cloud`](../endpoints/cloud-and-account.md)
  and `/admin/cloud_account` implement the router's end of this channel
  (binding, token, firmware sync, and the `cloud_pass_through` form).

---

## Secure app channel (KLAP-style handshake)

Alongside plain passthrough, the app negotiates an encrypted session with a
three-call handshake:

| Path | Step |
|------|------|
| `/app/handshake1` | Client hello — exchange first nonce. |
| `/app/handshake2` | Server confirm — derive the session key. |
| `/app/request` | Encrypted request/response over the negotiated key. |

This is TP-Link's "secure passthrough" (KLAP) layer, distinct from the
RSA/AES envelope used by the *local* `/cgi-bin/luci` API. It protects the
cloud-tunneled channel end to end. The local SDK does not implement it.

---

## Relationship to this SDK

This SDK talks to the router **directly over the LAN** using the local
protocol. The cloud API is documented here only for completeness and to make
the remote-control architecture legible. Implementing cloud/remote access would
mean adding: account login → `getDeviceList` → `passthrough`, all against the
TP-Link cloud, and is intentionally not part of the local surface.
</content>
