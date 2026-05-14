# TP-Link Deco — Authentication Protocol

Documentation of the proprietary HTTP protocol used by the TP-Link Deco web UI
(tested on `192.168.5.1`). Reverse-engineered from the firmware's JavaScript
files.

---

## Overview

All communication uses `POST` with `Content-Type: application/json` against:

```
http://<router-ip>/cgi-bin/luci/;stok=<TOKEN>/<endpoint>?form=<form>
```

`stok` is empty before login (`/;stok=/`) and populated afterwards.

Authenticated requests carry an **AES-128-CBC** encrypted payload signed with
**RSA PKCS#1 v1.5** — except for the endpoints listed under
[Plaintext endpoints](#plaintext-endpoints).

---

## Login flow

### Step 1 — Fetch RSA keys

Two calls in parallel, both unencrypted:

#### `POST /login?form=auth`

```json
{ "operation": "read" }
```

Response:
```json
{
  "result": {
    "key": ["<modulus_hex>", "010001"],
    "seq": 766218342
  },
  "error_code": 0
}
```

- **512-bit RSA key** used to sign the `sign` field on every request.
- **`seq`** is a session counter; it increments on every request.

#### `POST /login?form=keys`

```json
{ "operation": "read" }
```

Response:
```json
{
  "result": {
    "username": "",
    "password": ["<modulus_hex>", "010001"]
  },
  "error_code": 0
}
```

- **1024-bit RSA key** used to encrypt the password inside the login payload.

---

### Step 2 — Prepare the encryptor

```python
import secrets, hashlib

# AES key: two 16-digit numeric strings
aes_key = "".join(secrets.choice("0123456789") for _ in range(16))
aes_iv  = "".join(secrets.choice("0123456789") for _ in range(16))

# AES key identifier (used inside the signature)
aes_key_str = f"k={aes_key}&i={aes_iv}"
# e.g. "k=1415950173028918&i=5652578606663031"

# Session hash: MD5 of the username concatenated with the password
session_hash = hashlib.md5((username + password).encode()).hexdigest()
```

---

### Step 3 — Send the login request

#### Build the payload

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode
import json, secrets

def aes_encrypt(key: str, iv: str, plaintext: str) -> str:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
    enc = cipher.encryptor()
    return b64encode(enc.update(padded) + enc.finalize()).decode()

def rsa_pkcs1v15_encrypt(n: int, e: int, message: bytes) -> str:
    """RSA PKCS#1 v1.5 — returns lowercase hex."""
    k = (n.bit_length() + 7) // 8
    pad_len = k - len(message) - 3
    pad = b""
    while len(pad) < pad_len:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            pad += b
    em = b"\x00\x02" + pad + b"\x00" + message
    ct = pow(int.from_bytes(em, "big"), e, n)
    h  = format(ct, "x")
    return h if len(h) % 2 == 0 else "0" + h

def sign(n: int, e: int, sig_str: str) -> str:
    """Split into 53-char blocks (the PKCS#1 v1.5 limit for 512-bit RSA)."""
    if len(sig_str) > 53:
        return (rsa_pkcs1v15_encrypt(n, e, sig_str[:53].encode()) +
                rsa_pkcs1v15_encrypt(n, e, sig_str[53:].encode()))
    return rsa_pkcs1v15_encrypt(n, e, sig_str.encode())

# Login data (AES-encrypted)
login_data = json.dumps({
    "operation": "login",
    "username":  username,
    "password":  password,   # plaintext password (AES already protects the channel)
})
data_b64 = aes_encrypt(aes_key, aes_iv, login_data)

# String to sign: includes the AES key (isLogin=True)
sig_str = f"{aes_key_str}&h={session_hash}&s={seq + len(data_b64)}"

payload = {
    "sign": sign(sign_rsa_n, sign_rsa_e, sig_str),
    "data": data_b64,
}
```

#### `POST /login?form=login`

```json
{
  "sign": "<hex RSA-512(sig_str[:53]) + RSA-512(sig_str[53:])>",
  "data": "<base64 AES-CBC-PKCS7(login_data_json)>"
}
```

Response (on success):
```json
{
  "result": {
    "stok":    "abc123...",
    "usrLvl":  1
  },
  "error_code": 0
}
```

---

## Authenticated requests

After login, every call uses the same encryptor with `isLogin=False` (no AES
key in the signature):

```python
# String to sign: WITHOUT the AES key
sig_str = f"h={session_hash}&s={seq + len(data_b64)}"

payload = {
    "sign": sign(sign_rsa_n, sign_rsa_e, sig_str),
    "data": aes_encrypt(aes_key, aes_iv, json.dumps(request_data)),
}

seq += 1  # increment on every request
```

URL:
```
POST http://<ip>/cgi-bin/luci/;stok=<TOKEN>/admin/<endpoint>?form=<form>
```

---

## Crypto parameters

| Parameter | Value |
|-----------|-------|
| AES mode | CBC |
| AES padding | PKCS7 |
| AES key size | 128-bit (16 numeric chars) |
| RSA (sign) | 512-bit, PKCS#1 v1.5 |
| RSA (pwd) | 1024-bit, PKCS#1 v1.5 |
| RSA split | 53 chars per block |
| Session hash | MD5(username + password) |

---

## Plaintext endpoints

These endpoints accept plain JSON (no `sign` / `data`):

| Endpoint | Description |
|----------|-------------|
| `/login?form=auth` | RSA sign key + initial seq |
| `/login?form=keys` | RSA password key |
| `/login?form=check_factory_default` | Check whether the router is in factory state |
| `/login?form=default_info` | Factory default SSID and password |
| `/admin/system?form=envar` | Environment variables |
| `/admin/system?form=sysmode` | System mode |
| `/admin/cloud?form=firmware` | Cloud firmware info |
| `/admin/isp?form=isp_upgrade` | ISP-driven upgrade |
| `/admin/firmware?form=config_multipart` | Firmware config (multipart) |
| `/admin/log_export?form=save_log` | Log export |

---

## Authenticated endpoints (discovered)

| Endpoint | Description |
|----------|-------------|
| `/admin/device?form=mode` | Device operating mode |
| `/admin/wireless?form=wlan` | Wi-Fi configuration |
| `/admin/web?form=extra_component_info` | Extra component info |
| `/admin/component_control?form=switch_list` | Switch list |

---

## Relevant firmware JavaScript files

| File | Contents |
|------|----------|
| `js/libs/tpEncrypt.js` | `encryptor` class — orchestrates AES + RSA |
| `js/libs/encrypt.js` | RSA PKCS#1 v1.5 + DES3 (legacy) |
| `js/libs/cryptoJS.min.js` | AES-CBC, MD5 |
| `js/app/url.js` | Base URL and `stok` |
| `js/su/frame.js` | Main framework, request interceptor |
