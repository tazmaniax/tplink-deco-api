# TP-Link Deco — Protocolo de Autenticação

Documentação do protocolo HTTP proprietário usado pela interface web do roteador TP-Link Deco (testado em `192.168.5.1`). Obtida por engenharia reversa dos arquivos JavaScript do firmware.

---

## Visão geral

Toda comunicação usa `POST` com `Content-Type: application/json` para:

```
http://<router-ip>/cgi-bin/luci/;stok=<TOKEN>/<endpoint>?form=<form>
```

O `stok` é vazio antes do login (`/;stok=/`) e preenchido depois.

Requisições autenticadas têm o payload cifrado com **AES-128-CBC** e assinado com **RSA PKCS#1 v1.5** — exceto os endpoints listados na seção [Endpoints sem criptografia](#endpoints-sem-criptografia).

---

## Fluxo de login

### Passo 1 — Obter chaves RSA

Duas chamadas em paralelo, ambas sem criptografia:

#### `POST /login?form=auth`

```json
{ "operation": "read" }
```

Resposta:
```json
{
  "result": {
    "key": ["<modulus_hex>", "010001"],
    "seq": 766218342
  },
  "error_code": 0
}
```

- **Chave RSA 512-bit** usada para assinar o campo `sign` de todas as requisições
- **`seq`** é um contador de sessão; incrementa a cada request

#### `POST /login?form=keys`

```json
{ "operation": "read" }
```

Resposta:
```json
{
  "result": {
    "username": "",
    "password": ["<modulus_hex>", "010001"]
  },
  "error_code": 0
}
```

- **Chave RSA 1024-bit** usada para cifrar a senha no payload de login

---

### Passo 2 — Preparar o encryptor

```python
import secrets, hashlib

# Chave AES: 2 strings de 16 dígitos numéricos aleatórios
aes_key = "".join(secrets.choice("0123456789") for _ in range(16))
aes_iv  = "".join(secrets.choice("0123456789") for _ in range(16))

# String de identificação da chave AES (usada na assinatura)
aes_key_str = f"k={aes_key}&i={aes_iv}"
# ex: "k=1415950173028918&i=5652578606663031"

# Hash da sessão: MD5 do username concatenado com a senha
session_hash = hashlib.md5((username + password).encode()).hexdigest()
```

---

### Passo 3 — Enviar o login

#### Montar o payload

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
    """RSA PKCS#1 v1.5 — retorna hex lowercase."""
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
    """Divide em blocos de 53 chars (limite do RSA 512-bit com PKCS#1 v1.5)."""
    if len(sig_str) > 53:
        return (rsa_pkcs1v15_encrypt(n, e, sig_str[:53].encode()) +
                rsa_pkcs1v15_encrypt(n, e, sig_str[53:].encode()))
    return rsa_pkcs1v15_encrypt(n, e, sig_str.encode())

# Dados de login (cifrados com AES)
login_data = json.dumps({
    "operation": "login",
    "username":  username,
    "password":  password,   # senha plain-text (AES já protege o canal)
})
data_b64 = aes_encrypt(aes_key, aes_iv, login_data)

# String a assinar: inclui chave AES (isLogin=True)
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

Resposta (sucesso):
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

## Requisições autenticadas

Após o login, toda chamada usa o mesmo encryptor com `isLogin=False` (sem a chave AES na assinatura):

```python
# String a assinar: SEM chave AES
sig_str = f"h={session_hash}&s={seq + len(data_b64)}"

payload = {
    "sign": sign(sign_rsa_n, sign_rsa_e, sig_str),
    "data": aes_encrypt(aes_key, aes_iv, json.dumps(request_data)),
}

seq += 1  # incrementar a cada requisição
```

URL:
```
POST http://<ip>/cgi-bin/luci/;stok=<TOKEN>/admin/<endpoint>?form=<form>
```

---

## Parâmetros criptográficos

| Parâmetro | Valor |
|-----------|-------|
| AES modo | CBC |
| AES padding | PKCS7 |
| AES key size | 128-bit (16 chars numéricos) |
| RSA (sign) | 512-bit, PKCS#1 v1.5 |
| RSA (pwd) | 1024-bit, PKCS#1 v1.5 |
| RSA split | 53 chars por bloco |
| Hash sessão | MD5(username + password) |

---

## Endpoints sem criptografia

Estes endpoints recebem JSON puro (sem `sign`/`data`):

| Endpoint | Descrição |
|----------|-----------|
| `/login?form=auth` | RSA sign key + seq inicial |
| `/login?form=keys` | RSA password key |
| `/login?form=check_factory_default` | Verifica se está em fábrica |
| `/login?form=default_info` | SSID e senha padrão de fábrica |
| `/admin/system?form=envar` | Variáveis de ambiente |
| `/admin/system?form=sysmode` | Modo do sistema |
| `/admin/cloud?form=firmware` | Info de firmware cloud |
| `/admin/isp?form=isp_upgrade` | Upgrade via ISP |
| `/admin/firmware?form=config_multipart` | Config de firmware (multipart) |
| `/admin/log_export?form=save_log` | Exportar logs |

---

## Endpoints autenticados (descobertos)

| Endpoint | Descrição |
|----------|-----------|
| `/admin/device?form=mode` | Modo do dispositivo |
| `/admin/wireless?form=wlan` | Configuração Wi-Fi |
| `/admin/web?form=extra_component_info` | Info de componentes extras |
| `/admin/component_control?form=switch_list` | Lista de switches |

---

## Arquivos JavaScript relevantes do firmware

| Arquivo | Conteúdo |
|---------|----------|
| `js/libs/tpEncrypt.js` | Classe `encryptor` — orquestra AES + RSA |
| `js/libs/encrypt.js` | RSA PKCS#1 v1.5 + DES3 (legado) |
| `js/libs/cryptoJS.min.js` | AES-CBC, MD5 |
| `js/app/url.js` | Base URL e `stok` |
| `js/su/frame.js` | Framework principal, interceptor de requisições |