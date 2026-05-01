import hashlib
import math
import secrets
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import CryptoError

_AES_KEY_BYTES = 16
_AES_KEY_MIN   = 10 ** (_AES_KEY_BYTES - 1)   # garante 16 dígitos sem zero à esquerda
_AES_KEY_MAX   = (10 ** _AES_KEY_BYTES) - 1


def generate_aes_pair() -> tuple[str, str]:
    key = str(secrets.randbelow(_AES_KEY_MAX - _AES_KEY_MIN) + _AES_KEY_MIN)
    iv  = str(secrets.randbelow(_AES_KEY_MAX - _AES_KEY_MIN) + _AES_KEY_MIN)
    return key, iv


def md5_session_hash(username: str, password: str) -> str:
    return hashlib.md5((username + password).encode()).hexdigest()


def aes_encrypt(key: str, iv: str, plaintext: str) -> str:
    """AES-128-CBC + PKCS7. Retorna base64."""
    key_b = key.encode()
    iv_b  = iv.encode()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_b), modes.CBC(iv_b))
    enc = cipher.encryptor()
    return b64encode(enc.update(padded) + enc.finalize()).decode()


def aes_decrypt(key: str, iv: str, ciphertext_b64: str) -> str:
    try:
        ct = b64decode(ciphertext_b64)
        cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
        dec = cipher.decryptor()
        raw = dec.update(ct) + dec.finalize()
        n_pad = raw[-1]
        return raw[:-n_pad].decode()
    except Exception as exc:
        raise CryptoError(f"Falha ao decifrar AES: {exc}") from exc


def rsa_encrypt(n: int, e: int, plaintext: bytes) -> str:
    """RSA PKCS#1 v1.5 — divide em blocos de (key_bytes - 11) bytes. Retorna hex."""
    block_size      = (int(math.log2(n)) + 8) >> 3  # bytes da chave
    bytes_per_block = block_size - 11
    result = ""
    for i in range(0, len(plaintext), bytes_per_block):
        result += _rsa_encrypt_block(n, e, block_size, plaintext[i : i + bytes_per_block])
    return result


def _rsa_encrypt_block(n: int, e: int, k: int, block: bytes) -> str:
    if len(block) > k - 11:
        raise CryptoError(f"Bloco RSA muito longo: {len(block)} > {k - 11}")
    pad_len = k - len(block) - 3
    pad = b""
    while len(pad) < pad_len:
        byte = secrets.token_bytes(1)
        if byte != b"\x00":
            pad += byte
    em = b"\x00\x02" + pad + b"\x00" + block
    ct = pow(int.from_bytes(em, "big"), e, n)
    return format(ct, f"0{k * 2}x")  # zero-pad para k bytes (2k hex chars)
