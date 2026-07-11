"""Payload encoding / decoding for the Deco auth protocol."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import quote_plus

from .._json import JsonObject, JsonValue, get_int, get_str
from ..crypto.aes import aes_decrypt, aes_encrypt
from ..crypto.rsa import rsa_encrypt
from ..exceptions.api import ApiError
from ..models.api_response import ApiResponse

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..models.rsa_key import RsaKey
    from ..models.session_keys import SessionKeys


def build_payload(
    keys: SessionKeys,
    sign_key: RsaKey,
    data: Mapping[str, JsonValue],
) -> str:
    """Encrypt + sign ``data`` and return the URL-encoded form body."""
    data_b64 = _encode_data(keys, data)
    sign = _encode_sign(keys, sign_key, len(data_b64))
    return f"sign={sign}&data={quote_plus(data_b64)}"


def parse_response(raw: JsonObject, keys: SessionKeys) -> JsonObject:
    """Decrypt the ``data`` field and return its ``result`` mapping."""
    return parse_encrypted_response(raw, keys).result_object()


def parse_encrypted_response(raw: JsonObject, keys: SessionKeys) -> ApiResponse:
    """Decrypt a response while preserving its complete firmware envelope."""
    data_b64 = raw.get("data")
    if not isinstance(data_b64, str) or not data_b64:
        raise ApiError(-1, "missing encrypted response data")
    decrypted_text = aes_decrypt(keys.aes_key, keys.aes_iv, data_b64)
    decoded = json.loads(_normalize_numeric_literals(decrypted_text))
    if not isinstance(decoded, dict):
        raise ApiError(-1, "decrypted response is not an object")
    decrypted: JsonObject = decoded
    _check_error(decrypted)
    return ApiResponse.from_api(decrypted)


def parse_plain_response(raw: JsonObject) -> JsonObject:
    """Return the ``result`` mapping of an un-encrypted response."""
    return parse_plain_envelope(raw).result_object()


def parse_plain_envelope(raw: JsonObject) -> ApiResponse:
    """Preserve a plaintext response envelope after checking its error code."""
    _check_error(raw)
    return ApiResponse.from_api(raw)


def parse_list_response(raw: JsonObject, keys: SessionKeys) -> list[JsonObject]:
    """Decrypt the ``data`` field and return its ``result`` as a list of objects."""
    return parse_encrypted_response(raw, keys).result_list()


def _encode_data(keys: SessionKeys, data: Mapping[str, JsonValue]) -> str:
    return aes_encrypt(
        keys.aes_key,
        keys.aes_iv,
        json.dumps(data, separators=(",", ":")),
    )


def _encode_sign(keys: SessionKeys, sign_key: RsaKey, data_len: int) -> str:
    seq_with_len = keys.seq + data_len
    sig_str = f"k={keys.aes_key}&i={keys.aes_iv}&h={keys.session_hash}&s={seq_with_len}"
    return rsa_encrypt(sign_key.n, sign_key.e, sig_str.encode())


def _normalize_numeric_literals(payload: str) -> str:
    literal = "Number.NaN"
    normalized: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(payload):
        character = payload[index]
        if in_string:
            normalized.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            normalized.append(character)
            index += 1
            continue
        if payload.startswith(literal, index):
            normalized.append("null")
            index += len(literal)
            continue
        normalized.append(character)
        index += 1
    return "".join(normalized)


def _check_error(response: JsonObject) -> None:
    code = get_int(response, "error_code") or get_int(response, "errorcode")
    if code:
        raise ApiError(code, get_str(response, "msg") or get_str(response, "message"))
