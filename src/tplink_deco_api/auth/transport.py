"""Minimal HTTP transport with cookie tracking for the Deco router."""

from __future__ import annotations

import json
import logging
import re
import secrets
import ssl
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

from .._json import JsonObject, JsonValue, loads
from ..exceptions.transport import TransportError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from http.client import HTTPResponse

log: logging.Logger = logging.getLogger("tplink_deco_api.transport")

_COOKIE_RE = re.compile(r"(sysauth=[a-f0-9]+)")
_STOK_RE = re.compile(r"(?P<prefix>;stok=)[^/;?\s]+")


def _redact_session_token(url: str) -> str:
    """Replace a session token in an admin URL before logging or raising it."""
    return _STOK_RE.sub(r"\g<prefix><redacted>", url)


class HttpTransport:
    """POST JSON / form payloads to the router, tracking the ``sysauth`` cookie."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._cookie: str | None = None
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def post_json(self, url: str, body: Mapping[str, JsonValue]) -> JsonObject:
        """POST ``body`` as JSON and return the parsed response."""
        return self._post(url, json.dumps(body).encode())

    def post_form(self, url: str, body: str) -> JsonObject:
        """POST a pre-serialized form body and return the parsed response."""
        return self._post(url, body.encode())

    def post_bytes(
        self,
        url: str,
        body: bytes = b"",
        content_type: str = "application/json",
    ) -> bytes:
        """POST raw bytes and return the response without JSON decoding."""
        return self._request(url, body, content_type)

    def post_multipart_fields(
        self,
        url: str,
        fields: Mapping[str, str],
    ) -> bytes:
        """POST a multipart form containing scalar fields and return raw bytes."""
        boundary = f"----tplink-deco-api-{secrets.token_hex(12)}"
        body = _multipart_body(boundary, fields)
        return self._request(
            url,
            body,
            f"multipart/form-data; boundary={boundary}",
        )

    def clear_session(self) -> None:
        """Forget the captured router session cookie."""
        self._cookie = None

    def _post(self, url: str, data: bytes) -> JsonObject:
        return loads(self._request(url, data, "application/json"))

    def _request(self, url: str, data: bytes, content_type: str) -> bytes:
        headers = {"Content-Type": content_type}
        if self._cookie:
            headers["Cookie"] = self._cookie
        req = urllib.request.Request(url, data=data, headers=headers)
        safe_url = _redact_session_token(url)
        log.debug("POST %s (%d bytes)", safe_url, len(data))
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                self._capture_cookie(resp)
                response_body = resp.read()
                if not isinstance(response_body, bytes):
                    raise TransportError(f"Failed to POST {safe_url}: response is not bytes")
                return response_body
        except urllib.error.HTTPError as exc:
            raise TransportError(
                f"Failed to POST {safe_url}: HTTP {exc.code}",
                status_code=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise TransportError(f"Failed to POST {safe_url}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise TransportError(f"Failed to POST {safe_url}: timed out") from exc
        except OSError as exc:
            raise TransportError(f"Failed to POST {safe_url}: {exc}") from exc

    def _capture_cookie(self, resp: HTTPResponse) -> None:
        for header, value in resp.headers.items():
            if header.lower() == "set-cookie":
                match = _COOKIE_RE.search(value)
                if match:
                    self._cookie = match.group(1)
                    break


def _multipart_body(boundary: str, fields: Mapping[str, str]) -> bytes:
    if not fields:
        raise ValueError("Failed to encode multipart form: at least one field is required")
    parts: list[bytes] = []
    for name, value in fields.items():
        if not name or any(character in name for character in ('"', "\r", "\n")):
            raise ValueError("Failed to encode multipart form: field name is invalid")
        if "\r" in value or "\n" in value:
            raise ValueError("Failed to encode multipart form: field value is invalid")
        parts.extend(
            (
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            )
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)
