"""URL builders and the set of endpoints that skip the encrypted envelope."""

from __future__ import annotations

_PLAIN_ENDPOINTS: frozenset[str] = frozenset(
    {
        "/login?form=auth",
        "/login?form=keys",
        "/login?form=check_factory_default",
        "/login?form=default_info",
        "/admin/system?form=envar",
        "/admin/system?form=sysmode",
        "/admin/cloud?form=firmware",
        "/admin/isp?form=isp_upgrade",
        "/admin/firmware?form=config_multipart",
        "/admin/log_export?form=save_log",
    }
)


def is_plain(path_with_form: str) -> bool:
    """Return ``True`` if ``path_with_form`` does not use the AES envelope."""
    return path_with_form in _PLAIN_ENDPOINTS


def is_plain_endpoint(path: str, form: str) -> bool:
    """Return whether one normalized path/form pair uses plaintext JSON."""
    return is_plain(f"/{path.strip('/')}?form={form}")


def login_url(host: str, form: str) -> str:
    """Return the unauthenticated ``/login`` URL for the given ``form``."""
    return f"https://{host}/cgi-bin/luci/;stok=/login?form={form}"


def admin_url(host: str, stok: str, path: str, form: str) -> str:
    """Return the authenticated admin URL for ``path`` + ``form``."""
    return endpoint_url(host, stok, path, form)


def endpoint_url(host: str, stok: str, path: str, form: str | None) -> str:
    """Return an authenticated URL for any local controller path."""
    normalized_path = path.strip("/")
    url = f"https://{host}/cgi-bin/luci/;stok={stok}/{normalized_path}"
    return f"{url}?form={form}" if form is not None else url
