"""
Teste de integração — requer roteador acessível e credenciais em .env

Execute:
    uv run pytest tests/test_login.py -v -s
"""
import os
import pathlib

import pytest

from tplink_deco import AuthenticationError, DecoClient


def _load_env() -> dict[str, str]:
    env_file = pathlib.Path(__file__).parent.parent / ".env"
    if not env_file.exists():
        return {}
    values: dict[str, str] = {}
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


_ENV = _load_env()
_HOST     = _ENV.get("DECO_HOST", "192.168.5.1")
_USERNAME = _ENV.get("DECO_USERNAME", "admin")
_PASSWORD = _ENV.get("DECO_PASSWORD", "")

pytestmark = pytest.mark.skipif(
    not _PASSWORD,
    reason="DECO_PASSWORD não definido em .env",
)


def test_login_retorna_stok():
    client = DecoClient(_HOST, _USERNAME, _PASSWORD)
    result = client.login()

    print(f"\n  stok={result.stok[:16]}...")
    print(f"  usr_lvl={result.usr_lvl}")

    assert result.stok
    assert isinstance(result.usr_lvl, int)


def test_login_credenciais_erradas():
    client = DecoClient(_HOST, _USERNAME, "senha_errada_xyz_123")
    with pytest.raises((AuthenticationError, Exception)):
        client.login()


def test_context_manager():
    with DecoClient(_HOST, _USERNAME, _PASSWORD) as deco:
        assert deco.is_authenticated()
    assert not deco.is_authenticated()


def test_get_device_mode():
    with DecoClient(_HOST, _USERNAME, _PASSWORD) as deco:
        mode = deco.get_device_mode()
        print(f"\n  mode={mode.mode!r}")
        print(f"  raw={mode.raw}")
        assert isinstance(mode.raw, dict)


def test_get_wlan_config():
    with DecoClient(_HOST, _USERNAME, _PASSWORD) as deco:
        wlan = deco.get_wlan_config()
        print(f"\n  raw={wlan.raw}")
        assert isinstance(wlan.raw, dict)


def test_get_device_list():
    with DecoClient(_HOST, _USERNAME, _PASSWORD) as deco:
        devices = deco.get_device_list()
        print(f"\n  devices={devices}")
        assert isinstance(devices, list)
