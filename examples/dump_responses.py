#!/usr/bin/env python3
"""Capture non-secret SDK responses into ``docs/api-responses/``.

Usage::

    uv run examples/dump_responses.py

Login results and WLAN configuration are deliberately excluded because they
contain session tokens and Wi-Fi passwords. Prefer ``read_only_probe.py`` for
ordinary inventory collection.
"""

from __future__ import annotations

import dataclasses
import getpass
import json
import pathlib

_OUT = pathlib.Path(__file__).parent.parent / "docs" / "api-responses"


def _load_env() -> dict[str, str]:
    env_file = pathlib.Path(__file__).parent.parent / ".env"
    if not env_file.exists():
        return {}
    values: dict[str, str] = {}
    for line in env_file.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        values[key.strip()] = val.strip()
    return values


def _save(name: str, data: object) -> None:
    _OUT.mkdir(parents=True, exist_ok=True)
    path = _OUT / f"{name}.json"

    serializable: object
    if dataclasses.is_dataclass(data) and not isinstance(data, type):
        serializable = dataclasses.asdict(data)
    elif isinstance(data, list):
        serializable = [
            dataclasses.asdict(item)
            if dataclasses.is_dataclass(item) and not isinstance(item, type)
            else item
            for item in data
        ]
    else:
        serializable = data

    path.write_text(json.dumps(serializable, indent=2, ensure_ascii=False))
    print(f"  saved: {path.relative_to(pathlib.Path(__file__).parent.parent)}")


def main() -> None:
    env = _load_env()
    host = env.get("DECO_HOST", "192.168.5.1")
    username = env.get("DECO_USERNAME", "admin")
    password = getpass.getpass("Deco owner password: ")
    if not password:
        raise SystemExit("No password was supplied")

    from tplink_deco_api import DecoClient

    with DecoClient(host, username, password, timeout=60.0) as deco:
        _save("device_list", deco.get_device_list())
        _save("device_mode", deco.get_device_mode())
        _save("performance", deco.get_performance())
        _save("client_list", deco.get_client_list())
        _save("internet_status", deco.get_internet_status())
        _save("wan_info", deco.get_wan_info())
        _save("address_reservations", deco.get_address_reservations())

    print(f"\nDone. {len(list(_OUT.glob('*.json')))} files in docs/api-responses/")


if __name__ == "__main__":
    main()
