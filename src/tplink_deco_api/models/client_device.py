"""Client device connected to the mesh."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_bool, get_int, get_str
from ._utils import decode_b64, normalize_mac


@dataclass(frozen=True)
class ClientDevice:
    """A device currently or recently connected to the Deco mesh."""

    mac: str
    ip: str
    name: str
    up_speed: int
    down_speed: int
    wire_type: str
    connection_type: str
    space_id: str
    access_host: str
    interface: str
    client_type: str
    owner_id: str
    remain_time: int
    online: bool
    client_mesh: bool
    enable_priority: bool

    @classmethod
    def from_api(cls, data: JsonObject) -> ClientDevice:
        """Build ``ClientDevice`` from a router payload."""
        return cls(
            mac=normalize_mac(get_str(data, "mac")),
            ip=get_str(data, "ip"),
            name=decode_b64(get_str(data, "name")),
            up_speed=get_int(data, "up_speed"),
            down_speed=get_int(data, "down_speed"),
            wire_type=get_str(data, "wire_type"),
            connection_type=get_str(data, "connection_type"),
            space_id=get_str(data, "space_id"),
            access_host=get_str(data, "access_host"),
            interface=get_str(data, "interface"),
            client_type=get_str(data, "client_type"),
            owner_id=get_str(data, "owner_id"),
            remain_time=get_int(data, "remain_time"),
            online=get_bool(data, "online"),
            client_mesh=get_bool(data, "client_mesh"),
            enable_priority=get_bool(data, "enable_priority"),
        )
