"""Clients reported by one Deco mesh node."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue
    from .client_device import ClientDevice


@dataclass(frozen=True)
class NodeClientList:
    """Associate the queried Deco node with the clients returned for its MAC."""

    node_mac: str
    clients: tuple[ClientDevice, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        """Return topology data in a JSON-compatible representation."""
        return {
            "node_mac": self.node_mac,
            "clients": [
                {
                    "mac": client.mac,
                    "ip": client.ip,
                    "name": client.name,
                    "up_speed": client.up_speed,
                    "down_speed": client.down_speed,
                    "wire_type": client.wire_type,
                    "connection_type": client.connection_type,
                    "space_id": client.space_id,
                    "access_host": client.access_host,
                    "interface": client.interface,
                    "client_type": client.client_type,
                    "owner_id": client.owner_id,
                    "remain_time": client.remain_time,
                    "online": client.online,
                    "client_mesh": client.client_mesh,
                    "enable_priority": client.enable_priority,
                }
                for client in self.clients
            ],
        }
