# tplink-deco-api

SDK Python para controle de roteadores **TP-Link Deco** (mesh Wi-Fi) via API HTTP interna.

## Instalação

```bash
pip install tplink-deco-api
```

## Uso

```python
from tplink_deco_api import DecoClient

with DecoClient("192.168.68.1", "admin", "sua-senha") as deco:
    for client in deco.get_client_list():
        print(client.name, client.ip, client.connection_type)
```

## Métodos disponíveis

| Método | Retorno |
|--------|---------|
| `login()` | `LoginResult` |
| `get_device_list()` | `list[Device]` |
| `get_device_mode()` | `DeviceMode` |
| `get_wlan_config()` | `WlanConfig` |
| `get_performance()` | `Performance` |
| `get_client_list(deco_mac?)` | `list[ClientDevice]` |

## Modelos

Todos os métodos retornam dataclasses tipadas — sem dicionários genéricos.

```python
client.mac              # "AA:BB:CC:DD:EE:FF"
client.name             # "MacBook Pro"
client.ip               # "192.168.68.10"
client.connection_type  # "band6"
client.online           # True

device.device_model     # "BE65"
device.software_ver     # "1.2.10 Build 20251229"

wlan.band2_4.host.ssid      # "Minha Rede"
wlan.band2_4.guest.password # "senha-visitas"

perf.cpu_usage  # 0.03
perf.mem_usage  # 0.42
```

## Requisitos

- Python 3.11+
- Roteador TP-Link Deco acessível na rede local
