from dataclasses import dataclass


@dataclass(frozen=True)
class RsaKey:
    n: int
    e: int

    @classmethod
    def from_hex(cls, modulus_hex: str, exponent_hex: str) -> "RsaKey":
        return cls(n=int(modulus_hex, 16), e=int(exponent_hex, 16))


@dataclass
class SessionKeys:
    aes_key: str   # 16 numeric chars
    aes_iv:  str   # 16 numeric chars
    session_hash: str  # MD5(username + password)
    seq: int


@dataclass(frozen=True)
class LoginResult:
    stok:    str
    usr_lvl: int = 1


@dataclass(frozen=True)
class DeviceMode:
    mode: str
    raw: dict


@dataclass(frozen=True)
class WlanConfig:
    raw: dict
