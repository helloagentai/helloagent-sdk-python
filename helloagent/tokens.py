"""HelloAgent token format: `ha_{base62(payload)}`.

Payload layout per ConnectionSpec §9.2:
  32 bytes random entropy + 4 bytes big-endian unix timestamp + 2 bytes scope flags
"""
from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass

_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
PREFIX = "ha_"


def _b62_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    if n == 0:
        return _ALPHABET[0]
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(_ALPHABET[r])
    return "".join(reversed(out))


def _b62_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 62 + _ALPHABET.index(ch)
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


@dataclass(frozen=True)
class TokenPayload:
    entropy: bytes  # 32 bytes
    issued_at: int  # unix seconds
    scope_flags: int  # 16-bit

    def encode(self) -> str:
        if len(self.entropy) != 32:
            raise ValueError("entropy must be 32 bytes")
        raw = self.entropy + struct.pack(">IH", self.issued_at & 0xFFFFFFFF, self.scope_flags & 0xFFFF)
        return PREFIX + _b62_encode(raw)


def generate(scope_flags: int = 0) -> str:
    return TokenPayload(
        entropy=os.urandom(32),
        issued_at=int(time.time()),
        scope_flags=scope_flags,
    ).encode()


def parse(token: str) -> TokenPayload:
    if not token.startswith(PREFIX):
        raise ValueError(f"token missing {PREFIX!r} prefix")
    raw = _b62_decode(token[len(PREFIX):])
    # Left-pad in case leading zeros were stripped during encode.
    raw = raw.rjust(38, b"\x00")
    if len(raw) != 38:
        raise ValueError(f"decoded payload is {len(raw)} bytes, expected 38")
    entropy = raw[:32]
    issued_at, scope_flags = struct.unpack(">IH", raw[32:])
    return TokenPayload(entropy=entropy, issued_at=issued_at, scope_flags=scope_flags)


def is_ha_token(token: str) -> bool:
    return token.startswith(PREFIX)
