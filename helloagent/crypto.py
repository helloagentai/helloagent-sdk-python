"""Minimal E2E encryption primitives.

This is NOT the Signal Protocol. It is a static X25519 + HKDF + AES-GCM
construction used to prove the wire format and SDK surface. Phase 2 will
replace `Session` with a Double Ratchet implementation; callers won't notice
because the API surface (encrypt/decrypt bytes) stays the same.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class KeyPair:
    private: x25519.X25519PrivateKey
    public: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = x25519.X25519PrivateKey.generate()
        return cls(private=sk, public=sk.public_key())

    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_bytes(self) -> bytes:
        return self.private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "KeyPair":
        sk = x25519.X25519PrivateKey.from_private_bytes(data)
        return cls(private=sk, public=sk.public_key())


def load_public(data: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(data)


class Session:
    """Symmetric AEAD channel derived from a static ECDH handshake.

    Replace with a ratcheting Session in Phase 2; the wire format stays the
    same (encrypted_body bytes, is_encrypted true).
    """

    def __init__(self, shared_secret: bytes, info: bytes = b"helloagent/e2e-v1"):
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(shared_secret)
        self._aead = AESGCM(key)

    @classmethod
    def from_keypair(cls, mine: KeyPair, peer_public: x25519.X25519PublicKey,
                     info: bytes = b"helloagent/e2e-v1") -> "Session":
        shared = mine.private.exchange(peer_public)
        return cls(shared, info=info)

    def encrypt(self, plaintext: bytes, associated: bytes | None = None) -> bytes:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext, associated)
        return nonce + ct

    def decrypt(self, wire: bytes, associated: bytes | None = None) -> bytes:
        if len(wire) < 12:
            raise ValueError("ciphertext too short")
        nonce, ct = wire[:12], wire[12:]
        return self._aead.decrypt(nonce, ct, associated)
