"""Optional keyring-backed token storage.

Requires `keyring` (install via `pip install helloagent[keyring]`).
Falls back with a clear error if the package is missing.
"""
from __future__ import annotations

_SERVICE = "helloagent"


def _kr():
    try:
        import keyring  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "keyring support not installed; `pip install helloagent[keyring]`"
        ) from e
    return keyring


def save_token(account: str, token: str) -> None:
    _kr().set_password(_SERVICE, account, token)


def load_token(account: str) -> str | None:
    return _kr().get_password(_SERVICE, account)


def delete_token(account: str) -> None:
    try:
        _kr().delete_password(_SERVICE, account)
    except Exception:
        pass
