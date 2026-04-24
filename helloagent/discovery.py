"""Client for Tier 2 agent.json auto-discovery.

A user pastes a base URL; the relay fetches /.well-known/agent.json from
that origin, validates it against the v1 schema, and returns the manifest
plus a suggested handle. This step is preview-only — no persistence, no
outbound bridge yet.
"""
from __future__ import annotations

from typing import Optional

from .channels import _req  # same POST/JSON+Bearer helper
from .client import DEFAULT_API


def discover(url: str, user_jwt: str, auth_credential: Optional[str] = None,
             api: str = DEFAULT_API) -> dict:
    """Validate the agent.json manifest at `url` and return a preview.

    Returns {manifest, manifest_url, suggested_handle, auth_credential_set, warnings}.
    Raises RuntimeError for network errors or invalid manifests.
    """
    body: dict = {"url": url}
    if auth_credential:
        body["auth_credential"] = auth_credential
    _, payload = _req("POST", f"{api}/v1/discover", user_jwt, body=body)
    return payload
