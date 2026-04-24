"""Thin HTTP helpers for the channel-linking API.

A "channel provider" is a hosted personal-agent product (e.g. OpenClaw) that
uses HelloAgent as a messaging surface. The user holds an account on both
sides; linking provisions a per-user agent on the relay, owned by the user,
and hands the one-time token to the provider to connect with.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional

from .client import DEFAULT_API


def _req(method: str, url: str, token: str, body: Optional[dict] = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            payload = json.loads(raw) if raw else {}
            return resp.status, payload
    except urllib.error.HTTPError as e:
        raw = e.read().decode() if e.fp else ""
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"code": "http", "message": raw}
        raise RuntimeError(f"{e.code} {payload.get('code')}: {payload.get('message')}") from None


def link(provider: str, user_jwt: str, api: str = DEFAULT_API) -> dict:
    """Provision (or rotate) a channel agent for the authenticated user.

    Returns {provider, handle, display_name, user_handle, token, relay_ws}.
    The `token` is shown once; store it server-side on the provider.
    """
    _, payload = _req("POST", f"{api}/v1/channels/{provider}/link", user_jwt, body={})
    return payload


def list_channels(user_jwt: str, api: str = DEFAULT_API) -> list[dict]:
    _, payload = _req("GET", f"{api}/v1/channels", user_jwt)
    return payload or []


def unlink(provider: str, user_jwt: str, api: str = DEFAULT_API) -> None:
    _req("DELETE", f"{api}/v1/channels/{provider}", user_jwt)


# --- OAuth helpers (channel providers act as OAuth clients) ---


def oauth_authorize(user_jwt: str, client_id: str, redirect_uri: str,
                    scope: str = "channel:link", state: str = "",
                    api: str = DEFAULT_API) -> dict:
    """User-agent step: exchange the user's session JWT for an auth code
    bound to (client_id, redirect_uri, scope). Returns {code, state, redirect_url}.
    """
    _, payload = _req("POST", f"{api}/oauth/authorize", user_jwt, body={
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    })
    return payload


def oauth_token(client_id: str, client_secret: str, code: str, redirect_uri: str,
                api: str = DEFAULT_API) -> dict:
    """Provider-side step: exchange an auth code for a scoped access token.
    POSTs form-encoded per RFC 6749. Returns {access_token, token_type, expires_in, scope}.
    """
    import urllib.parse
    form = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }).encode()
    req = urllib.request.Request(f"{api}/oauth/token", data=form, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode() if e.fp else ""
        raise RuntimeError(f"{e.code}: {raw}") from None
