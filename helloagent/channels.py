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


def link(provider: str, user_jwt: str, agent_name: Optional[str] = None,
         api: str = DEFAULT_API) -> dict:
    """Provision a channel agent for the authenticated user.

    `agent_name` is the user-chosen suffix of the agent handle: passing
    "jarvis" for owner @alice yields handle @alice/jarvis. Required for every
    link. Reusing the same name conflicts with the existing handle; choose a
    new name to create another provider-backed agent.

    Returns {provider, handle, agent_name, display_name, user_handle, token,
    relay_ws}. The `token` is shown once; store it locally on the provider.
    """
    body: dict = {}
    if agent_name is not None:
        body["agent_name"] = agent_name
    _, payload = _req("POST", f"{api}/v1/channels/{provider}/link", user_jwt, body=body)
    return payload


def list_channels(user_jwt: str, api: str = DEFAULT_API) -> list[dict]:
    _, payload = _req("GET", f"{api}/v1/channels", user_jwt)
    return payload or []


def unlink(provider: str, user_jwt: str, api: str = DEFAULT_API) -> None:
    """Remove all linked agents for this provider owned by the authenticated user."""
    _req("DELETE", f"{api}/v1/channels/{provider}", user_jwt)


# --- OAuth helpers (channel providers act as OAuth clients) ---


def oauth_authorize(user_jwt: str, client_id: str, redirect_uri: str,
                    scope: str = "channel:link", state: str = "",
                    api: str = DEFAULT_API, code_challenge: Optional[str] = None,
                    code_challenge_method: str = "S256") -> dict:
    """User-agent step: exchange the user's session JWT for an auth code
    bound to (client_id, redirect_uri, scope). Returns {code, state, redirect_url}.
    """
    body = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }
    if code_challenge:
        body["code_challenge"] = code_challenge
        body["code_challenge_method"] = code_challenge_method
    _, payload = _req("POST", f"{api}/oauth/authorize", user_jwt, body=body)
    return payload


def oauth_token(client_id: str, client_secret: Optional[str], code: str, redirect_uri: str,
                api: str = DEFAULT_API, code_verifier: Optional[str] = None) -> dict:
    """Provider-side step: exchange an auth code for a scoped access token.
    POSTs form-encoded per RFC 6749. Returns {access_token, token_type, expires_in, scope}.
    """
    import urllib.parse
    fields = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }
    if client_secret is not None:
        fields["client_secret"] = client_secret
    if code_verifier is not None:
        fields["code_verifier"] = code_verifier
    form = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(f"{api}/oauth/token", data=form, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode() if e.fp else ""
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"code": "http", "message": raw}
        raise RuntimeError(f"{e.code} {payload.get('code')}: {payload.get('message')}") from None


def oauth_device_authorize(client_id: str, scope: str = "channel:link",
                           api: str = DEFAULT_API) -> dict:
    _, payload = _req("POST", f"{api}/oauth/device/authorize", "", body={
        "client_id": client_id,
        "scope": scope,
    })
    return payload


def oauth_device_approve(user_jwt: str, client_id: str, user_code: str,
                         api: str = DEFAULT_API) -> dict:
    _, payload = _req("POST", f"{api}/oauth/device/approve", user_jwt, body={
        "client_id": client_id,
        "user_code": user_code,
    })
    return payload


def oauth_device_token(client_id: str, device_code: str,
                       api: str = DEFAULT_API) -> dict:
    import urllib.parse
    form = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": device_code,
    }).encode()
    req = urllib.request.Request(f"{api}/oauth/token", data=form, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode() if e.fp else ""
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"code": "http", "message": raw}
        raise RuntimeError(f"{e.code} {payload.get('code')}: {payload.get('message')}") from None
