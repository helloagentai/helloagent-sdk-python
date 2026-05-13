import asyncio
import io
import json
import sys
import urllib.error
import urllib.parse

import pytest
from cryptography.hazmat.primitives import serialization

from helloagent import channels, discovery, keystore, tokens
from helloagent.crypto import KeyPair, Session, load_public
from helloagent.tools import ToolRegistry


class Response:
    def __init__(self, payload=None, *, status=200, raw=None):
        self.payload = payload
        self.status = status
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        if self.raw is not None:
            return self.raw
        return json.dumps(self.payload).encode()


def test_token_payload_roundtrip_and_generation(monkeypatch):
    entropy = bytes(range(32))
    payload = tokens.TokenPayload(entropy=entropy, issued_at=123, scope_flags=7)

    encoded = payload.encode()
    parsed = tokens.parse(encoded)

    assert tokens.is_ha_token(encoded) is True
    assert parsed == payload

    monkeypatch.setattr(tokens.os, "urandom", lambda size: b"x" * size)
    monkeypatch.setattr(tokens.time, "time", lambda: 456.9)

    generated = tokens.parse(tokens.generate(scope_flags=2))
    assert generated.entropy == b"x" * 32
    assert generated.issued_at == 456
    assert generated.scope_flags == 2


def test_token_validation_errors():
    assert tokens._b62_encode(b"\x00") == "0"

    with pytest.raises(ValueError, match="missing 'ha_' prefix"):
        tokens.parse("not-a-token")

    with pytest.raises(ValueError, match="entropy must be 32 bytes"):
        tokens.TokenPayload(entropy=b"short", issued_at=1, scope_flags=0).encode()

    with pytest.raises(ValueError, match="decoded payload is 39 bytes"):
        tokens.parse("ha_" + tokens._b62_encode(b"x" * 39))


def test_crypto_keypair_roundtrip_and_session_encryption():
    alice = KeyPair.generate()
    bob = KeyPair.generate()

    restored = KeyPair.from_private_bytes(alice.private_bytes())
    assert restored.public_bytes() == alice.public_bytes()
    assert load_public(bob.public_bytes()).public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) == bob.public_bytes()

    alice_session = Session.from_keypair(alice, bob.public)
    bob_session = Session.from_keypair(bob, alice.public)
    wire = alice_session.encrypt(b"hello", associated=b"conv_1")

    assert wire != b"hello"
    assert bob_session.decrypt(wire, associated=b"conv_1") == b"hello"

    with pytest.raises(ValueError, match="ciphertext too short"):
        bob_session.decrypt(b"short")


@pytest.mark.asyncio
async def test_tool_registry_infers_schema_and_invokes_sync_and_async_tools():
    registry = ToolRegistry()

    def add(count: int, label: str = "x") -> str:
        """Add a label."""
        return label * count

    async def double(value: int) -> int:
        return value * 2

    def method_like(self, value: bool):
        return value

    add_tool = registry.register(add)
    double_tool = registry.register(double, parameters={"type": "object"})
    method_tool = registry.register(method_like, name="method")

    assert len(registry) == 3
    assert "add" in registry
    assert [tool.name for tool in registry] == ["add", "double", "method"]
    assert add_tool.schema()["description"] == "Add a label."
    assert add_tool.schema()["parameters"] == {
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "label": {"type": "string"},
        },
        "required": ["count"],
    }
    assert await add_tool.invoke(count=3, label="a") == "aaa"
    assert await double_tool.invoke(value=4) == 8
    assert registry.schemas()[1]["parameters"] == {"type": "object"}
    assert method_tool.schema()["parameters"]["properties"] == {"value": {"type": "boolean"}}


def test_keystore_uses_keyring_module(monkeypatch):
    calls = []

    class FakeKeyring:
        @staticmethod
        def set_password(service, account, token):
            calls.append(("set", service, account, token))

        @staticmethod
        def get_password(service, account):
            calls.append(("get", service, account))
            return "ha_saved"

        @staticmethod
        def delete_password(service, account):
            calls.append(("delete", service, account))

    monkeypatch.setitem(sys.modules, "keyring", FakeKeyring)

    keystore.save_token("alice", "ha_saved")
    assert keystore.load_token("alice") == "ha_saved"
    keystore.delete_token("alice")

    assert calls == [
        ("set", "helloagent", "alice", "ha_saved"),
        ("get", "helloagent", "alice"),
        ("delete", "helloagent", "alice"),
    ]


def test_keystore_missing_keyring_has_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)

    with pytest.raises(RuntimeError, match="keyring support not installed"):
        keystore.save_token("alice", "ha_saved")


def test_keystore_delete_swallows_backend_errors(monkeypatch):
    class BrokenKeyring:
        @staticmethod
        def delete_password(_service, _account):
            raise RuntimeError("backend down")

    monkeypatch.setitem(sys.modules, "keyring", BrokenKeyring)

    keystore.delete_token("alice")


def test_channels_request_success_and_wrappers(monkeypatch):
    seen = []

    def fake_urlopen(req):
        seen.append(
            {
                "url": req.full_url,
                "method": req.get_method(),
                "headers": dict(req.header_items()),
                "body": req.data,
            }
        )
        if req.full_url.endswith("/channels"):
            return Response([{"provider": "openclaw"}])
        return Response({"ok": True, "token": "ha_test"}, status=201)

    monkeypatch.setattr(channels.urllib.request, "urlopen", fake_urlopen)

    assert channels.link("openclaw", "jwt", agent_name="jarvis", api="https://api.test") == {
        "ok": True,
        "token": "ha_test",
    }
    assert channels.list_channels("jwt", api="https://api.test") == [{"provider": "openclaw"}]
    assert channels.unlink("openclaw", "jwt", api="https://api.test") is None

    assert seen[0]["url"] == "https://api.test/v1/channels/openclaw/link"
    assert seen[0]["method"] == "POST"
    assert seen[0]["headers"]["Authorization"] == "Bearer jwt"
    assert json.loads(seen[0]["body"]) == {"agent_name": "jarvis"}
    assert seen[1]["method"] == "GET"
    assert seen[1]["body"] is None
    assert seen[2]["method"] == "DELETE"


def test_channels_request_handles_empty_json_and_http_errors(monkeypatch):
    monkeypatch.setattr(
        channels.urllib.request,
        "urlopen",
        lambda _req: Response(raw=b"", status=204),
    )
    assert channels.list_channels("jwt", api="https://api.test") == []

    def json_error(_req):
        raise urllib.error.HTTPError(
            url="https://api.test/v1/channels",
            code=400,
            msg="bad",
            hdrs=None,
            fp=io.BytesIO(b'{"code":"bad_request","message":"Nope"}'),
        )

    monkeypatch.setattr(channels.urllib.request, "urlopen", json_error)
    with pytest.raises(RuntimeError, match="400 bad_request: Nope"):
        channels.list_channels("jwt", api="https://api.test")

    def text_error(_req):
        raise urllib.error.HTTPError(
            url="https://api.test/v1/channels",
            code=500,
            msg="bad",
            hdrs=None,
            fp=io.BytesIO(b"plain failure"),
        )

    monkeypatch.setattr(channels.urllib.request, "urlopen", text_error)
    with pytest.raises(RuntimeError, match="500 http: plain failure"):
        channels.list_channels("jwt", api="https://api.test")


def test_oauth_helpers_build_expected_requests(monkeypatch):
    seen = []

    def fake_urlopen(req):
        seen.append(
            {
                "url": req.full_url,
                "method": req.get_method(),
                "headers": dict(req.header_items()),
                "body": req.data,
            }
        )
        return Response({"ok": True})

    monkeypatch.setattr(channels.urllib.request, "urlopen", fake_urlopen)

    assert channels.oauth_authorize(
        "jwt",
        "client",
        "http://localhost/cb",
        state="s1",
        code_challenge="challenge",
        api="https://api.test",
    ) == {"ok": True}
    assert channels.oauth_token(
        "client",
        "secret",
        "code",
        "http://localhost/cb",
        code_verifier="verifier",
        api="https://api.test",
    ) == {"ok": True}
    assert channels.oauth_device_authorize("client", api="https://api.test") == {"ok": True}
    assert channels.oauth_device_approve(
        "jwt",
        "client",
        "ABCD",
        api="https://api.test",
    ) == {"ok": True}
    assert channels.oauth_device_token("client", "device", api="https://api.test") == {"ok": True}

    assert seen[0]["url"] == "https://api.test/oauth/authorize"
    assert json.loads(seen[0]["body"])["code_challenge"] == "challenge"

    token_form = urllib.parse.parse_qs(seen[1]["body"].decode())
    assert token_form["client_secret"] == ["secret"]
    assert token_form["code_verifier"] == ["verifier"]
    token_headers = {key.lower(): value for key, value in seen[1]["headers"].items()}
    assert token_headers["content-type"] == "application/x-www-form-urlencoded"

    device_form = urllib.parse.parse_qs(seen[4]["body"].decode())
    assert device_form["grant_type"] == ["urn:ietf:params:oauth:grant-type:device_code"]


def test_oauth_token_helpers_surface_http_errors(monkeypatch):
    def json_error(_req):
        raise urllib.error.HTTPError(
            url="https://api.test/oauth/token",
            code=401,
            msg="bad",
            hdrs=None,
            fp=io.BytesIO(b'{"code":"invalid","message":"Bad code"}'),
        )

    monkeypatch.setattr(channels.urllib.request, "urlopen", json_error)

    with pytest.raises(RuntimeError, match="401 invalid: Bad code"):
        channels.oauth_token("client", None, "code", "http://localhost/cb")

    with pytest.raises(RuntimeError, match="401 invalid: Bad code"):
        channels.oauth_device_token("client", "device")

    def text_error(_req):
        raise urllib.error.HTTPError(
            url="https://api.test/oauth/token",
            code=502,
            msg="bad",
            hdrs=None,
            fp=io.BytesIO(b"proxy exploded"),
        )

    monkeypatch.setattr(channels.urllib.request, "urlopen", text_error)

    with pytest.raises(RuntimeError, match="502 http: proxy exploded"):
        channels.oauth_token("client", None, "code", "http://localhost/cb")

    with pytest.raises(RuntimeError, match="502 http: proxy exploded"):
        channels.oauth_device_token("client", "device")


def test_discovery_posts_manifest_preview_request(monkeypatch):
    seen = {}

    def fake_req(method, url, token, body=None):
        seen.update({"method": method, "url": url, "token": token, "body": body})
        return 200, {"suggested_handle": "alice/jarvis"}

    monkeypatch.setattr(discovery, "_req", fake_req)

    assert discovery.discover(
        "https://agent.test",
        "jwt",
        auth_credential="secret",
        api="https://api.test",
    ) == {"suggested_handle": "alice/jarvis"}
    assert seen == {
        "method": "POST",
        "url": "https://api.test/v1/discover",
        "token": "jwt",
        "body": {"url": "https://agent.test", "auth_credential": "secret"},
    }


def test_asyncio_import_is_real_for_async_tool_tests():
    assert asyncio.iscoroutinefunction(asyncio.sleep)
