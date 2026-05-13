import asyncio
import json
import urllib.error

import pytest

import helloagent.client as client
from helloagent import Agent, AuthFailedError, UserClient, claim_handle, login_user, register_user
from helloagent.v1 import protocol_pb2 as pb


class FakeWS:
    def __init__(self, incoming=None):
        self.incoming = list(incoming or [])
        self.sent = []

    async def send(self, payload):
        self.sent.append(payload)

    async def recv(self):
        return self.incoming.pop(0)


class FakeSession:
    def __init__(self):
        self.encrypted = []
        self.decrypted = []

    def encrypt(self, plaintext: bytes) -> bytes:
        self.encrypted.append(plaintext)
        return b"cipher:" + plaintext

    def decrypt(self, wire: bytes) -> bytes:
        self.decrypted.append(wire)
        return b"decrypted text"


def _bytes(env: pb.Envelope) -> bytes:
    return env.SerializeToString()


def _auth_response(*, ok: bool = True, handle: str = "alice/jarvis") -> bytes:
    return _bytes(
        pb.Envelope(
            message_id="auth_1",
            ts_unix_ms=1,
            auth_response=pb.AuthResponse(ok=ok, handle=handle),
        )
    )


def _send_message(*, encrypted: bool = False) -> pb.Envelope:
    return pb.Envelope(
        message_id="in_1",
        ts_unix_ms=1,
        send_message=pb.SendMessage(
            conversation_id="conv_1",
            from_handle="alice",
            to_handle="alice/jarvis",
            text="" if encrypted else "hello",
            encrypted_body=b"wire" if encrypted else b"",
            is_encrypted=encrypted,
        ),
    )


@pytest.mark.asyncio
async def test_connect_once_sends_auth_request_and_updates_server_handle(monkeypatch):
    ws = FakeWS([_auth_response(handle="server/handle")])

    async def fake_connect(url, max_size):
        assert url == "ws://relay.test/v1/ws"
        assert max_size == 2**20
        return ws

    monkeypatch.setattr(client.websockets, "connect", fake_connect)
    agent = Agent("ha_test", relay_url="ws://relay.test/v1/ws")

    await agent._connect_once()

    assert agent.ws is ws
    assert agent.handle == "server/handle"
    env = pb.Envelope()
    env.ParseFromString(ws.sent[0])
    assert env.auth_request.token == "ha_test"
    assert env.auth_request.role == pb.ROLE_AGENT


@pytest.mark.asyncio
async def test_connect_once_raises_terminal_auth_failure(monkeypatch):
    ws = FakeWS([_auth_response(ok=False, handle="")])

    async def fake_connect(*_args, **_kwargs):
        return ws

    monkeypatch.setattr(client.websockets, "connect", fake_connect)
    agent = Agent("ha_test")

    with pytest.raises(AuthFailedError):
        await agent._connect_once()


@pytest.mark.asyncio
async def test_agent_loop_dispatches_inbound_send_messages(monkeypatch):
    agent = Agent("ha_test")
    incoming = [_send_message()]
    created = []

    async def fake_recv():
        if incoming:
            return incoming.pop(0)
        raise RuntimeError("stop")

    def fake_create_task(coro):
        created.append(coro)
        coro.close()
        return object()

    agent._recv = fake_recv
    monkeypatch.setattr(asyncio, "create_task", fake_create_task)

    with pytest.raises(RuntimeError, match="stop"):
        await agent._loop()

    assert len(created) == 1


@pytest.mark.asyncio
async def test_base_recv_parses_next_websocket_envelope():
    inbound = _send_message()
    agent = Agent("ha_test")
    agent.ws = FakeWS([inbound.SerializeToString()])

    received = await agent._recv()

    assert received.message_id == inbound.message_id
    assert received.send_message.text == inbound.send_message.text


@pytest.mark.asyncio
async def test_agent_run_reconnects_with_backoff(monkeypatch, caplog):
    agent = Agent("ha_test")
    calls = []

    async def fake_connect_once():
        calls.append("connect")

    async def fake_loop():
        calls.append("loop")
        raise RuntimeError("socket dropped")

    async def fake_sleep(delay):
        calls.append(("sleep", delay))
        raise StopAsyncIteration

    agent._connect_once = fake_connect_once
    agent._loop = fake_loop
    monkeypatch.setattr(client.asyncio, "sleep", fake_sleep)

    with pytest.raises(StopAsyncIteration):
        await agent.run()

    assert calls == ["connect", "loop", ("sleep", 1)]
    assert "reconnecting in 1s" in caplog.text


def test_agent_connect_runs_async_run(monkeypatch):
    agent = Agent("ha_test")
    calls = []

    def fake_run(coro):
        calls.append(coro)
        coro.close()

    monkeypatch.setattr(client.asyncio, "run", fake_run)

    agent.connect()

    assert len(calls) == 1


@pytest.mark.asyncio
async def test_encrypted_message_without_session_is_dropped(caplog):
    agent = Agent("ha_test")
    sent = []

    async def fake_send(env):
        sent.append(env)

    agent._send = fake_send

    await agent._handle(_send_message(encrypted=True))

    assert sent == []
    assert "no session" in caplog.text


@pytest.mark.asyncio
async def test_encrypted_inbound_text_and_reply_chunks_use_session():
    agent = Agent("ha_test")
    agent.handle = "alice/jarvis"
    sent = []
    session = FakeSession()
    agent.set_peer_session("alice", session)

    async def fake_send(env):
        sent.append(env)

    agent._send = fake_send

    @agent.on_message
    def handler(msg):
        assert msg.text == "decrypted text"
        return "secret reply"

    await agent._handle(_send_message(encrypted=True))

    assert session.decrypted == [b"wire"]
    assert session.encrypted == [b"secret reply"]
    assert [env.WhichOneof("payload") for env in sent] == ["ack", "stream_chunk"]
    chunk = sent[1].stream_chunk
    assert chunk.is_encrypted is True
    assert chunk.encrypted_body == b"cipher:secret reply"
    assert chunk.body == ""


@pytest.mark.asyncio
async def test_user_client_send_builds_plain_message_with_default_conversation():
    user = UserClient(handle="alice")
    user.ws = FakeWS()

    message_id = await user.send("alice/jarvis", "hello")

    env = pb.Envelope()
    env.ParseFromString(user.ws.sent[0])
    assert env.message_id == message_id
    assert env.send_message.conversation_id == "alice:alice/jarvis"
    assert env.send_message.from_handle == "alice"
    assert env.send_message.to_handle == "alice/jarvis"
    assert env.send_message.text == "hello"


@pytest.mark.asyncio
async def test_user_client_send_encrypts_when_peer_session_exists():
    user = UserClient(handle="alice")
    user.ws = FakeWS()
    session = FakeSession()
    user.set_peer_session("alice/jarvis", session)

    await user.send("alice/jarvis", "hello", conversation_id="conv_1")

    env = pb.Envelope()
    env.ParseFromString(user.ws.sent[0])
    assert session.encrypted == [b"hello"]
    assert env.send_message.conversation_id == "conv_1"
    assert env.send_message.is_encrypted is True
    assert env.send_message.encrypted_body == b"cipher:hello"
    assert env.send_message.text == ""


@pytest.mark.asyncio
async def test_user_client_connect_and_recv_delegate_to_base_methods():
    user = UserClient(handle="alice")
    connected = []
    inbound = _send_message()

    async def fake_connect_once():
        connected.append(True)

    async def fake_recv():
        return inbound

    user._connect_once = fake_connect_once
    user._recv = fake_recv

    await user.connect()

    assert connected == [True]
    assert await user.recv() is inbound


def test_user_client_requires_handle_or_token():
    with pytest.raises(ValueError, match="handle or token required"):
        UserClient()


def test_agent_token_sets_empty_handle_until_server_authenticates():
    assert Agent("ha_test").handle == ""
    assert Agent("legacy-handle").handle == "legacy-handle"


def test_agent_tool_decorator_registers_tool():
    agent = Agent("ha_test")

    @agent.tool(name="echo", description="Echo text")
    def echo(text: str) -> str:
        return text

    assert "echo" in agent.tools
    assert agent.tools["echo"].fn("hi") == "hi"
    assert agent.tools.schemas()[0]["name"] == "echo"


def test_removed_auth_helpers_raise_clear_error():
    with pytest.raises(NotImplementedError, match="Supabase Auth"):
        register_user("alice", "pw")

    with pytest.raises(NotImplementedError, match="Supabase Auth"):
        login_user("alice", "pw")


def test_claim_handle_posts_profile_and_decodes_json(monkeypatch):
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"handle": "alice"}).encode()

    def fake_urlopen(req):
        seen["url"] = req.full_url
        seen["headers"] = dict(req.header_items())
        seen["body"] = req.data
        return Response()

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)

    assert claim_handle("jwt", "alice", api="https://api.test") == {"handle": "alice"}
    assert seen["url"] == "https://api.test/v1/profile"
    assert seen["headers"]["Authorization"] == "Bearer jwt"
    assert json.loads(seen["body"]) == {"handle": "alice"}


def test_claim_handle_surfaces_http_error_body(monkeypatch):
    def fake_urlopen(_req):
        raise urllib.error.HTTPError(
            url="https://api.test/v1/profile",
            code=409,
            msg="conflict",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="409:"):
        claim_handle("jwt", "alice", api="https://api.test")


def test_http_json_posts_json_and_surfaces_http_errors(monkeypatch):
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"ok": True}).encode()

    def fake_urlopen(req):
        seen["url"] = req.full_url
        seen["headers"] = dict(req.header_items())
        seen["body"] = req.data
        return Response()

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)

    assert client._http_json("https://api.test/endpoint", {"x": 1}) == {"ok": True}
    assert seen["url"] == "https://api.test/endpoint"
    assert json.loads(seen["body"]) == {"x": 1}

    def fake_error(_req):
        raise urllib.error.HTTPError(
            url="https://api.test/endpoint",
            code=418,
            msg="teapot",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_error)

    with pytest.raises(RuntimeError, match="418:"):
        client._http_json("https://api.test/endpoint", {"x": 1})
