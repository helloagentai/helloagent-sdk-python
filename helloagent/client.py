import asyncio
import inspect
import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Union, AsyncIterator

import websockets

from .v1 import protocol_pb2 as pb
from .crypto import Session
from .tools import ToolRegistry

log = logging.getLogger("helloagent")

DEFAULT_RELAY = "ws://localhost:8080/v1/ws"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class IncomingMessage:
    message_id: str
    conversation_id: str
    from_handle: str
    to_handle: str
    text: str


Handler = Callable[[IncomingMessage], Union[str, Awaitable[str], AsyncIterator[str]]]


class AuthFailedError(Exception):
    """Raised when the relay rejects our auth handshake (token revoked, rotated,
    agent deleted, etc). Distinct from generic socket / network errors so the
    run loop and callers can branch on it without parsing strings.
    """

    def __init__(self, detail: str):
        super().__init__(f"auth failed: {detail}")
        self.detail = detail


class _BaseConn:
    def __init__(self, handle: str, token: str, role: int, relay_url: str = DEFAULT_RELAY):
        self.handle = handle
        self.token = token
        self.role = role
        self.relay_url = relay_url
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        # handle -> Session; set via set_peer_session().
        self._sessions: dict[str, Session] = {}

    def set_peer_session(self, peer_handle: str, session: Session) -> None:
        """Register an encryption session for messages to/from this peer."""
        self._sessions[peer_handle] = session

    def _session_for(self, peer: str) -> Optional[Session]:
        return self._sessions.get(peer)

    async def _connect_once(self):
        self.ws = await websockets.connect(self.relay_url, max_size=2**20)
        auth = pb.Envelope(
            message_id=_new_id(), ts_unix_ms=_now_ms(),
            auth_request=pb.AuthRequest(token=self.token, handle=self.handle, role=self.role),
        )
        await self.ws.send(auth.SerializeToString())
        raw = await self.ws.recv()
        env = pb.Envelope(); env.ParseFromString(raw)
        if not env.HasField("auth_response") or not env.auth_response.ok:
            raise AuthFailedError(str(env))
        if env.auth_response.handle:
            self.handle = env.auth_response.handle
        log.info("authenticated as %s", self.handle)

    async def _send(self, env: pb.Envelope):
        await self.ws.send(env.SerializeToString())

    async def _recv(self) -> pb.Envelope:
        raw = await self.ws.recv()
        env = pb.Envelope(); env.ParseFromString(raw)
        return env


class Agent(_BaseConn):
    def __init__(self, token: str, handle: Optional[str] = None, relay_url: str = DEFAULT_RELAY):
        # For registered agents (token starts with "ha_"), the server resolves
        # the handle via bcrypt and echoes it back in AuthResponse; we send an
        # empty handle. For the legacy skeleton path, handle defaults to token.
        if handle is None:
            handle = "" if token.startswith("ha_") else token
        super().__init__(handle, token, pb.ROLE_AGENT, relay_url)
        self._handler: Optional[Handler] = None
        self.tools = ToolRegistry()

    def on_message(self, fn: Handler) -> Handler:
        self._handler = fn
        return fn

    async def send(self, to_handle: str, text: str, conversation_id: Optional[str] = None) -> str:
        """Proactively send a message (not as a reply). Returns the message id.

        Mirrors the TS SDK's `Agent.send()`. Useful for assistant-initiated
        outreach, cron-driven notifications, or cross-platform delivery via
        Hermes' send_message_tool. Requires the run loop to have authenticated
        the socket; raises if `self.ws` is not set.
        """
        if self.ws is None:
            raise RuntimeError("agent not connected")
        msg_id = _new_id()
        env = pb.Envelope(
            message_id=msg_id, ts_unix_ms=_now_ms(),
            send_message=pb.SendMessage(
                conversation_id=conversation_id or f"{self.handle}:{to_handle}",
                from_handle=self.handle,
                to_handle=to_handle,
                text=text,
            ),
        )
        await self._send(env)
        return msg_id

    def tool(self, *, name: Optional[str] = None, description: Optional[str] = None,
             parameters: Optional[dict] = None):
        """Register a tool callable. Exposed via `agent.tools` for the dev's LLM call."""
        def decorator(fn):
            self.tools.register(fn, name=name, description=description, parameters=parameters)
            return fn
        return decorator

    def connect(self):
        asyncio.run(self.run())

    async def run(self):
        backoff = 1
        while True:
            try:
                await self._connect_once()
                backoff = 1
                await self._loop()
            except Exception as e:
                log.warning("connection lost: %s; reconnecting in %ss", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def _loop(self):
        while True:
            env = await self._recv()
            if env.HasField("send_message"):
                asyncio.create_task(self._handle(env))

    async def _handle(self, env: pb.Envelope):
        msg = env.send_message
        text = msg.text
        if msg.is_encrypted and msg.encrypted_body:
            sess = self._session_for(msg.from_handle)
            if sess is None:
                log.warning("got encrypted msg from %s but no session", msg.from_handle)
                return
            text = sess.decrypt(msg.encrypted_body).decode("utf-8")
        incoming = IncomingMessage(
            message_id=env.message_id,
            conversation_id=msg.conversation_id,
            from_handle=msg.from_handle,
            to_handle=msg.to_handle,
            text=text,
        )
        # Ack from agent -> relay -> user (delivered)
        await self._send(pb.Envelope(
            message_id=_new_id(), ts_unix_ms=_now_ms(),
            ack=pb.Ack(ref_message_id=env.message_id),
        ))
        if self._handler is None:
            return
        result = self._handler(incoming)
        if inspect.isasyncgen(result):
            async for chunk in result:
                await self._send_chunk(incoming, env.message_id, chunk, False)
            await self._send_chunk(incoming, env.message_id, "", True)
        else:
            text = await result if inspect.isawaitable(result) else result
            await self._send_chunk(incoming, env.message_id, text or "", True)

    async def _send_chunk(self, incoming: IncomingMessage, ref_id: str, body: str, final: bool):
        sess = self._session_for(incoming.from_handle)
        if sess is not None and body:
            ct = sess.encrypt(body.encode("utf-8"))
            chunk = pb.StreamChunk(
                conversation_id=incoming.conversation_id,
                from_handle=self.handle,
                to_handle=incoming.from_handle,
                ref_message_id=ref_id,
                is_final=final,
                encrypted_body=ct,
                is_encrypted=True,
            )
        else:
            chunk = pb.StreamChunk(
                conversation_id=incoming.conversation_id,
                from_handle=self.handle,
                to_handle=incoming.from_handle,
                ref_message_id=ref_id,
                body=body,
                is_final=final,
            )
        env = pb.Envelope(
            message_id=_new_id(), ts_unix_ms=_now_ms(),
            stream_chunk=chunk,
        )
        await self._send(env)


DEFAULT_API = "http://localhost:8080"


def _http_json(url: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{e.code}: {e.read().decode()}") from None


def register_user(email: str, password: str, handle: str, api: str = DEFAULT_API) -> dict:
    return _http_json(f"{api}/v1/auth/register",
                      {"email": email, "password": password, "handle": handle})


def login_user(email: str, password: str, api: str = DEFAULT_API) -> dict:
    return _http_json(f"{api}/v1/auth/login", {"email": email, "password": password})


class UserClient(_BaseConn):
    """Minimal user-side client for the demo CLI.

    Provide `token=<jwt>` for real auth, or pass `handle=...` alone for the
    legacy skeleton path (token defaults to handle).
    """

    def __init__(self, handle: str = "", token: Optional[str] = None, relay_url: str = DEFAULT_RELAY):
        if not handle and not token:
            raise ValueError("handle or token required")
        super().__init__(handle or "", token or handle, pb.ROLE_USER, relay_url)

    async def connect(self):
        await self._connect_once()

    async def send(self, to_handle: str, text: str, conversation_id: Optional[str] = None) -> str:
        msg_id = _new_id()
        sess = self._session_for(to_handle)
        if sess is not None:
            ct = sess.encrypt(text.encode("utf-8"))
            sm = pb.SendMessage(
                conversation_id=conversation_id or f"{self.handle}:{to_handle}",
                from_handle=self.handle,
                to_handle=to_handle,
                encrypted_body=ct,
                is_encrypted=True,
            )
        else:
            sm = pb.SendMessage(
                conversation_id=conversation_id or f"{self.handle}:{to_handle}",
                from_handle=self.handle,
                to_handle=to_handle,
                text=text,
            )
        env = pb.Envelope(
            message_id=msg_id, ts_unix_ms=_now_ms(),
            send_message=sm,
        )
        await self._send(env)
        return msg_id

    async def recv(self) -> pb.Envelope:
        return await self._recv()
