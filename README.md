# helloagent

Talk to the [HelloAgent](https://helloagent.cc) relay from Python. Pair, send, receive, and stream agent messages over a single long-lived WebSocket.

```bash
pip install helloagent
```

## Quickstart — Python agent

```python
import asyncio
import os
from helloagent import Agent

async def main():
    agent = Agent(
        token=os.environ["HELLOAGENT_TOKEN"],          # ha_* token
        relay_url="wss://api.helloagent.cc/v1/ws",
    )

    @agent.on_message
    async def reply(msg):
        print(f"{msg.from_handle}: {msg.text}")
        return f"you said: {msg.text}"                  # simple echo reply

    await agent.run()                                   # long-lived; reconnects on drop

asyncio.run(main())
```

Get an `ha_*` token from [https://app.helloagent.cc/app/agents/new](https://app.helloagent.cc/app/agents/new).

## Quickstart — user client

```python
from helloagent import UserClient

client = UserClient(
    handle="alice",
    token=sso_session_token,
    relay_url="wss://api.helloagent.cc/v1/ws",
)

@client.on_message
def handle(msg):
    ...  # render in your chat UI

await client.run()
await client.send("alice/jarvis", "what's on my calendar today?")
```

## What you get

- **`Agent`** — long-lived WebSocket connection authenticated with an `ha_*` token. Auto-reconnects with exponential backoff. Inbound messages are dispatched to a handler that returns a `str`, an awaitable, or an `AsyncIterator[str]` for streaming replies.
- **`UserClient`** — same transport, `ROLE_USER`. For user-facing surfaces.
- **`IncomingMessage`** — dataclass with `message_id`, `conversation_id`, `from_handle`, `to_handle`, `text`.
- **`AuthFailedError`** — raised when the relay rejects auth (`auth_response.ok=false`). Treat as terminal: re-pair, don't retry.
- **`Tool`, `ToolRegistry`** — register tools your agent can invoke.
- **`tokens`, `keystore`, `channels`, `discovery`** — auxiliary modules for token handling, key management, channel-link helpers, and agent discovery.

## Reconnect behavior

`Agent.run()` opens the WebSocket, sends `auth_request`, awaits `auth_response`, dispatches incoming messages to your `@on_message` handler, and reconnects on any disconnect. Exponential backoff: 1s → 30s, doubling on consecutive failures, reset after a successful auth. Terminate the run loop by cancelling the `asyncio` task.

## Authentication

The relay no longer hosts `/v1/auth/register` or `/v1/auth/login` — `register_user` and `login_user` are kept exported for back-compat but raise `NotImplementedError`. New code should sign in with `supabase-py` and pass the access token straight into `UserClient(token=..., handle=...)`. The helper `claim_handle(access_token, handle)` wraps `POST /v1/profile`.

## Compatibility

- Python ≥ 3.10
- Depends on `websockets>=11` and `protobuf>=4.21,<7`

## Versioning

Follows semver; pre-1.0 the protocol may shift between minor versions. The relay protocol itself is versioned via the `/v1/ws` URL path — bumping that is reserved for breaking wire-format changes.

## License

MIT
