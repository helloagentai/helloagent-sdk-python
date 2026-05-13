import pytest

from helloagent import Agent
from helloagent.v1 import protocol_pb2 as pb


def _incoming_env() -> pb.Envelope:
    return pb.Envelope(
        message_id="in_1",
        ts_unix_ms=123,
        send_message=pb.SendMessage(
            conversation_id="conv_1",
            from_handle="alice",
            to_handle="alice/jarvis",
            text="hello",
        ),
    )


def _capture_agent() -> tuple[Agent, list[pb.Envelope]]:
    agent = Agent("ha_test")
    agent.handle = "alice/jarvis"
    sent = []

    async def fake_send(env):
        sent.append(env)

    agent._send = fake_send
    return agent, sent


@pytest.mark.asyncio
async def test_none_handler_result_acks_without_reply_chunk():
    agent, sent = _capture_agent()

    @agent.on_message
    async def handler(msg):
        return None

    await agent._handle(_incoming_env())

    assert [env.WhichOneof("payload") for env in sent] == ["ack"]


@pytest.mark.asyncio
async def test_string_handler_result_sends_final_reply_chunk():
    agent, sent = _capture_agent()

    @agent.on_message
    async def handler(msg):
        return "hi"

    await agent._handle(_incoming_env())

    assert [env.WhichOneof("payload") for env in sent] == ["ack", "stream_chunk"]
    chunk = sent[1].stream_chunk
    assert chunk.body == "hi"
    assert chunk.is_final is True


@pytest.mark.asyncio
async def test_sync_none_handler_result_acks_without_reply_chunk():
    agent, sent = _capture_agent()

    @agent.on_message
    def handler(msg):
        return None

    await agent._handle(_incoming_env())

    assert [env.WhichOneof("payload") for env in sent] == ["ack"]


@pytest.mark.asyncio
async def test_missing_handler_only_acks():
    agent, sent = _capture_agent()

    await agent._handle(_incoming_env())

    assert [env.WhichOneof("payload") for env in sent] == ["ack"]


@pytest.mark.asyncio
async def test_async_generator_handler_streams_chunks_then_final_empty_chunk():
    agent, sent = _capture_agent()

    @agent.on_message
    async def handler(msg):
        yield "one"
        yield "two"

    await agent._handle(_incoming_env())

    assert [env.WhichOneof("payload") for env in sent] == [
        "ack",
        "stream_chunk",
        "stream_chunk",
        "stream_chunk",
    ]
    chunks = [env.stream_chunk for env in sent[1:]]
    assert [(chunk.body, chunk.is_final) for chunk in chunks] == [
        ("one", False),
        ("two", False),
        ("", True),
    ]


@pytest.mark.asyncio
async def test_agent_send_builds_send_message_envelope():
    class FakeWS:
        def __init__(self):
            self.payloads = []

        async def send(self, payload):
            self.payloads.append(payload)

    agent = Agent("ha_test")
    agent.handle = "alice/jarvis"
    agent.ws = FakeWS()

    message_id = await agent.send("bob", "hello", conversation_id="conv_1")

    assert message_id
    env = pb.Envelope()
    env.ParseFromString(agent.ws.payloads[0])
    assert env.message_id == message_id
    assert env.send_message.conversation_id == "conv_1"
    assert env.send_message.from_handle == "alice/jarvis"
    assert env.send_message.to_handle == "bob"
    assert env.send_message.text == "hello"


@pytest.mark.asyncio
async def test_agent_send_requires_connection():
    agent = Agent("ha_test")

    with pytest.raises(RuntimeError, match="agent not connected"):
        await agent.send("bob", "hello")
