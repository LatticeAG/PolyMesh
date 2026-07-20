from __future__ import annotations

import asyncio
import base64
import json

import pytest

from polymesh.broker import PolyMeshBroker
from polymesh.client import PolyMeshClient
from polymesh.errors import ContractMismatchError, TaskRejectedError, TransportClosedError
from polymesh.protocol import (
    card_digest,
    capability_contract_tuple,
    create_envelope,
    derive_session_id,
    encode_record_text,
    parse_strict_json,
    random_nonce,
    uuidv7,
    validate_envelope,
    validate_handshake_frame,
)
from polymesh.transport import InMemoryTransport
from polymesh.types import (
    AgentCardBuilder,
    AgentIdentity,
    AgentRef,
    CapabilityBuilder,
    CardFrame,
    ClientPhase,
    InitiatorHello,
    ReadyFrame,
    ResponderHello,
    TaskStatus,
    TaskStatusSnapshotParams,
    utc_now_millis,
)


def _token() -> str:
    return base64.urlsafe_b64encode(b"p" * 32).decode("ascii").rstrip("=")


async def _wait_for_peer_count(broker: PolyMeshBroker, count: int) -> None:
    for _ in range(100):
        if len(broker.peers) >= count:
            return
        await asyncio.sleep(0)
    raise AssertionError(f"broker did not register {count} in-memory peer(s)")


@pytest.mark.asyncio
async def test_python_broker_in_memory_hello_card_ready_and_ping() -> None:
    broker = PolyMeshBroker(token=_token(), allow_insecure_loopback_development=True)
    transport = broker.create_in_memory_transport()
    card = AgentCardBuilder("example.handshake-client").build()
    identity = AgentIdentity(agent_id=card.agent_id, instance_id=card.instance_id)
    initiator_nonce = random_nonce()
    try:
        initiator_hello = InitiatorHello(
            type="hello",
            role="initiator",
            agent_id=identity.agent_id,
            instance_id=identity.instance_id,
            nonce=initiator_nonce,
        )
        await transport.send(encode_record_text(initiator_hello))

        responder = validate_handshake_frame(parse_strict_json(await transport.recv()))
        assert isinstance(responder, ResponderHello)
        assert responder.echo == initiator_nonce
        assert responder.sid == derive_session_id(initiator_nonce, responder.nonce)

        await transport.send(
            encode_record_text(
                CardFrame(
                    type="card",
                    sid=responder.sid,
                    for_nonce=responder.nonce,
                    digest=card_digest(card),
                    card=card,
                )
            )
        )
        broker_card = validate_handshake_frame(parse_strict_json(await transport.recv()))
        assert isinstance(broker_card, CardFrame)
        assert broker_card.sid == responder.sid
        assert broker_card.for_nonce == initiator_nonce

        await transport.send(
            encode_record_text(
                ReadyFrame(
                    type="ready",
                    sid=responder.sid,
                    self_card=card_digest(card),
                    peer_card=card_digest(broker.card),
                )
            )
        )
        ready = validate_handshake_frame(parse_strict_json(await transport.recv()))
        assert isinstance(ready, ReadyFrame)
        assert ready.sid == responder.sid
        assert ready.self_card == card_digest(broker.card)
        assert ready.peer_card == card_digest(card)

        ping = create_envelope(
            type="ping",
            source=identity,
            target=AgentRef(agent_id=broker.card.agent_id, instance_id=broker.card.instance_id),
            params={"n": 42},
        )
        await transport.send(encode_record_text(ping))
        pong = validate_envelope(parse_strict_json(await transport.recv()))
        receipt = validate_envelope(parse_strict_json(await transport.recv()))
        assert pong.type == "pong"
        assert pong.params == {"n": 42}
        assert receipt.type == "receipt"
        assert receipt.in_reply_to == ping.message_id
        assert receipt.params["received_message_id"] == ping.message_id
    finally:
        await transport.close()
        await broker.close()


@pytest.mark.asyncio
async def test_python_broker_rejects_a_card_frame_with_a_wrong_digest() -> None:
    """The responder must not reach `ready` with an unbound peer Card."""

    broker = PolyMeshBroker(token=_token(), allow_insecure_loopback_development=True)
    transport = broker.create_in_memory_transport()
    card = AgentCardBuilder("example.bad-card-digest").build()
    identity = AgentIdentity(agent_id=card.agent_id, instance_id=card.instance_id)
    initiator_nonce = random_nonce()
    try:
        await transport.send(
            encode_record_text(
                InitiatorHello(
                    type="hello",
                    role="initiator",
                    agent_id=identity.agent_id,
                    instance_id=identity.instance_id,
                    nonce=initiator_nonce,
                )
            )
        )
        responder = validate_handshake_frame(parse_strict_json(await transport.recv()))
        assert isinstance(responder, ResponderHello)

        malformed = CardFrame(
            type="card",
            sid=responder.sid,
            for_nonce=responder.nonce,
            digest=card_digest(card),
            card=card,
        ).model_dump(mode="json", exclude_none=True)
        malformed["digest"] = "0" * 64
        assert malformed["digest"] != card_digest(card)
        await transport.send(json.dumps(malformed))

        with pytest.raises(TransportClosedError):
            await asyncio.wait_for(transport.recv(), timeout=1)
        assert transport.close_code == 1002
    finally:
        await broker.close()


@pytest.mark.asyncio
async def test_client_calls_in_memory_broker_ping_through_full_lifecycle() -> None:
    broker = PolyMeshBroker(token=_token(), allow_insecure_loopback_development=True)
    client = PolyMeshClient(
        card=AgentCardBuilder("example.client-owner").build(),
        transport_factory=broker.create_in_memory_transport,
        default_timeout=2,
    )
    try:
        assert await client.connect() is client
        assert client.phase is ClientPhase.ACTIVE
        assert client.connected
        assert client.broker_identity is not None
        assert client.broker_identity.agent_id == broker.card.agent_id
        await _wait_for_peer_count(broker, 1)

        handle = await client.call(broker.card.agent_id, "org.polymesh.agent.ping", {}, timeout=2)
        assert await asyncio.wait_for(handle.result(), timeout=2) == {}
        assert handle.status is TaskStatus.COMPLETED
        assert handle.last_event_seq == 2
    finally:
        await client.disconnect()
        await broker.close()


@pytest.mark.asyncio
async def test_clients_route_registered_handler_through_in_memory_broker() -> None:
    broker = PolyMeshBroker(token=_token(), allow_insecure_loopback_development=True)
    capability = (
        CapabilityBuilder("org.example.echo")
        .schemas(
            input_schema={
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
                "additionalProperties": False,
            },
            result_schema={
                "type": "object",
                "properties": {"echo": {"type": "string"}},
                "required": ["echo"],
                "additionalProperties": False,
            },
        )
        .execution(idempotency="idempotent", side_effects="none", cancellation="supported")
        .build()
    )
    executor = PolyMeshClient(
        card=AgentCardBuilder("example.handler").capability(capability).build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        authorization=lambda *_: True,
        default_timeout=2,
    )
    owner = PolyMeshClient(
        card=AgentCardBuilder("example.owner").build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        authorization=lambda *_: True,
        default_timeout=2,
    )
    observed: list[tuple[str, str]] = []
    progress: list[dict[str, str]] = []

    @executor.handle(capability.id)
    async def echo(input_value: dict, context) -> dict:
        observed.append((context.task_id, input_value["message"]))
        assert context.generation == executor._generation
        context.progress({"state": "running"})
        return {"echo": input_value["message"]}

    try:
        await executor.connect()
        await owner.connect()
        await _wait_for_peer_count(broker, 2)

        result = await asyncio.wait_for(
            owner.call_with_result(
                executor.card.agent_id,
                capability.id,
                {"message": "hello mesh"},
                capability_contract=capability,
                on_progress=progress.append,
                timeout=2,
            ),
            timeout=2,
        )
        assert result == {"echo": "hello mesh"}
        assert len(observed) == 1
        assert observed[0][1] == "hello mesh"
        assert progress == [{"state": "running"}]
    finally:
        await owner.disconnect()
        await executor.disconnect()
        await broker.close()


@pytest.mark.asyncio
async def test_query_status_emits_status_query_and_returns_advisory_snapshot() -> None:
    """A status query is an ordinary ``task.status`` envelope, not a ping."""

    client_transport, peer_transport = InMemoryTransport.pair()
    client_card = AgentCardBuilder("example.status-owner").build()
    peer_card = AgentCardBuilder("example.status-peer").build()
    peer_identity = AgentIdentity(agent_id=peer_card.agent_id, instance_id=peer_card.instance_id)
    task_id = uuidv7()
    received: dict[str, object] = {}

    async def peer() -> None:
        hello = validate_handshake_frame(parse_strict_json(await peer_transport.recv()))
        assert isinstance(hello, InitiatorHello)
        responder_nonce = random_nonce()
        sid = derive_session_id(hello.nonce, responder_nonce)
        await peer_transport.send(
            encode_record_text(
                ResponderHello(
                    type="hello",
                    role="responder",
                    agent_id=peer_identity.agent_id,
                    instance_id=peer_identity.instance_id,
                    nonce=responder_nonce,
                    echo=hello.nonce,
                    sid=sid,
                )
            )
        )
        frame = validate_handshake_frame(parse_strict_json(await peer_transport.recv()))
        assert isinstance(frame, CardFrame)
        await peer_transport.send(
            encode_record_text(
                CardFrame(
                    type="card",
                    sid=sid,
                    for_nonce=hello.nonce,
                    digest=card_digest(peer_card),
                    card=peer_card,
                )
            )
        )
        ready = validate_handshake_frame(parse_strict_json(await peer_transport.recv()))
        assert isinstance(ready, ReadyFrame)
        await peer_transport.send(
            encode_record_text(
                ReadyFrame(
                    type="ready",
                    sid=sid,
                    self_card=card_digest(peer_card),
                    peer_card=card_digest(client_card),
                )
            )
        )
        query = validate_envelope(parse_strict_json(await peer_transport.recv()))
        received["query"] = query
        assert query.type == "task.status"
        assert query.target == AgentRef(agent_id=peer_identity.agent_id, instance_id=peer_identity.instance_id)
        assert query.params == {"kind": "query", "task_id": task_id}
        snapshot = create_envelope(
            type="task.status",
            source=peer_identity,
            target=AgentIdentity(agent_id=client_card.agent_id, instance_id=client_card.instance_id),
            in_reply_to=query.message_id,
            deadline=query.delivery.deadline,
            params={
                "kind": "snapshot",
                "task_id": task_id,
                "observed_at": utc_now_millis(),
                "state": "accepted",
                "event_seq": 1,
            },
        )
        await peer_transport.send(encode_record_text(snapshot))

    peer_task = asyncio.create_task(peer())
    client = PolyMeshClient(card=client_card, default_timeout=1)
    try:
        await client.connect_transport(client_transport)
        snapshot = await asyncio.wait_for(
            client.query_status(
                peer_identity.agent_id,
                task_id,
                target_instance_id=peer_identity.instance_id,
                timeout=1,
            ),
            timeout=1,
        )
        assert isinstance(snapshot, TaskStatusSnapshotParams)
        assert snapshot.task_id == task_id
        assert snapshot.state == "accepted"
        assert received["query"] is not None
        await peer_task
    finally:
        if not peer_task.done():
            peer_task.cancel()
        await asyncio.gather(peer_task, return_exceptions=True)
        await client.disconnect()


@pytest.mark.asyncio
async def test_executor_ignores_forged_cancel_from_non_owner() -> None:
    """Only the task's pinned owner may cancel the executor-side local task."""

    broker = PolyMeshBroker(token=_token(), allow_insecure_loopback_development=True)
    capability = CapabilityBuilder("org.example.slow-result").build()
    executor = PolyMeshClient(
        card=AgentCardBuilder("example.cancel-executor").capability(capability).build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        authorization=lambda *_: True,
        default_timeout=2,
    )
    owner = PolyMeshClient(
        card=AgentCardBuilder("example.cancel-owner").build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        default_timeout=2,
    )
    attacker = PolyMeshClient(
        card=AgentCardBuilder("example.cancel-attacker").build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        default_timeout=2,
    )
    started = asyncio.Event()
    release = asyncio.Event()

    @executor.handle(capability.id)
    async def slow_result(_: dict, context) -> dict:
        started.set()
        await release.wait()
        context.raise_if_cancelled()
        return {"ok": True}

    try:
        await executor.connect()
        await owner.connect()
        await attacker.connect()
        await _wait_for_peer_count(broker, 3)
        handle = await owner.call(
            executor.card.agent_id,
            capability.id,
            {},
            capability_contract=capability,
            timeout=2,
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        forged = create_envelope(
            type="task.cancel",
            source=AgentIdentity(agent_id=attacker.card.agent_id, instance_id=attacker.card.instance_id),
            target=AgentRef(agent_id=executor.card.agent_id, instance_id=executor.card.instance_id),
            deadline=owner._pending_by_task[handle.task_id].deadline,
            params={"task_id": handle.task_id, "reason": "forged"},
        )
        await attacker._send_record(forged, generation=attacker._generation)
        # Let the broker forward the cancellation and the executor dispatch
        # it before proving that the foreign owner did not fence this task.
        for _ in range(20):
            await asyncio.sleep(0)
        local = executor._local_tasks.get(handle.task_id)
        assert local is not None
        assert not local.cancelled.is_set()
        release.set()
        assert await asyncio.wait_for(handle.result(), timeout=1) == {"ok": True}
        assert handle.status is TaskStatus.COMPLETED
    finally:
        await owner.disconnect()
        await attacker.disconnect()
        await executor.disconnect()
        await broker.close()


@pytest.mark.asyncio
async def test_declared_but_unhandled_capability_is_rejected_before_execution() -> None:
    """An advertised custom capability needs an admitted local handler."""

    broker = PolyMeshBroker(token=_token(), allow_insecure_loopback_development=True)
    capability = CapabilityBuilder("org.example.unhandled").build()
    executor = PolyMeshClient(
        card=AgentCardBuilder("example.unhandled-executor").capability(capability).build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        authorization=lambda *_: True,
        default_timeout=2,
    )
    owner = PolyMeshClient(
        card=AgentCardBuilder("example.unhandled-owner").build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        default_timeout=2,
    )
    try:
        await executor.connect()
        await owner.connect()
        await _wait_for_peer_count(broker, 2)
        handle = await owner.call(
            executor.card.agent_id,
            capability.id,
            {},
            capability_contract=capability,
            timeout=2,
        )
        with pytest.raises(TaskRejectedError):
            await asyncio.wait_for(handle.result(), timeout=1)
        assert handle.status is TaskStatus.REJECTED
    finally:
        await owner.disconnect()
        await executor.disconnect()
        await broker.close()


@pytest.mark.asyncio
async def test_explicit_capability_version_and_digest_can_pin_nondefault_contract() -> None:
    """A routed caller may know a verified tuple without retaining the full Card."""

    broker = PolyMeshBroker(token=_token(), allow_insecure_loopback_development=True)
    capability = (
        CapabilityBuilder("org.example.tuple-contract")
        .schemas(
            input_schema={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            result_schema={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
        )
        .build()
    )
    executor = PolyMeshClient(
        card=AgentCardBuilder("example.tuple-executor").capability(capability).build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        authorization=lambda *_: True,
        default_timeout=2,
    )
    owner = PolyMeshClient(
        card=AgentCardBuilder("example.tuple-owner").build(),
        transport_factory=broker.create_in_memory_transport,
        allow_insecure_loopback_development=True,
        default_timeout=2,
    )

    @executor.handle(capability.id)
    async def echo(input_value: dict, _: object) -> dict:
        return {"value": input_value["value"]}

    try:
        await executor.connect()
        await owner.connect()
        await _wait_for_peer_count(broker, 2)
        contract = capability_contract_tuple(capability)
        with pytest.raises(ContractMismatchError):
            await owner.call(
                executor.card.agent_id,
                capability.id,
                {"value": "pinned"},
                capability_contract=capability,
                result_schema={"type": "string"},
                timeout=2,
            )
        result = await asyncio.wait_for(
            owner.call_with_result(
                executor.card.agent_id,
                capability.id,
                {"value": "pinned"},
                capability_version=contract.capability_version,
                capability_contract_digest=contract.capability_contract_digest,
                result_schema=capability.result_schema,
                timeout=2,
            ),
            timeout=1,
        )
        assert result == {"value": "pinned"}
    finally:
        await owner.disconnect()
        await executor.disconnect()
        await broker.close()
