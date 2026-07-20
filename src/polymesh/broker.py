"""A compact asyncio broker for local SDK testing and loopback development.

The production TypeScript broker remains the v0.1 routing authority.  This
Python broker intentionally implements the same selected-profile handshake,
token boundary, standard broker capabilities, and basic in-memory routing so
the Python SDK can be used end-to-end in tests and local applications.  It
does not claim durable routing, secure WSS enrollment, or v0.2 behaviour.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .auth import validate_runtime_token
from .errors import AuthenticationError, HandshakeError, TransportClosedError
from .protocol import (
    capability_contract_tuple,
    card_digest,
    create_envelope,
    derive_session_id,
    encode_record_text,
    envelope_semantic_digest,
    parse_strict_json,
    random_nonce,
    validate_envelope,
    validate_handshake_frame,
)
from .transport import (
    MAX_FRAME_BYTES,
    POLYMESH_PATH,
    PROTOCOL_SUBPROTOCOL,
    InMemoryTransport,
    WebSocketTransport,
    WireTransport,
    is_numeric_loopback_host,
)
from .types import (
    AgentCard,
    AgentCardBuilder,
    AgentIdentity,
    AgentRef,
    CardFrame,
    Envelope,
    InitiatorHello,
    ReadyFrame,
    ResponderHello,
    TaskAcceptedParams,
    TaskCompletedParams,
    TaskRejectedParams,
    parse_timestamp,
    utc_now_millis,
)


@dataclass(slots=True)
class BrokerPeer:
    """One live loopback peer after its `ready` barrier."""

    transport: WireTransport
    identity: AgentIdentity
    card: AgentCard
    session_id: str
    task: asyncio.Task[None]


class PolyMeshBroker:
    """Minimal v0.1 loopback broker and in-memory integration harness."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 7337,
        token: str,
        card: AgentCard | None = None,
        agent_id: str = "org.polymesh.broker",
        allow_insecure_loopback_development: bool = False,
    ) -> None:
        if not allow_insecure_loopback_development or not is_numeric_loopback_host(host):
            raise AuthenticationError(
                "INSECURE_TRANSPORT_DISABLED",
                "Python loopback broker requires explicit numeric-loopback development mode",
            )
        self.host = host
        self._requested_port = port
        self.token = validate_runtime_token(token)
        self.card = card or AgentCardBuilder(agent_id).display_name("PolyMesh Python Broker").build()
        self._card_digest = card_digest(self.card)
        self._server: Any | None = None
        self._port: int | None = None
        self._closing = False
        self._peers: dict[tuple[str, str], BrokerPeer] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._lock = asyncio.Lock()

    @property
    def port(self) -> int | None:
        return self._port

    @property
    def url(self) -> str | None:
        if self._port is None:
            return None
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"ws://{host}:{self._port}{POLYMESH_PATH}"

    @property
    def peers(self) -> tuple[BrokerPeer, ...]:
        return tuple(self._peers.values())

    async def start(self) -> "PolyMeshBroker":
        """Start a token-authenticated WebSocket listener for local use."""

        if self._server is not None:
            return self
        try:
            from websockets.asyncio.server import serve
        except ImportError:  # pragma: no cover - compatibility with websockets 13
            from websockets.server import serve  # type: ignore[no-redef]

        async def handler(connection: Any) -> None:
            request = getattr(connection, "request", None)
            headers = getattr(request, "headers", None)
            if headers is None:
                headers = getattr(connection, "request_headers", {})
            path = getattr(request, "path", None)
            if path is None:
                path = getattr(connection, "path", None)
            if path != POLYMESH_PATH:
                with contextlib.suppress(Exception):
                    await connection.close(code=1008, reason="invalid path")
                return
            try:
                supplied_token = headers.get("x-polymesh-token")
                token_matches = isinstance(supplied_token, str) and secrets.compare_digest(
                    supplied_token, self.token
                )
            except (AttributeError, TypeError):
                token_matches = False
            if not token_matches:
                with contextlib.suppress(Exception):
                    await connection.close(code=1008, reason="authentication failed")
                return
            if getattr(connection, "subprotocol", None) != PROTOCOL_SUBPROTOCOL:
                with contextlib.suppress(Exception):
                    await connection.close(code=1002, reason="subprotocol mismatch")
                return
            transport = WebSocketTransport(connection, max_frame_bytes=MAX_FRAME_BYTES)
            task = self.accept_transport(transport)
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        self._server = await serve(
            handler,
            self.host,
            self._requested_port,
            subprotocols=[PROTOCOL_SUBPROTOCOL],
            compression=None,
            max_size=MAX_FRAME_BYTES,
            max_queue=16,
            ping_interval=None,
            ping_timeout=None,
        )
        sockets = getattr(self._server, "sockets", ())
        if not sockets:
            raise RuntimeError("WebSocket broker did not expose a bound socket")
        self._port = int(sockets[0].getsockname()[1])
        return self

    async def close(self) -> None:
        """Stop listener and fence/cancel every local peer task."""

        if self._closing:
            return
        self._closing = True
        server, self._server = self._server, None
        if server is not None:
            server.close()
            wait_closed = getattr(server, "wait_closed", None)
            if wait_closed is not None:
                with contextlib.suppress(Exception):
                    await wait_closed()
        peers = list(self._peers.values())
        for peer in peers:
            with contextlib.suppress(Exception):
                await peer.transport.close(1001, "broker closed")
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._peers.clear()
        self._tasks.clear()

    async def __aenter__(self) -> "PolyMeshBroker":
        return await self.start()

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    def create_in_memory_transport(self) -> InMemoryTransport:
        """Return the client end of a freshly scheduled in-memory session."""

        client, server = InMemoryTransport.pair()
        self.accept_transport(server)
        return client

    def accept_transport(self, transport: WireTransport) -> asyncio.Task[None]:
        """Schedule responder handshake over an already-open injected carrier."""

        task = asyncio.create_task(self._serve_transport(transport), name="polymesh-broker-peer")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _receive(self, transport: WireTransport) -> Any:
        raw = await transport.recv()
        return parse_strict_json(raw, max_bytes=MAX_FRAME_BYTES)

    async def _send(self, transport: WireTransport, record: Any) -> None:
        await transport.send(encode_record_text(record))

    async def _serve_transport(self, transport: WireTransport) -> None:
        peer: BrokerPeer | None = None
        try:
            initial = validate_handshake_frame(await self._receive(transport))
            if not isinstance(initial, InitiatorHello):
                raise HandshakeError("HANDSHAKE_FAILED", "expected initiator hello")
            if initial.security_profile is not None:
                raise HandshakeError("SECURITY_PROFILE_MISMATCH", "loopback broker does not offer secure WSS")
            if initial.agent_id == self.card.agent_id and initial.instance_id == self.card.instance_id:
                raise HandshakeError("SELF_CONNECTION", "an agent cannot connect to itself")

            responder_nonce = random_nonce()
            sid = derive_session_id(initial.nonce, responder_nonce)
            hello = ResponderHello(
                type="hello",
                role="responder",
                agent_id=self.card.agent_id,
                instance_id=self.card.instance_id,
                nonce=responder_nonce,
                echo=initial.nonce,
                sid=sid,
            )
            await self._send(transport, hello)

            card_frame = validate_handshake_frame(await self._receive(transport))
            if not isinstance(card_frame, CardFrame):
                raise HandshakeError("HANDSHAKE_FAILED", "expected card frame")
            if card_frame.sid != sid or card_frame.for_nonce != responder_nonce:
                raise HandshakeError("HANDSHAKE_FAILED", "card frame does not bind this session")
            if card_frame.card.agent_id != initial.agent_id or card_frame.card.instance_id != initial.instance_id:
                raise HandshakeError("SOURCE_IDENTITY_MISMATCH", "card does not match hello identity")
            if datetime.fromisoformat(card_frame.card.expires_at[:-1] + "+00:00") <= datetime.now(UTC):
                raise HandshakeError("CARD_EXPIRED", "peer card has expired")
            peer_card_digest = card_digest(card_frame.card)
            if card_frame.digest.lower() != peer_card_digest:
                raise HandshakeError("CARD_DIGEST_MISMATCH", "card frame digest does not match card")
            await self._send(
                transport,
                CardFrame(
                    type="card",
                    sid=sid,
                    for_nonce=initial.nonce,
                    digest=self._card_digest,
                    card=self.card,
                ),
            )

            ready = validate_handshake_frame(await self._receive(transport))
            if not isinstance(ready, ReadyFrame):
                raise HandshakeError("HANDSHAKE_FAILED", "expected ready frame")
            if ready.sid != sid or ready.self_card != peer_card_digest or ready.peer_card != self._card_digest:
                raise HandshakeError("HANDSHAKE_FAILED", "ready frame does not bind exchanged cards")
            await self._send(
                transport,
                ReadyFrame(type="ready", sid=sid, self_card=self._card_digest, peer_card=peer_card_digest),
            )

            identity = AgentIdentity(agent_id=initial.agent_id, instance_id=initial.instance_id)
            current = asyncio.current_task()
            assert current is not None
            peer = BrokerPeer(transport=transport, identity=identity, card=card_frame.card, session_id=sid, task=current)
            await self._register_peer(peer)
            while not self._closing and not transport.closed:
                value = await self._receive(transport)
                envelope = validate_envelope(value)
                if envelope.source != peer.identity:
                    await self._send_error(peer, envelope.message_id, "SOURCE_IDENTITY_MISMATCH", "source does not match the active session")
                    continue
                await self._route_envelope(peer, envelope)
        except TransportClosedError:
            # A carrier close is the ordinary termination path for an
            # in-memory or WebSocket peer.  The task is intentionally
            # consumed by the broker's background registry, so do not leave
            # an unobserved exception behind during normal client shutdown.
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            # Do not reflect arbitrary malformed bytes over an unauthenticated
            # handshake. Once active, callers receive bounded errors above.
            with contextlib.suppress(Exception):
                await transport.close(1002, "protocol error")
        finally:
            if peer is not None:
                await self._remove_peer(peer)
            with contextlib.suppress(Exception):
                await transport.close(1000, "broker session closed")

    async def _register_peer(self, peer: BrokerPeer) -> None:
        key = (peer.identity.agent_id, peer.identity.instance_id)
        async with self._lock:
            prior = self._peers.get(key)
            self._peers[key] = peer
        if prior is not None and prior is not peer:
            with contextlib.suppress(Exception):
                await prior.transport.close(1008, "instance replaced")

    async def _remove_peer(self, peer: BrokerPeer) -> None:
        key = (peer.identity.agent_id, peer.identity.instance_id)
        async with self._lock:
            if self._peers.get(key) is peer:
                self._peers.pop(key, None)

    async def _find_target(self, target: AgentRef) -> BrokerPeer | None:
        async with self._lock:
            if target.instance_id is not None:
                return self._peers.get((target.agent_id, target.instance_id))
            choices = [peer for key, peer in self._peers.items() if key[0] == target.agent_id]
        return min(choices, key=lambda peer: peer.identity.instance_id) if choices else None

    async def _route_envelope(self, source: BrokerPeer, envelope: Envelope) -> None:
        # Only an enrolled secure broker may append provenance while routing.
        # This loopback broker neither signs nor accepts a sender-supplied
        # attachment, so it must reject one before any target sees it.
        if envelope.provenance is not None:
            await self._send_error(
                source,
                envelope.message_id,
                "ROUTED_PROVENANCE_INVALID",
                "sender-supplied routed provenance is not permitted",
                category="identity",
            )
            await self._send_receipt(source, envelope, "rejected")
            return
        if envelope.type == "task.submit" and parse_timestamp(envelope.delivery.deadline) <= datetime.now(UTC):
            await self._send_error(
                source,
                envelope.message_id,
                "PMX.TASK.DEADLINE_EXCEEDED",
                "task deadline has elapsed",
                category="task",
            )
            await self._send_receipt(source, envelope, "rejected")
            return
        if envelope.type == "receipt":
            return  # Receipts are non-recursive broker-local observations.
        if envelope.target.agent_id == self.card.agent_id:
            if envelope.target.instance_id not in {None, self.card.instance_id}:
                await self._send_error(source, envelope.message_id, "TARGET_UNAVAILABLE", "target broker instance is unavailable")
                await self._send_receipt(source, envelope, "rejected")
                return
            if envelope.type == "ping":
                await self._send_pong(source, envelope)
                await self._send_receipt(source, envelope, "accepted")
                return
            if envelope.type == "task.submit":
                await self._handle_broker_task(source, envelope)
                await self._send_receipt(source, envelope, "accepted")
                return

        target = await self._find_target(envelope.target)
        if target is None:
            await self._send_error(source, envelope.message_id, "TARGET_UNAVAILABLE", "target agent is unavailable")
            await self._send_receipt(source, envelope, "rejected")
            return
        await self._send(target.transport, envelope)
        await self._send_receipt(source, envelope, "accepted")

    async def _send_receipt(self, peer: BrokerPeer, received: Envelope, disposition: str) -> None:
        await self._send(
            peer.transport,
            create_envelope(
                type="receipt",
                source=AgentIdentity(agent_id=self.card.agent_id, instance_id=self.card.instance_id),
                target=peer.identity,
                in_reply_to=received.message_id,
                params={
                    "received_message_id": received.message_id,
                    "semantic_digest": envelope_semantic_digest(received),
                    "disposition": disposition,
                },
            ),
        )

    async def _send_error(
        self,
        peer: BrokerPeer,
        in_reply_to: str,
        code: str,
        message: str,
        *,
        category: str = "routing",
    ) -> None:
        await self._send(
            peer.transport,
            create_envelope(
                type="error",
                source=AgentIdentity(agent_id=self.card.agent_id, instance_id=self.card.instance_id),
                target=peer.identity,
                in_reply_to=in_reply_to,
                params={
                    "category": category,
                    "code": code,
                    "message": message,
                    "retryable": False,
                    "retry_after_ms": None,
                },
            ),
        )

    async def _send_pong(self, peer: BrokerPeer, ping: Envelope) -> None:
        await self._send(
            peer.transport,
            create_envelope(
                type="pong",
                source=AgentIdentity(agent_id=self.card.agent_id, instance_id=self.card.instance_id),
                target=peer.identity,
                in_reply_to=ping.message_id,
                params={"n": ping.params["n"]},
            ),
        )

    async def _handle_broker_task(self, peer: BrokerPeer, submit: Envelope) -> None:
        params = submit.params
        task_id = str(params["task_id"])
        method = str(params["method"])
        capability = next((item for item in self.card.capabilities if item.id == method), None)
        if capability is None:
            rejected = TaskRejectedParams(task_id=task_id, event_seq=1, code="UNSUPPORTED_CAPABILITY", message="broker does not implement this capability")
            await self._send(
                peer.transport,
                create_envelope(
                    type="task.rejected",
                    source=AgentIdentity(agent_id=self.card.agent_id, instance_id=self.card.instance_id),
                    target=peer.identity,
                    in_reply_to=submit.message_id,
                    deadline=submit.delivery.deadline,
                    params=rejected.model_dump(mode="json"),
                ),
            )
            return
        contract = capability_contract_tuple(capability)
        if (
            params.get("capability_version") != contract.capability_version
            or params.get("capability_contract_digest") != contract.capability_contract_digest
        ):
            rejected = TaskRejectedParams(task_id=task_id, event_seq=1, code="CAPABILITY_CONTRACT_MISMATCH", message="submitted capability contract is not advertised")
            await self._send(
                peer.transport,
                create_envelope(
                    type="task.rejected",
                    source=AgentIdentity(agent_id=self.card.agent_id, instance_id=self.card.instance_id),
                    target=peer.identity,
                    in_reply_to=submit.message_id,
                    deadline=submit.delivery.deadline,
                    params=rejected.model_dump(mode="json"),
                ),
            )
            return
        if method == "org.polymesh.agent.ping":
            result: Any = {}
        elif method == "org.polymesh.agent.info":
            result = self.card.model_dump(mode="json", exclude_none=True)
        else:
            result = [{"id": item.id, "version": item.version} for item in self.card.capabilities]
        accepted = TaskAcceptedParams(
            task_id=task_id,
            event_seq=1,
            accepted_at=utc_now_millis(),
            **contract.model_dump(mode="json"),
        )
        completed = TaskCompletedParams(
            task_id=task_id,
            event_seq=2,
            **contract.model_dump(mode="json"),
            terminal={"outcome": "succeeded", "result": result, "completed_at": utc_now_millis()},
        )
        broker_identity = AgentIdentity(agent_id=self.card.agent_id, instance_id=self.card.instance_id)
        await self._send(
            peer.transport,
            create_envelope(
                type="task.accepted",
                source=broker_identity,
                target=peer.identity,
                in_reply_to=submit.message_id,
                deadline=submit.delivery.deadline,
                params=accepted.model_dump(mode="json"),
            ),
        )
        await self._send(
            peer.transport,
            create_envelope(
                type="task.completed",
                source=broker_identity,
                target=peer.identity,
                deadline=submit.delivery.deadline,
                params=completed.model_dump(mode="json"),
            ),
        )


InMemoryBroker = PolyMeshBroker


__all__ = ["BrokerPeer", "InMemoryBroker", "PolyMeshBroker"]
