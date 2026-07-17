# PolyMesh Protocol — Codex Design Review (gpt-5.6-terra)

> Generated: 2026-07-17  
> Model: gpt-5.6-terra  
> Session: 019f6e24-e969-7c43-8950-5a7396b5fd6c  
> Tokens used: 18,617

---

## Executive Summary

PolyMesh has a good product instinct: local-first agent interoperability should be much lighter than enterprise A2A stacks. The draft is readable, approachable, and its core primitives — Agent Card, capabilities, request/result, discovery — are sensible.

However, v0.1.0 is not yet sufficiently specified to produce interoperable or safe implementations. The biggest issue is that it promises delivery and delegation semantics without defining the protocol machinery needed to make those promises true. It also treats agent identity and local trust too casually for agents capable of email, filesystem writes, and shell execution.

**Recommendation:** Keep the narrow local-first scope, but make v0.1.0 a rigorous "direct, authenticated local RPC" protocol. Defer brokered offline delivery and remote support until their semantics can be fully specified.

---

## Priority Findings

| Priority | Finding | Why It Matters |
|----------|---------|----------------|
| **Critical** | `source` is self-asserted and unauthenticated | Any peer can impersonate another agent, including an approval proxy |
| **Critical** | "At-least-once" is not actually defined or achievable as written | A `result` is not an acknowledgement; retries, persistence, and duplicate-result behavior are unspecified |
| **Critical** | The protocol permits dangerous capabilities with no authorization contract | Capability declaration is not access control; `shell.exec`, `file.write`, `email.send` need explicit policy boundaries |
| **High** | Direct-connect discovery by port scanning and "start a broker after 5 seconds" is unsafe and race-prone | Causes unwanted listening services, port collisions, scans unrelated services, ambiguous topology |
| **High** | Broker mode has no routing, registration, authorization, queue, or failure semantics | Two compliant brokers could behave incompatibly |
| **High** | Wire format and examples contradict the required envelope | Minimal examples omit required fields, so they are invalid under the draft |
| **High** | No task lifecycle, cancellation, admission, queueing, or terminal-state model | Long-running and side-effecting tasks cannot be reliably managed |
| **Medium** | Discovery data is unauthenticated, underspecified, potentially too large for mDNS TXT | Discovery can be spoofed and service records can disagree with cards |
| **Medium** | Schema use is vague | JSON Schema dialect, validation rules, schema evolution, and error behavior are absent |
| **Medium** | Error model conflates protocol, transport, and application failures | Senders cannot safely decide whether to retry |
| **Medium** | Broadcast is underspecified and dangerous | No scope, fan-out, response aggregation, loop prevention, or authorization rules |

---

## 1. Message Envelope Design

### What Works
- Right basic correlation fields: `id`, `source`, `target`, `thread`, `reply_to`
- UUIDv7 for sortable request IDs
- JSON text frames as baseline

### Problems

**No explicit protocol version per message.** Version only in Agent Card and WebSocket subprotocol. Every message needs a version identifier.

**Requiredness is inconsistent.** Appendix B makes `id`, `timestamp`, `source`, `target`, `payload` mandatory. Handshake examples and reference implementations omit most of them.

**`source` and `target` are logical identity claims, not authenticated session identities.** On a direct connection, receiver should derive identity from the authenticated session, not trust a JSON field.

**`thread` is too vague.** Is it a request ID, conversation, workflow correlation, or arbitrary label?

**`reply_to` cannot express all relationships.** Need explicit `task_id` on all lifecycle messages.

**No extensibility discipline.** Need an `extensions` object or rules for unknown fields.

**No size/encoding rules.** "≤1MB" needs exact units, encoding, and behavior on oversize.

### Recommended Envelope

```json
{
  "protocol": "polymesh/0.1",
  "type": "task.submit",
  "message_id": "019f...",
  "sent_at": "2026-07-17T12:00:00.000Z",
  "from": "agent-instance-id",
  "to": "agent-instance-id",
  "task_id": "019f...",
  "correlation_id": "019f...",
  "in_reply_to": "019f...",
  "delivery": {
    "mode": "best-effort",
    "idempotency_key": "client-chosen-stable-key"
  },
  "payload": {}
}
```

Key changes:
- `message_id` per transmission event
- `task_id` stable identity for task lifecycle
- `correlation_id` for application-level grouping
- `from`/`to` as instance-level IDs
- `delivery.idempotency_key` stable across retries
- `protocol` in every envelope

---

## 2. Agent Card & Capability Model

### Needed Additions

```json
{
  "card_version": "1.0",
  "agent_id": "com.example.coding-agent",
  "instance_id": "01J...",
  "issued_at": "2026-07-17T12:00:00Z",
  "expires_at": "2026-07-17T12:05:00Z",
  "revision": 12,
  "endpoints": [
    {
      "transport": "websocket",
      "url": "ws://127.0.0.1:9855/polymesh",
      "scope": "loopback",
      "security": "local-session"
    }
  ],
  "capabilities": [
    {
      "id": "org.polymesh.calendar.read",
      "version": "1.0.0",
      "input_schema": { "$schema": "https://json-schema.org/draft/2020-12/schema" },
      "output_schema": { "$schema": "https://json-schema.org/draft/2020-12/schema" },
      "idempotency": "idempotent",
      "side_effects": "none",
      "approval": "never",
      "cancellation": "supported"
    }
  ]
}
```

---

## 3. Discovery Mechanism

### mDNS
- Service name inconsistent (`_polymesh._tcp.local` vs `_polymesh._tcp`)
- Port in TXT duplicate of SRV record
- TXT records have size limits; capabilities list can exceed them
- Not authenticated — attacker on LAN can spoof agent_id
- Define IPv4/IPv6, name conflicts, TTL expiry

**Recommendation:** Advertise minimal TXT only (protocol, instance_id, card_revision). Fetch authoritative card after connecting.

### Port Scanning — REMOVE
Scanning `9800-9899` is slow, noisy, probes unrelated services, fails across containers. "Start a broker after 5 seconds" is worse — agents race for port 9854.

**Better:** Unix domain socket at `$XDG_RUNTIME_DIR/polymesh/registry.json` or direct explicit endpoint config.

### Broker Mode — REMOVE from v0.1.0

Must define: registration, authenticated session binding, routing, queue semantics, retention, expiry, reconnection, ID collisions.

---

## 4. Security Model

**Largest design risk.** Shared developer workstations, CI runners, containers, browser-accessible local ports, malware, prompt-injection chains all produce untrusted processes. A local unauthenticated WebSocket offering `shell.exec` is a privilege-escalation boundary.

### Required Changes

1. **Separate discovery from authorization**
2. **Mandatory local authentication baseline**
   - Unix domain sockets with filesystem permissions (best v0.1.0 option)
   - User-owned bearer token in OS runtime directory
   - Loopback TCP with per-user session token
3. **Capability-scoped authorization policies**
4. **Resource limits as normative controls** — max connections, frame size, task concurrency, rate limits
5. **Do not treat input schemas as security boundary** — validate everything
6. **Protect sensitive metadata** — minimal public card, detailed card after auth

---

## 5. Delivery Semantics & Task Lifecycle

### Current Problems
A receiver sending `result` is NOT an acknowledgement. Sender cannot distinguish:
- never received → received + running → completed but result lost → rejected → timed out → crashed after side effect

### Recommended Lifecycle

```
submit → accepted | rejected
accepted → running → succeeded | failed | cancelled | expired
```

Wire sequence:
```
Sender                         Receiver
  task.submit  ───────────────►
                 ◄──────────── task.accepted
                 ◄──────────── task.progress*
                 ◄──────────── task.completed
  delivery.ack ───────────────►   (durable/broker only)
```

### Delivery Profiles for v0.1.0

| Profile | Guarantee | Suitable For |
|---------|-----------|--------------|
| Direct ephemeral | Best effort over active socket; idempotent retry | Reads, short tasks |
| Direct acknowledged | Receipt + sender retry; receiver dedupe cache | Idempotent tasks |
| Durable broker | At-least-once to persisted queue (deferred) | Future |

---

## 6. Suggested v0.1.0 Scope

**"Safe Local RPC" — strip it back to minimal interoperable core:**

- Direct peer-to-peer only
- Loopback & same-user local transport (Unix socket or local token)
- WebSocket over localhost as baseline
- mDNS optional, hints only
- Agent Card exchange after authenticated handshake
- `task.submit`, `task.accepted`, `task.progress`, `task.completed`, `task.cancel`, `task.status`
- Sender retries with idempotency keys
- Receiver retains completed state for minimum TTL
- No broadcast
- No broker, offline inbox, or remote mode
- Explicit "best effort / acknowledged direct" delivery claims
- Capability-level authorization with safe defaults

Still fits in ~200 lines, but with actual interoperable semantics.

---

## 7. Revision Path

| Version | Scope | Description |
|---------|-------|-------------|
| **v0.1.0** | Safe local RPC | Envelope, card schemas, local auth, task lifecycle, dedupe, size limits, error taxonomy, conformance tests. Remove port scanning, implicit broker, broadcast from normative scope |
| **v0.1.1** | Discovery + hardening | mDNS details, card caching/expiry, local registry, tracing, rate limiting, robust ref implementations |
| **v0.2** | Brokered delivery | Persistent queue semantics, acknowledgements, identity binding, retention, replay, routing failure, broker trust |
| **v0.3** | Remote profiles | TLS, bearer/mTLS/Tailscale auth, remote card resolution, network policy |

---

*Full review by Codex (gpt-5.6-terra) — 18,617 tokens consumed*
