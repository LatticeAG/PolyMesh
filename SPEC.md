# PolyMesh Protocol Specification v0.1.0

> **Status:** Draft Specification  
> **Type:** Protocol Standard (local agent-to-agent communication)  
> **Repository:** https://github.com/mosesman831/polymesh  
> **Version:** 0.1.0  
> **Tags:** `agent-to-agent`, `protocol`, `messaging`, `local-first`, `distributed-systems`

---

## Abstract

PolyMesh is a lightweight, open protocol for local agent-to-agent communication. It enables heterogeneous AI agents — Hermes, Codex, Claude Code, custom agents — to discover each other on the same machine or LAN, declare capabilities, exchange structured messages, delegate tasks, and coordinate without a central authority, blockchain, or global registry.

This specification defines:

1. **Message Envelope & Wire Format** — JSON-based, JSON-RPC inspired, with strict validation
2. **Agent Card Schema** — Self-describing capability declaration with JSON Schema typed I/O
3. **Task Lifecycle** — Submit → accept/reject → progress → complete/cancel with at-least-once delivery
4. **Transport Binding** — WebSocket (loopback/LAN) and Unix domain sockets (local)
5. **Discovery** — Local registry via Unix socket, LAN via mDNS, HTTP as optional hint
6. **Security Model** — OS-authenticated local sessions, capability authorization, resource limits
7. **Error Taxonomy** — Structured, machine-readable error codes with retry semantics
8. **Reference Implementation** — TypeScript @polymesh/broker + @polymesh/client (~300 LOC)

PolyMesh is **not a product**. It is a specification that any agent can implement in ~300 lines of code.

---

## Table of Contents

1. [Design Goals & Non-Goals](#1-design-goals--non-goals)
2. [Core Protocol: Message Envelope](#2-core-protocol-message-envelope)
3. [Message Types & Behavior](#3-message-types--behavior)
4. [Task Lifecycle & State Machine](#4-task-lifecycle--state-machine)
5. [Delivery Semantics & Idempotency](#5-delivery-semantics--idempotency)
6. [Agent Card Schema](#6-agent-card-schema)
7. [Capability Vocabulary](#7-capability-vocabulary)
8. [Discovery & Transport Binding](#8-discovery--transport-binding)
9. [Security Model & Authentication](#9-security-model--authentication)
10. [Error Taxonomy](#10-error-taxonomy)
11. [Reference Implementation Architecture](#11-reference-implementation-architecture)
12. [Edge Cases & Required Behaviors](#12-edge-cases--required-behaviors)
13. [Appendix: JSON Schema](#13-appendix-json-schema)
14. [Appendix: Standard Capability Definitions](#14-appendix-standard-capability-definitions)

---

## 1. Design Goals & Non-Goals

### Goals

| Priority | Goal | Rationale |
|----------|------|-----------|
| P0 | **Local-first** | Agents on same machine/LAN discover and talk without internet, DNS, or cloud |
| P0 | **Zero-config discovery** | Start an agent → it announces itself → becomes reachable. No config files |
| P0 | **Framework-agnostic** | Any agent in any language can implement. No SDK lock-in |
| P0 | **Self-describing** | Every agent publishes an Agent Card declaring identity, capabilities, and endpoints |
| P0 | **Simple wire format** | JSON-based. A developer can craft a valid message by hand |
| P1 | **Standard capability vocabulary** | Shared capability names so agents understand each other |
| P1 | **At-least-once delivery** | Messages acknowledged. Offline targets receive deferred notification |
| P1 | **Deterministic task lifecycle** | Submit → accept/reject → progress → complete/cancel with strict state transitions |
| P2 | **Opt-in remote** | Protocol works on localhost first. Internet routing is possible but only for advanced profiles |

### Non-Goals

- **Global agent discovery** — No global registry. Agents find each other locally
- **Cryptographic identity** — No PKI, no blockchain, no wallets. Identity is OS-authenticated on localhost, trust-on-first-use on LAN
- **Payment / billing** — PolyMesh does not handle payments
- **Workflow orchestration** — PolyMesh delivers messages. Workflow DAGs are a layer above
- **Agent-to-tool** — MCP covers that. PolyMesh is agent-to-agent only
- **Large file transfer** — Messages ≤1 MiB. Large files use side channels (HTTP download, presigned URLs) referenced within messages
- **Exactly-once execution** — Not achievable across crashes without application-level coordination. The spec provides at-most-once admission and terminalization

---

## 2. Core Protocol: Message Envelope

Every message is a JSON object with the following top-level fields. All fields except `in_reply_to` are REQUIRED unless noted.

### 2.1 Base Envelope Schema

```json
{
  "protocol": "polymesh.0.1",
  "type": "<message_type>",
  "message_id": "0197a1b0-0000-7000-8000-000000000001",
  "timestamp": "2026-07-17T12:00:00.000Z",
  "source": {
    "agent_id": "example-agent",
    "instance_id": "base64url-128-bit-instance-id"
  },
  "target": {
    "agent_id": "target-agent",
    "instance_id": "base64url-128-bit-instance-id"
  },
  "delivery": {
    "mode": "at_least_once",
    "idempotency_key": "submit:task-uuid",
    "deadline": "2026-07-17T12:10:00.000Z"
  },
  "in_reply_to": "<message_id this is a response to, OPTIONAL>",
  "params": {}
}
```

### 2.2 Field Constraints

| Field | Constraint |
|-------|-----------|
| `protocol` | MUST be exactly `"polymesh.0.1"` |
| `type` | One of the registered message types |
| `message_id` | UUIDv7. Unique per sender. Time-ordered |
| `timestamp` | RFC 3339 with milliseconds, UTC. Server monotonic clock is authoritative |
| `source.agent_id` | Stable logical identity, reverse-DNS recommended (e.g., `com.example.my-agent`) |
| `source.instance_id` | 128-bit cryptographically random, base64url-encoded. Changes on restart |
| `target.agent_id` | Target agent identity. `"*"` reserved for future broadcast |
| `target.instance_id` | OPTIONAL. When absent, routes to any instance of that agent_id |
| `delivery.mode` | Only `"at_least_once"` in v0.1 |
| `delivery.idempotency_key` | Opaque string. MUST be unique per (source, target, type) scope |
| `delivery.deadline` | RFC 3339. The server's clock is authoritative. Client MUST NOT exceed this |

### 2.3 Wire Framing

On WebSocket transport, each message is a single JSON text frame. On Unix socket transport, messages are length-prefixed:

```
[4 bytes: big-endian uint32 payload length][UTF-8 JSON payload]
```

Maximum frame size: **1,048,576 bytes** (1 MiB).

---

## 3. Message Types & Behavior

### 3.1 Message Type Catalog

| Type | Direction | Semantics |
|------|-----------|-----------|
| `card` | Agent → peer | Capability snapshot. Sent on connect and on revision change |
| `task.submit` | Owner → executor | Creates or replays a logical task |
| `task.accepted` | Executor → owner | Durable admission. `event_seq=1` |
| `task.rejected` | Executor → owner | Final pre-admission refusal. `event_seq=1` |
| `task.progress` | Executor → owner | Optional non-terminal lifecycle event. `event_seq >= 2` |
| `task.completed` | Executor → owner | Sole post-acceptance terminal event |
| `task.cancel` | Owner → executor | Idempotent cancellation request |
| `task.status` | Bidirectional | Query (owner→executor) and snapshot (executor→owner) |
| `ping` | Bidirectional | Liveness check. Requires `pong` reply within 5 seconds |
| `pong` | Bidirectional | Liveness response. MUST match ping sequence number |
| `error` | Any → sender | Protocol, routing, delivery, or control failure |

### 3.2 Card Exchange

On connection establishment, agents exchange `card` messages:

1. Initiator sends `card` after `hello`/`hello` handshake
2. Responder validates card, sends its own `card`
3. Both sides send `ready` to confirm
4. Application messages are illegal until both `ready` frames exchanged

A `card` message contains:
```json
{
  "type": "card",
  "params": {
    "card": { /* AgentCard object */ },
    "digest": "sha256-of-canonical-card"
  }
}
```

### 3.3 task.submit

Creates a task. The owner generates `task_id` (UUIDv7) and retains it until retention expiry.

```json
{
  "type": "task.submit",
  "params": {
    "task_id": "0197a1b0-0000-7000-8000-000000000001",
    "method": "org.polymesh.calendar.read",
    "params": { /* capability-specific input */ },
    "deadline": "2026-07-17T12:10:00.000Z"
  }
}
```

Rules:
- `method` MUST match an advertised capability
- Executor MUST validate `params` against capability `input_schema` before accepting
- Deadline is immutable across retries
- Owner MUST NOT alter method, parameters, task_id, or idempotency_key on retry

### 3.4 task.accepted

Durable admission. The executor persists the task state, idempotency key, and deadline before emitting this.

```json
{
  "type": "task.accepted",
  "in_reply_to": "<submit message_id>",
  "params": {
    "task_id": "0197a1b0-...",
    "event_seq": 1,
    "accepted_at": "2026-07-17T12:00:01.000Z"
  }
}
```

An accepted task MUST eventually produce exactly one `task.completed` terminal event.

### 3.5 task.rejected

Final refusal. Non-retryable. MUST NOT be followed by `task.accepted` or `task.completed`.

```json
{
  "type": "task.rejected",
  "in_reply_to": "<submit message_id>",
  "params": {
    "task_id": "0197a1b0-...",
    "event_seq": 1,
    "code": "UNSUPPORTED_CAPABILITY",
    "message": "Agent does not implement org.polymesh.calendar.read"
  }
}
```

### 3.6 task.progress

Optional, advisory. Signals intermediate state.

```json
{
  "type": "task.progress",
  "params": {
    "task_id": "0197a1b0-...",
    "event_seq": 2,
    "progress": {
      "current": 1,
      "total": 5,
      "status": "querying google calendar API",
      "state": "running"
    }
  }
}
```

MUST follow `task.accepted`, precede terminal record, and have `event_seq >= 2`.

### 3.7 task.completed

Terminal event. Exactly one permitted. Uses `outcome` field for the result type:

```json
{
  "type": "task.completed",
  "params": {
    "task_id": "0197a1b0-...",
    "event_seq": 3,
    "terminal": {
      "outcome": "succeeded",
      "result": { "free_slots": [] },
      "completed_at": "2026-07-17T12:00:05.000Z"
    }
  }
}
```

Terminal outcomes:
- `succeeded` — requires `result` field
- `failed` — requires `error` with code and message
- `cancelled` — requires `cancellation` with code

### 3.8 task.cancel

Idempotent cancellation request:

```json
{
  "type": "task.cancel",
  "params": {
    "task_id": "0197a1b0-...",
    "reason": "deadline approaching, initiating fallback"
  }
}
```

- Only the authenticated submitter may cancel by default
- Executor MUST persist accepted cancellation intent before transport receipt
- If cancellation arrives before matching submit, store cancellation tombstone
- Terminal outcome `cancelled` confirms cancellation

### 3.9 task.status

Two shapes:
- **Query:** `{"kind": "query", "task_id": "..."}`
- **Snapshot:** `{"kind": "snapshot", ...}` plus `in_reply_to`

Snapshot reflects one persisted task state at `observed_at`.

### 3.10 ping/pong

```json
{"type": "ping", "params": {"n": 41}}
{"type": "pong", "params": {"n": 41}}
```

Sent every 30 seconds during active sessions. Any valid inbound frame refreshes liveness.

---

## 4. Task Lifecycle & State Machine

```
                     SUBMITTED (owner-local only)
                         |
                         | task.submit received
                         v
                    NO_RECORD
                    /        \
                   /          \
        permanent refusal     durable admission
             |                      |
             v                      v
         REJECTED               ACCEPTED
         event_seq=1            event_seq=1
                                     |
                          +----------+----------+
                          |          |          |
                          v          v          v
                       QUEUED    RUNNING    WAITING
                       event_seq >= 2 (task.progress)
                          |          |          |
                          +----------+----------+
                                     |
                          +----------+----------+
                          |          |          |
                          v          v          v
                     SUCCEEDED   FAILED    CANCELLED
                     outcome:    outcome:  outcome:
                     "succeeded" "failed"  "cancelled"
```

### State Machine Rules

1. `REJECTED`, `SUCCEEDED`, `FAILED`, `CANCELLED` are terminal states
2. Exactly one event may occupy a `(task_id, event_seq)` pair
3. Accepted/rejected events always use `event_seq: 1`
4. Every progress event increments event sequence monotonically
5. Terminal event sequence MUST exceed all progress sequence numbers
6. Consumers MUST deduplicate lifecycle events by `(task_id, event_seq)`, not envelope `message_id`
7. A terminal event may arrive before delayed accepted/progress events. Consumers MUST NOT regress from a terminal state

---

## 5. Delivery Semantics & Idempotency

### 5.1 Delivery Mode

v0.1 supports only `"at_least_once"`. Messages are retried until acknowledged or deadline expiry.

### 5.2 Deduplication Key

The deduplication key is constructed from:

```text
(authenticated_source_instance_id,
 authenticated_target_instance_id,
 protocol,
 message_type,
 delivery.idempotency_key)
```

### 5.3 Semantic Fingerprint

For each idempotency key, the receiver stores a fingerprint:

```text
SHA-256(JCS({
  protocol, type, source, target,
  delivery: { mode, deadline },
  params
}))
```

Where JCS = JSON Canonicalization Scheme (RFC 8785).

### 5.4 Deduplication Behavior

| Condition | Required Response |
|-----------|------------------|
| Same key, same fingerprint | Replay canonical outcome (duplicate delivery) |
| Same key, different fingerprint | `PMX.DELIVERY.IDEMPOTENCY_CONFLICT` |
| Same task_id, same immutable task, different submit key | Replay existing task state |
| Same task_id, different method/input/deadline | `PMX.TASK.ID_CONFLICT` |

### 5.5 Retention Requirements

| Record | Minimum Retention |
|--------|-------------------|
| Idempotency key | 24 hours |
| Active task state | Through task deadline |
| Terminal records + results | `max(deadline, completed_at) + idempotency_retention_ms` (≥24h) |
| Cancellation tombstones | Same as idempotency retention |

### 5.6 Durable Inbox/Outbox Pattern

Implementations SHOULD use:

1. Persist inbound deduplication state
2. Persist task state transition and canonical event
3. Persist outbound event in outbox
4. Only then issue durable transport receipt
5. Retry outbox events until receipt or retention expiry

---

## 6. Agent Card Schema

### 6.1 Full Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": [
    "card_version", "agent_id", "instance_id",
    "issued_at", "expires_at", "revision",
    "capabilities"
  ],
  "properties": {
    "card_version": {
      "const": "1.0",
      "description": "Schema version of the card itself"
    },
    "agent_id": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9._-]*$",
      "description": "Stable logical identifier, reverse-DNS recommended (e.g. com.example.my-agent)"
    },
    "instance_id": {
      "type": "string",
      "description": "128-bit random, base64url-encoded. Changes on each process restart"
    },
    "display_name": {
      "type": "string",
      "description": "Human-readable name. Presentation only"
    },
    "issued_at": {
      "type": "string",
      "format": "date-time",
      "description": "When this card version was issued"
    },
    "expires_at": {
      "type": "string",
      "format": "date-time",
      "description": "When this card expires. MUST be later than issued_at"
    },
    "revision": {
      "type": "integer",
      "minimum": 1,
      "description": "Monotonically increasing per-instance. Higher value replaces older cards"
    },
    "endpoints": {
      "type": "array",
      "items": { "$ref": "#/$defs/Endpoint" },
      "description": "List of reachable endpoints"
    },
    "capabilities": {
      "type": "array",
      "items": { "$ref": "#/$defs/Capability" },
      "minItems": 1,
      "description": "At minimum MUST include org.polymesh.agent.ping and org.polymesh.agent.info"
    },
    "limits": {
      "$ref": "#/$defs/Limits",
      "description": "Advisory resource limits"
    },
    "metadata": {
      "type": "object",
      "properties": {
        "description": { "type": "string" },
        "tags": { "type": "array", "items": { "type": "string" } },
        "icon": { "type": "string" }
      },
      "description": "Free-form metadata"
    }
  },
  "$defs": {
    "Endpoint": {
      "type": "object",
      "required": ["transport", "url", "scope"],
      "properties": {
        "transport": { "type": "string", "enum": ["websocket", "unix"] },
        "url": { "type": "string", "format": "uri" },
        "scope": { "type": "string", "enum": ["loopback", "lan", "remote"] },
        "security": { "type": "string", "enum": ["none", "token", "mutual"], "default": "none" }
      }
    },
    "Capability": {
      "type": "object",
      "required": ["id", "version"],
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*\\.[a-zA-Z][a-zA-Z0-9._-]*$",
          "description": "Reverse-DNS capability identifier (e.g. org.polymesh.calendar.read)"
        },
        "version": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
        "description": { "type": "string" },
        "input_schema": { "$ref": "https://json-schema.org/draft/2020-12/schema" },
        "result_schema": { "$ref": "https://json-schema.org/draft/2020-12/schema" },
        "idempotency": {
          "type": "string",
          "enum": ["pure", "idempotent", "sensitive"],
          "default": "idempotent"
        },
        "side_effects": {
          "type": "string",
          "enum": ["none", "read", "write", "network", "approval"],
          "default": "none"
        },
        "approval": {
          "type": "string",
          "enum": ["never", "always", "threshold"],
          "default": "never"
        },
        "cancellation": {
          "type": "string",
          "enum": ["none", "best_effort", "supported"],
          "default": "none"
        },
        "timeout_ceiling_seconds": {
          "type": "integer",
          "minimum": 1,
          "default": 300
        }
      }
    },
    "Limits": {
      "type": "object",
      "properties": {
        "max_task_timeout_ms": { "type": "integer", "default": 300000 },
        "max_tasks_per_principal": { "type": "integer", "default": 4 },
        "max_input_bytes": { "type": "integer", "default": 262144 },
        "max_result_bytes": { "type": "integer", "default": 1048576 }
      }
    }
  }
}
```

### 6.2 Card Exchange Protocol

1. On connection, after `hello/hello` handshake, initiator sends `card` message with full card
2. Responder validates: revision > cached, signatures match agent_id, expires_at in future
3. Responder sends its own `card`
4. Both sides send `ready` confirming mutual card receipt
5. Cards are re-sent when revision changes
6. Cards expire at `expires_at`; peers request refresh if still connected
7. A card with `revision <= cached` is ignored

### 6.3 Card Comparison Rules

| Condition | Interpretation |
|-----------|---------------|
| Same `agent_id`, same `instance_id` | Same agent instance. Card revision may update |
| Same `agent_id`, different `instance_id` | New instance (restart). Clear task state, re-authenticate |
| Different `agent_id` | Different agent. Route accordingly |
| Same `agent_id`, `revision` not strictly increasing | Protocol violation |

---

## 7. Capability Vocabulary

### 7.1 Namespace Convention

All capabilities use reverse-DNS notation:

```text
<org>.<domain>.<name>[.<sub>]
```

Standard namespace: `org.polymesh.*`
Vendor namespaces: `com.<vendor>.*`, `io.<vendor>.*`
Private/experimental: `custom.*`

### 7.2 Required Standard Capabilities

Every PolyMesh agent MUST implement:

| Capability ID | Description |
|---------------|-------------|
| `org.polymesh.agent.ping` | Required. Liveness check. Input: `{}`. Result: `{}` |
| `org.polymesh.agent.info` | Required. Returns full Agent Card. Input: `{}`. Result: `AgentCard` |
| `org.polymesh.capabilities.list` | Required. Returns list of capabilities for current connection. Input: `{}`. Result: `[{id, version}]` |

### 7.3 Standard Capability Definitions

| ID | Description | Input | Result | Idempotency | Side Effect |
|----|-------------|-------|--------|-------------|-------------|
| `org.polymesh.agent.ping` | Liveness check | `{}` | `{}` | pure | none |
| `org.polymesh.agent.info` | Get Agent Card | `{}` | `AgentCard` | pure | none |
| `org.polymesh.capabilities.list` | List capabilities | `{}` | `[{id, version}]` | pure | none |
| `org.polymesh.calendar.read` | Read calendar events | `{range: {from, to}, page_size?}` | `{events, next_cursor}` | pure | read |
| `org.polymesh.calendar.write` | Create/update events | `{event}` | `{event_id}` | idempotent | write |
| `org.polymesh.email.send` | Send email | `{to, subject, body}` | `{message_id}` | sensitive | network |
| `org.polymesh.email.read` | Read inbox | `{folder, limit}` | `{messages}` | pure | read |
| `org.polymesh.file.read` | Read file | `{path}` | `{content, size}` | pure | read |
| `org.polymesh.file.write` | Write file | `{path, content}` | `{size}` | idempotent | write |
| `org.polymesh.shell.exec` | Execute command | `{command, args, cwd, timeout}` | `{stdout, stderr, exit_code}` | sensitive | write |
| `org.polymesh.knowledge.query` | Query knowledge base | `{query, limit}` | `{results}` | pure | read |
| `org.polymesh.web.search` | Search web | `{query, limit}` | `{results}` | pure | network |
| `org.polymesh.code.review` | Review code | `{diff, context}` | `{comments}` | pure | read |
| `org.polymesh.code.build` | Build project | `{target, config}` | `{output, success}` | idempotent | write |
| `org.polymesh.notify.send` | Send notification | `{channel, message}` | `{delivered}` | idempotent | network |
| `org.polymesh.file.search` | Search files | `{pattern, root?, max_results?, max_bytes?, include_hidden?}` | `{files, truncated}` | pure | read |
| `org.polymesh.shell.exec` | Execute command | `{command, args?, cwd?, timeout_ms?, stdin_utf8?, env?, kill_grace_ms?}` | `{exit_code, signal, stdout, stderr, timed_out}` | sensitive | write |
| `org.polymesh.process.list` | List processes | `{}` | `{processes}` | pure | read |
| `org.polymesh.mcp.execute` | Forward MCP tool call | `{tool, args}` | `{result}` | idempotent | network |

---

## 8. Discovery & Transport Binding

### 8.1 Session Handshake

Every transport connection begins with a deterministic 4-frame handshake before any application traffic:

```
Initiator A                              Responder B
-----------                              -----------
transport connected
HELLO ---------------------------------->>
                                         validate version/shape
<<---------------------------------- HELLO
CARD ---------------------------------->>
                                         validate A's card
<<---------------------------------- CARD
READY ---------------------------------->>
                                         validate transcript
<<---------------------------------- READY
ACTIVE                                     ACTIVE
```

**hello frame (initiator):**
```json
{
  "type": "hello",
  "v": "0.1",
  "role": "initiator",
  "agent_id": "agent-a",
  "instance_id": "base64url-128-bit-id",
  "nonce": "base64url-32-byte-nonce"
}
```

**hello frame (responder):**
```json
{
  "type": "hello",
  "v": "0.1",
  "role": "responder",
  "agent_id": "agent-b",
  "instance_id": "base64url-128-bit-id",
  "nonce": "base64url-32-byte-nonce",
  "echo": "initiator-nonce",
  "sid": "derived-session-id"
}
```

The session ID is derived as:

```text
sid = base64url(SHA-256("polymesh.0.1\0" || initiator_nonce || responder_nonce))
```

**card frame:**
```json
{
  "type": "card",
  "sid": "derived-session-id",
  "for_nonce": "peer-nonce",
  "digest": "sha256-of-canonical-card",
  "card": { /* Agent Card */ }
}
```

**ready frame:**
```json
{
  "type": "ready",
  "sid": "derived-session-id",
  "self_card": "own-card-digest",
  "peer_card": "peer-card-digest"
}
```

Application messages are illegal until both `ready` frames exchanged.

### 8.2 Local Transport (Unix Domain Sockets)

For same-machine discovery, agents use Unix domain sockets under `$XDG_RUNTIME_DIR`:

```
$XDG_RUNTIME_DIR/polymesh/
├── registry.sock          # Discovery registry (not a broker)
└── agents/
    └── pm-<random-128-bit-id>.sock  # Agent's direct data socket
```

**Requirements:**
- `R` and `R/agents`: mode `0700`, owned by current UID
- Socket files: mode `0600`
- If `XDG_RUNTIME_DIR` is missing, unsafe, or wrong-owner: discovery unavailable. NO fallback to `/tmp`
- Peer credential verification (`SO_PEERCRED` on Linux, `getpeereid` on BSD) MUST confirm same UID

**Registry RPCs** (same framing, distinct from agent-to-agent messages):

| Operation | Payload | Description |
|-----------|---------|-------------|
| `register` | `{agent_id, instance_id, socket, card_digest?}` | Register with lease (120s default) |
| `renew` | `{lease_id}` | Renew registration (30s interval) |
| `unregister` | `{lease_id}` | Remove registration |
| `lookup` | `{agent_id}` | Get live agent endpoint |
| `list` | `{}` | List all registered agents |
| `watch` | — | Stream add/update/remove events |

### 8.3 WebSocket Transport (LAN)

WebSocket handshake:

```
GET /polymesh HTTP/1.1
Host: host:port
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: polymesh.0.1
```

Server responds with `101 Switching Protocols` and subprotocol `polymesh.0.1`.

After upgrade, the standard PolyMesh session handshake runs immediately.

**Pre-upgrade responses:**

| Condition | Response |
|-----------|----------|
| Malformed | 400 |
| Wrong path | 404 |
| Policy denial | 403 |
| Bad subprotocol | 426 |
| Rate limited | 429 |
| Temp unavailable | 503 + `Retry-After` |

### 8.4 mDNS/DNS-SD Discovery (LAN)

Service type: `_polymesh._tcp.local.`

TXT records are deliberately minimal:
- `v=0.1` (required)
- `id=<agent_id>` (required)
- `tls=1` (optional, indicates WSS)

**NO cards, capabilities, secrets, or paths in TXT records.**

Publish TTL: 120 seconds. Send TTL-0 goodbye on clean shutdown.

### 8.5 HTTP Discovery Endpoint (Optional)

```
GET /.well-known/polymesh
Accept: application/polymesh+json
```

Response (a hint only — NOT an Agent Card):
```json
{
  "v": "0.1",
  "agent_id": "agent-a",
  "instance_id": "instance-a",
  "endpoints": [{"transport": "websocket", "url": "wss://host:7443/polymesh"}]
}
```

Cache `max-age: 60`. Do NOT follow redirects. Do NOT treat as authoritative identity.

### 8.6 Heartbeat & Reconnection

Heartbeat timers use a local monotonic clock. Wall-clock time MUST NOT be used to measure ping intervals, pong deadlines, inactivity, stable-session duration, or reconnect delays.

| Parameter | Value |
|:---|---:|
| Ping interval | 30 seconds |
| Pong deadline | 5 seconds after transport accepts the ping write |
| Inbound timeout | 90 seconds with no valid inbound PolyMesh record |
| Initial retry delay | 1 second |
| Maximum retry delay | 60 seconds |
| Backoff factor | 2× with ±20% jitter |
| Backoff reset condition | 90 seconds of uninterrupted `ACTIVE` session time |

Heartbeat processing starts only after both `ready` records are exchanged. A **valid inbound record** is fully framed, decoded, authenticated, and valid for the current session state. Every valid inbound record refreshes the 90-second inbound timer.

A `pong` satisfies a pending heartbeat only if `params.n` exactly matches the outstanding ping sequence number. `n` MUST be a non-negative JSON safe integer and MUST increase monotonically for the lifetime of the session.

```text
const PING_INTERVAL_MS    = 30_000
const PONG_TIMEOUT_MS     = 5_000
const INBOUND_TIMEOUT_MS  = 90_000
const STABLE_SESSION_MS   = 90_000

function activate(session):
    now = monotonic_now_ms()
    session.state = ACTIVE
    session.generation += 1
    session.active_since = now
    session.last_valid_inbound = now
    session.next_ping_at = now + PING_INTERVAL_MS
    session.next_ping_n = 0
    session.pending_ping = null
    session.outstanding_ping = null
    session.backoff_reset = false
    arm_heartbeat(session)

function on_valid_inbound(session, record):
    if session.state != ACTIVE:
        return
    now = monotonic_now_ms()
    session.last_valid_inbound = now
    if record.type == "ping":
        n = record.params.n
        if not enqueueControl(session, {type: "pong", params: {n: n}}):
            fail_session(session, "HEARTBEAT_TIMEOUT", retryable=true)
            return
    if record.type == "pong":
        n = record.params.n
        if session.outstanding_ping != null and
           session.outstanding_ping.n == n:
            session.outstanding_ping = null
        else if session.pending_ping != null and
                session.pending_ping.n == n:
            session.pending_ping.pong_received = true
    arm_heartbeat(session)

function heartbeat_tick(session, captured_generation):
    if session.state != ACTIVE or session.generation != captured_generation:
        return
    now = monotonic_now_ms()
    if session.pending_ping != null and now >= session.pending_ping.write_deadline:
        fail_session(session, "HEARTBEAT_TIMEOUT", retryable=true); return
    if session.outstanding_ping != null and now >= session.outstanding_ping.pong_deadline:
        fail_session(session, "HEARTBEAT_TIMEOUT", retryable=true); return
    if now - session.last_valid_inbound >= INBOUND_TIMEOUT_MS:
        fail_session(session, "HEARTBEAT_TIMEOUT", retryable=true); return
    if not session.backoff_reset and now - session.active_since >= STABLE_SESSION_MS:
        reconnect_attempt = 0
        session.backoff_reset = true
    if session.pending_ping == null and session.outstanding_ping == null and now >= session.next_ping_at:
        begin_ping(session, now)
    arm_heartbeat(session)

function begin_ping(session, now):
    n = session.next_ping_n
    session.next_ping_n += 1
    session.pending_ping = {n: n, write_deadline: now + PONG_TIMEOUT_MS, pong_received: false}
    accepted = enqueueControl(session, {type: "ping", params: {n: n}},
        onWritten = function():
            if session.state != ACTIVE or session.pending_ping == null or session.pending_ping.n != n:
                return
            written_at = monotonic_now_ms()
            if session.pending_ping.pong_received:
                session.pending_ping = null
            else:
                session.outstanding_ping = {n: n, pong_deadline: written_at + PONG_TIMEOUT_MS}
                session.pending_ping = null
            session.next_ping_at = written_at + PING_INTERVAL_MS
            arm_heartbeat(session))
    if not accepted:
        fail_session(session, "HEARTBEAT_TIMEOUT", retryable=true)

function arm_heartbeat(session):
    cancel_timer(session.heartbeat_timer)
    now = monotonic_now_ms()
    due = session.last_valid_inbound + INBOUND_TIMEOUT_MS
    if session.pending_ping != null:
        due = min(due, session.pending_ping.write_deadline)
    if session.outstanding_ping != null:
        due = min(due, session.outstanding_ping.pong_deadline)
    if session.pending_ping == null and session.outstanding_ping == null:
        due = min(due, session.next_ping_at)
    if not session.backoff_reset:
        due = min(due, session.active_since + STABLE_SESSION_MS)
    session.heartbeat_timer = set_timer(max(1, due - now),
        function(): heartbeat_tick(session, session.generation))

function on_transport_closed(reason):
    cancel_timer(session.heartbeat_timer)
    if not reason.retryable or reason.code == "DUPLICATE_CONNECTION":
        return
    base_delay = min(1_000 * (2 ^ reconnect_attempt), 60_000)
    delay = min(60_000, base_delay * random_uniform(0.8, 1.2))
    reconnect_attempt += 1
    set_timer(delay, function():
        reconnect_transport()
        // Complete hello/card/ready before sending RESUME.
    )
```

`fail_session` MUST be idempotent. It cancels heartbeat timers, performs best-effort graceful close when writable, tears down the transport, and schedules reconnect only for retryable failures.

**Graceful close:**
```text
A: CLOSE {code, retryable} → B: CLOSE_ACK → WebSocket Close/UDS shutdown
```

A peer MUST NOT wait indefinitely for `CLOSE_ACK`; after one second it MUST complete transport shutdown and apply the reconnect rule.

### 8.7 Concurrent Connection Arbitration

Only one active session per verified peer instance. Deterministic tiebreaking:

1. Unix socket > WSS > WS
2. Lexicographically lower `(agent_id, instance_id)`
3. Lexicographically lower `sid`

The losing connection closes with `DUPLICATE_CONNECTION` and does not reconnect.

### 8.8 Reconnect During Task

After reconnect and handshake:

```text
A: RESUME {task-7, received_through: 40}
B: RESUME {task-7, received_through: 41}
```

A discards and retransmits as needed. If task state evicted, return `RESUME_UNAVAILABLE`.

Changed `instance_id` = restart. Task outcome unknown; do NOT replay non-idempotent work.

### 8.9 v0.1 Exclusions

**MUST NOT:**
- Scan ports
- Probe alternate ports after failure
- Use relay, STUN, ICE, or NAT hole-punching
- Interpret mDNS TXT, HTTP discovery, source IP, or TLS alone as identity
- Expose secrets or Agent Cards in discovery records

A local **router** (message-forwarding process) is permitted but must not impersonate agents, modify message payloads, or bypass authentication. The router is a convenience for same-machine agent-to-agent connectivity, not a NAT-traversal relay.

---

## 9. Security Model & Authentication

### 9.1 Trust Model

| Transport | Authentication | Trust Basis |
|-----------|---------------|-------------|
| Unix socket | Peer credential (SO_PEERCRED) | Same OS UID |
| WebSocket loopback | Runtime session token (256-bit, in `$XDG_RUNTIME_DIR`, `0600`) | OS file permissions |
| WebSocket LAN (opt-in) | HMAC-based shared secret | Explicit peer enrollment |

### 9.2 Authentication Flow

Every connection authenticates BEFORE exchanging cards or accepting tasks:

```
SESSION AUTH: hello/hello with nonces
SESSION ID:  derived from mutual nonces
SCOPE:       bound to authenticated principal
CARDS:       only after auth complete
TASKS:       only after cards exchanged
```

### 9.3 Authorization Policy

**Default: DENY ALL.** Unknown peers get only `org.polymesh.agent.ping`.

Policies are evaluated per-operation:

```json
{
  "version": "polymesh.policy/v1",
  "defaultAllow": ["org.polymesh.agent.ping", "org.polymesh.agent.info"],
  "rules": [
    {
      "match": {
        "subject": "peer:pm_build_runner",
        "authStrength": "local-unix"
      },
      "allow": [
        { "operation": "org.polymesh.agent.info" },
        {
          "operation": "capability.invoke",
          "capabilityId": "org.polymesh.file.read",
          "constraints": {
            "roots": ["/workspace/project"],
            "maxBytes": 262144,
            "followSymlinks": false
          }
        }
      ]
    },
    {
      "match": {
        "subject": "peer:pm_deploy_agent",
        "authStrength": "pairwise-psk"
      },
      "allow": [
        {
          "operation": "capability.invoke",
          "capabilityId": "org.polymesh.shell.exec",
          "constraints": {
            "programs": ["/usr/bin/git", "/usr/bin/npm"],
            "maxRuntimeMs": 30000,
            "network": "disabled"
          },
          "requireLocalConfirmation": true
        }
      ]
    }
  ]
}
```

### 9.4 Metadata Disclosure

| Level | Contents |
|-------|----------|
| Public card (unauthenticated) | `protocol version`, opaque `agent_id`, `authRequired: true` |
| Detailed card (authenticated) | Allowed capabilities, non-sensitive docs, risk labels, rate limits |
| Never exposed remotely | Tokens, secrets, policies, host details, internal paths, denied capabilities |

Public card: ≤8 KiB. Detailed card: ≤64 KiB, filtered to authenticated peer's authorization scope.

### 9.5 Resource Limits (Default)

| Resource | Default |
|----------|---------|
| Open inbound connections | 32 |
| Pending handshake connections | 8 |
| Sessions per principal | 4 |
| Authentication deadline | 5 seconds |
| Frame size (max) | 1,048,576 bytes |
| Control requests | 60/min/principal |
| Task submissions | 20/min/principal |
| Running tasks (global) | 4 |
| Running tasks (per principal) | 2 |
| Task input | 256 KiB |
| Default task timeout | 60 seconds |
| Max task timeout | 300 seconds |
| Result size | 1 MiB |
| Idle session timeout | 10 minutes |
| Max session age | 60 minutes |

### 9.6 Token Rotation

Runtime tokens (loopback):

1. Generate 256-bit token with CSPRNG
2. Write `0600` file, `fsync`, atomic rename into place
3. Increment `authEpoch`
4. Normal rotation: previous token accepted for 30-second overlap
5. Hard rotation: close all sessions immediately, reject old tokens

### 9.7 Threat Model

| Threat | Control | Residual Risk |
|--------|---------|--------------|
| Rogue process, different OS user | `0700` dirs, kernel UID check | Root/kernel out of scope |
| Rogue process, same OS user | Default deny, audit, managed-process binding | Cannot distinguish from legitimate same-UID agent without stronger OS boundary |
| Token theft | Runtime dir confinement, rotation, short sessions | Reader can replay until rotation |
| LAN injection | LAN disabled by default, explicit opt-in | Raw secret only blocks blind attackers |
| Replay | Session-bound nonces, sequence counters, deduplication | Captured traffic remains replayable within dedup window |
| DoS | Connection/handshake/frame/rate/task/buffer limits | Same-user can exhaust host resources |
| Metadata enumeration | Minimal public card, generic denials | Protocol presence visible to authenticated peers |

---

## 10. Error Taxonomy

### 10.1 Structured Error Format

```json
{
  "type": "error",
  "params": {
    "category": "task",
    "code": "TASK_NOT_FOUND",
    "message": "No task with ID 0197a1b0-1...",
    "retryable": false,
    "retry_after_ms": null,
    "details": {
      "task_id": "0197a1b0-1..."
    }
  }
}
```

### 10.2 Error Categories

| Category | Example Codes | Retryable? |
|----------|--------------|------------|
| `parse` | `MALFORMED_FRAME`, `MALFORMED_JSON`, `DUPLICATE_MEMBER` | Never |
| `protocol` | `UNSUPPORTED_PROTOCOL_VERSION`, `UNSUPPORTED_METHOD` | Never |
| `identity` | `AUTHENTICATION_FAILED`, `SOURCE_IDENTITY_MISMATCH`, `AUTHORIZATION_DENIED` | Never |
| `routing` | `UNKNOWN_TARGET`, `TARGET_UNAVAILABLE` | Target unavailable only |
| `delivery` | `PMX.DELIVERY.MESSAGE_ID_CONFLICT`, `PMX.DELIVERY.IDEMPOTENCY_CONFLICT` | Storage unavailable only |
| `resource` | `RATE_LIMITED`, `OVERLOADED`, `QUOTA_EXCEEDED` | Rate/overload yes |
| `task` | `PMX.TASK.NOT_FOUND`, `PMX.TASK.CONFLICT`, `PMX.TASK.DEADLINE_EXCEEDED` | Never |
| `execution` | `EXECUTION_FAILED`, `DEPENDENCY_FAILED`, `RESULT_TOO_LARGE` | After acceptance: never |
| `internal` | `INTERNAL_ERROR` | Transient cases yes |

### 10.3 Error Placement Rules

| Situation | Response |
|-----------|----------|
| Malformed envelope | Drop or transport diagnostic. No reflected error unless identity/route safe |
| Valid envelope can't be routed | Top-level `error` |
| Temporary admission failure | Retryable top-level `error` |
| Valid submit permanently refused | `task.rejected` |
| Accepted task fails | `task.completed(outcome="failed")` |
| Accepted task expires/cancels | `task.completed(outcome="cancelled")` |

`message` is human-readable. Clients MUST branch on `code` and `retryable`, never message text.

---

## 11. Reference Implementation Architecture

### 11.1 Package Structure

```
@polymesh/
├── packages/
│   ├── broker/
│   │   ├── src/
│   │   │   ├── protocol.ts    # 35 LOC — Types, guards, schemas
│   │   │   ├── registry.ts    # 120 LOC — Agent registry, TTL, routing
│   │   │   └── broker.ts      # 120 LOC — WebSocket server, handshake, auth, dispatch
│   └── client/
│       ├── src/
│       │   ├── client.ts      # 75 LOC — Connect, discover, call, respond
│       │   ├── cli.ts         # 45 LOC — polymesh CLI commands
│       │   └── mdns.ts        # 20 LOC — mDNS adapter
│       └── package.json
├── tsconfig.json
├── vitest.config.ts
└── package.json
```

~415 LOC total production code across all files.

### 11.2 Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `ws` | ^8.21.1 | WebSocket server + client |
| `bonjour-service` | ^1.4.3 | mDNS publish + discover |
| `vitest` | ^3 | Test runner |
| `typescript` | ^5 | Type system |

### 11.3 CLI Interface

```text
polymesh start       [--port 7337] [--host 127.0.0.1] [--token TOKEN] [--mdns]
polymesh connect     <ws-url> [--card FILE] [--token TOKEN]
polymesh peers       [--url URL] [--card FILE] [--mdns]
polymesh capabilities [--card FILE]
polymesh call        <agent> <capability> <json-input> [--url URL] [--timeout MS]
```

Environment defaults: `POLYMESH_URL`, `POLYMESH_TOKEN`, `POLYMESH_CARD`.

### 11.4 Test Plan

1. **Registry unit tests** — register, duplicate-ID rejection, TTL expiry, touch renewal, stale-socket-safe removal
2. **In-memory integration** — two paired `WireTransport`s, Alice + Bob, discovery + echo task exchange
3. **WebSocket integration** — `new Broker({port: 0})`, WS `localhost:OS-assigned-port`, two-agent task exchange
4. **Error cases** — bad token, unknown target, unknown capability, handler error, spoofed `from`, timeout, forged result, target disconnect
5. **CLI tests** — export `main(argv, deps)` and test without subprocess spawning

### 11.5 Broker Core (Pseudocode)

The broker is a message router, not a state machine. It:

1. Accepts WebSocket connections
2. Runs full handshake (hello/hello → card exchange → ready)
3. Maintains in-memory `Map<agent_id, {card, transport, sessionId}>` with TTL
4. Routes `task.submit` messages by `target.agent_id`
5. Returns `result`/`error` to the original caller using routing table
6. Deletes registry entries on disconnect
7. Fails pending routes on peer disconnect

---

## 12. Edge Cases & Required Behaviors

| Edge Case | Required Behavior |
|-----------|------------------|
| Simultaneous connections between same peers | Deterministic duplicate arbitration (see §8.7). Loser closes with DUPLICATE_CONNECTION |
| Restart during active task | New `instance_id` means stale task state. DO NOT replay non-idempotent work |
| Submit retried after acceptance | Replay accepted + terminal events |
| Submit retried after rejection | Replay canonical rejection |
| Terminal arrives before accepted | Preserve terminal state. Do NOT regress on late events |
| Cancel races success/failure | Durable compare-and-set decides winner |
| Cancel before submit | Store cancellation tombstone. Matching submit accepts then cancels without work |
| Deadline races cancellation | Deadline wins once reached |
| Expired card from live connection | Policy is authoritative. Caller refreshes card |
| Result purged after retention | Return `PMX.TASK.RESULT_EXPIRED`. Never invent state |
| Router can't reach target | Emit `TARGET_UNAVAILABLE`. MUST NOT impersonate target |
| mDNS spoofing | All discovery is hints. Card validation is authoritative |
| IPv4/IPv6 dual-stack | Happy Eyeballs: IPv6 first, IPv4 after 250ms |
| Port conflict | Report `PORT_IN_USE`. Do NOT probe neighbor ports |
| Stale local socket | `ECONNREFUSED`: mark stale, rescan, backoff. NEVER unlink another process's socket |
| Interface disappears | Retire candidates on that interface. Existing sessions rely on heartbeat |
| Self-connection | Reject with `SELF_CONNECTION` |
| Same agent_id, different key | `IDENTITY_COLLISION` |
| Clock skew (client) | Server clock is authoritative. No implicit grace period |
| Clock skew (server backward) | MUST NOT extend tasks beyond monotonic expiry |
| Rate limit exceeded | Return `RATE_LIMITED`. Honor `retry_after_ms` |
| Network partition / split-brain session | Heartbeat failure means transport reachability unknown. MUST NOT be interpreted as task cancellation or authorization revocation. On reconnect, apply duplicate-session arbitration, exchange `RESUME`, reconcile lifecycle state by `(task_id, event_seq)` and `received_through`. Executor-side task-row locking and fencing tokens MUST ensure only one worker can commit a transition. |
| Zombie registry registration | Registry lease binds `lease_id`, `agent_id`, `instance_id`, endpoint, and peer credential. Expired registrations not returned by `lookup`/`list`. Renewals match lease ID, not `agent_id`. `ECONNREFUSED` marks only matching lease stale; never unlink another process's socket. |
| Slow consumer backpressure | Apply bounded queue rules (see §2.3). Lifecycle records in outbox MUST NOT be dropped. Pause reads, reserve control capacity, reject new submissions with retryable `OVERLOADED` before durable admission when processing cannot be bounded. |
| Concurrent instance migration | Replacement uses new `instance_id`, may coexist with old instance under same `agent_id`. In-flight tasks pinned to accepting executor. New instance MUST NOT accept/cancel/complete old-instance tasks unless explicit fenced handoff above PolyMesh. |
| Version negotiation between 0.1.x agents | All `0.1.x` use `hello.v: "0.1"` and `protocol: "polymesh.0.1"`. Patch releases remain wire-compatible. Peer with unsupported wire profile rejected with `UNSUPPORTED_PROTOCOL_VERSION`. MUST NOT silently downgrade. |

---

## 13. Appendix: JSON Schema

### Base Envelope Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://polymesh.dev/schemas/envelope.json",
  "type": "object",
  "required": ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "params"],
  "properties": {
    "protocol": { "const": "polymesh.0.1" },
    "type": {
      "type": "string",
      "enum": ["card", "task.submit", "task.accepted", "task.rejected", "task.progress",
               "task.completed", "task.cancel", "task.status", "ping", "pong", "error"]
    },
    "message_id": { "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    "timestamp": { "type": "string", "format": "date-time" },
    "source": {
      "type": "object",
      "required": ["agent_id", "instance_id"],
      "properties": {
        "agent_id": { "type": "string" },
        "instance_id": { "type": "string" }
      }
    },
    "target": {
      "type": "object",
      "required": ["agent_id"],
      "properties": {
        "agent_id": { "type": "string" },
        "instance_id": { "type": "string" }
      }
    },
    "delivery": {
      "type": "object",
      "required": ["mode", "idempotency_key"],
      "properties": {
        "mode": { "const": "at_least_once" },
        "idempotency_key": { "type": "string" },
        "deadline": { "type": "string", "format": "date-time" }
      }
    },
    "in_reply_to": { "type": "string" },
    "params": { "type": "object" }
  }
}
```

*(Full per-message type schemas are defined in the Core Protocol §2 section above.)*

---

## 14. Appendix: Standard Capability Definitions

*(See §7.3 for the full capability table. Each capability has input_schema and result_schema defined as JSON Schema 2020-12.)*

### Example: `org.polymesh.calendar.read`

```json
{
  "id": "org.polymesh.calendar.read",
  "version": "2.0.0",
  "input_schema": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["range"],
    "properties": {
      "range": {
        "type": "object",
        "required": ["from", "to"],
        "properties": {
          "from": { "type": "string", "format": "date-time" },
          "to": { "type": "string", "format": "date-time" }
        },
        "additionalProperties": false
      },
      "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
      "cursor": { "type": "string" }
    },
    "additionalProperties": false
  },
  "result_schema": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["events"],
    "properties": {
      "events": { "type": "array", "items": { "type": "object" } },
      "next_cursor": { "type": ["string", "null"] }
    }
  },
  "idempotency": "pure",
  "side_effects": "read",
  "approval": "never",
  "cancellation": "supported",
  "timeout_ceiling_seconds": 30
}
```

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0-draft.1 | 2026-07-17 | Initial specification |
| 0.1.0-draft.2 | 2026-07-17 | Added Ultra-reasoned core protocol schemas, transport binding, security model, reference impl, agent card vocabulary |

---

*PolyMesh Protocol Specification v0.1.0 — MIT License*
