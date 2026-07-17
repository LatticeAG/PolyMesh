# PolyMesh Protocol Specification

> **Version:** 0.1.0 (Draft)  
> **Status:** Proposal  
> **Type:** Protocol Standard  
> **Repository:** github.com/mosesman831/polymesh  
> **Tags:** `agent-to-agent`, `protocol`, `discovery`, `messaging`, `local-first`

---

## Abstract

PolyMesh is a lightweight, open protocol for local agent-to-agent communication. It enables heterogeneous AI agents — Hermes, Claude Code, Codex, custom agents — to discover each other, declare capabilities, send structured messages, and delegate tasks without a central authority, blockchain, or global registry.

The protocol is transport-agnostic but defines WebSocket as the mandatory baseline transport. Agent identity is self-asserted (no PKI). Capabilities are declared via a standard Agent Card schema. Messages follow a JSON-RPC-inspired envelope with delivery semantics.

PolyMesh is **not a product**. It is a specification that any agent can implement in ~200 lines of code.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Design Goals](#2-design-goals)
3. [Non-Goals](#3-non-goals)
4. [Protocol Overview](#4-protocol-overview)
5. [Agent Card](#5-agent-card)
6. [Message Envelope](#6-message-envelope)
7. [Discovery](#7-discovery)
8. [Connection Lifecycle](#8-connection-lifecycle)
9. [Task Delegation](#9-task-delegation)
10. [Delivery Semantics](#10-delivery-semantics)
11. [Transport Binding: WebSocket](#11-transport-binding-websocket)
12. [Security Model](#12-security-model)
13. [Implementation Guide](#13-implementation-guide)
14. [Reference Implementation](#14-reference-implementation)
15. [FAQ](#15-faq)

---

## 1. Motivation

In mid-2026, the AI agent ecosystem is fragmented. A developer may simultaneously run:

- A **Hermes Agent** instance for personal automation (calendar, email, file ops)
- A **Codex** or **Claude Code** CLI for coding tasks
- An **OpenCode** instance for parallel builds
- A **custom agent** built for a specific domain (research, monitoring, etc.)

These agents operate in isolation. There is no standard way for them to:
- Discover each other on the same machine or network
- Ask "what can you do?"
- Send a task with structured input and get a structured result back
- Coordinate on multi-step workflows without human intervention

Existing solutions are over-engineered for local use:
- **Blockchain/DLT-based registries** add latency, cost, and complexity for a problem that exists entirely within one developer's local network
- **A2A (Agent-to-Agent) protocol** targets enterprise inter-org scenarios with full lifecycle management, suited for large-scale deployments
- **MCP (Model Context Protocol)** is agent→tool, not agent→agent
- **Custom glue code** creates brittle, non-reusable point solutions

PolyMesh fills the gap between "nothing" and "a global ledger" — a simple, local-first protocol that any agent can implement in an afternoon.

---

## 2. Design Goals

| Goal | Priority | Rationale |
|------|----------|-----------|
| **Local-first** | P0 | Agents on the same machine or LAN should discover and talk to each other without internet, DNS, or cloud dependencies |
| **Zero-config discovery** | P0 | An agent starts, announces itself, becomes reachable. No configuration files, no registries to join |
| **Framework-agnostic** | P0 | Any agent written in any language can implement the protocol. No SDK lock-in |
| **Self-describing** | P0 | Every agent publishes an Agent Card declaring its identity, capabilities, and how to reach it |
| **Simple message envelope** | P0 | JSON-based, akin to JSON-RPC 2.0. A developer can craft a valid message by hand |
| **Standard capability vocabulary** | P1 | A shared vocabulary of capability names so agents can say "I handle `calendar.read`" and be understood |
| **At-least-once delivery** | P1 | Messages are acknowledged. If the target is offline, the sender is told |
| **Opt-in remote** | P2 | The protocol works on localhost first. Public internet routing is defined but not mandatory |
| **No crypto/blockchain** | P2 | Identity is self-asserted. No keys, no wallets, no gas fees |

---

## 3. Non-Goals

- **Global agent discovery** — PolyMesh does not define a global registry. Agents find each other on localhost or the local network
- **Cryptographic identity** — No PKI, no signing, no blockchain. Identity is trust-on-first-use within a trusted network
- **Payment / billing** — PolyMesh does not handle payments. Use LexPay or x402 for that
- **Workflow orchestration** — PolyMesh delivers messages. It does not define workflow DAGs. That's a layer above
- **Agent-to-tool** — MCP already covers that. PolyMesh is agent-to-agent only
- **Large file transfer** — Messages are ≤1MB. Large files use side channels (HTTP download, S3 presigned URLs) referenced in the message

---

## 4. Protocol Overview

Agents in a PolyMesh network communicate over WebSocket connections. The protocol has four phases:

```
PHASE 1: DISCOVERY
  Agent A starts → announces via mDNS "_polymesh._tcp" → 
    or polls HTTP discovery endpoint → 
    or connects to a known broker URL

PHASE 2: ADVERTISEMENT
  Agent A sends its Agent Card to newly discovered peers →
    "I am agent-a, I can do: calendar.read, calendar.write, email.send"
    
PHASE 3: MESSAGING
  Agent B wants task X → looks up who can do X →
    sends a Task message to Agent A →
    Agent A processes and returns a Result message

PHASE 4: INBOX (optional)
  Agents that may be offline maintain a persistent inbox
    (local file, VekInbox, or AgentMail) for deferred delivery
```

---

## 5. Agent Card

Every agent publishes a JSON Agent Card describing itself. The card is the agent's identity and capability declaration.

### Schema

```json
{
  "protocol": "polymesh/0.1",
  "agent_id": "string (unique identifier, e.g. hermes-bot)",
  "display_name": "string (human-readable name)",
  "version": "string (agent version)",
  "capabilities": [
    {
      "name": "string (dotted capability name)",
      "description": "string (what this capability does)",
      "input_schema": { "type": "object", ... },
      "output_schema": { "type": "object", ... }
    }
  ],
  "endpoints": [
    {
      "transport": "ws",
      "location": "ws://localhost:9854",
      "priority": 0
    }
  ],
  "metadata": {
    "description": "string (free-text description of the agent)",
    "tags": ["string"],
    "icon": "string (emoji or URL)"
  }
}
```

### Standard Capability Names

PolyMesh defines a namespace convention for capability names:

| Namespace | Example | Description |
|-----------|---------|-------------|
| `calendar.read` | `calendar.read` | Read calendar events |
| `calendar.write` | `calendar.write` | Create/update calendar events |
| `email.send` | `email.send` | Send email |
| `email.read` | `email.read` | Read email inbox |
| `file.read` | `file.read` | Read files from workspace |
| `file.write` | `file.write` | Write files to workspace |
| `shell.exec` | `shell.exec` | Execute shell commands |
| `knowledge.query` | `knowledge.query` | Query knowledge base |
| `web.search` | `web.search` | Search the web |
| `code.review` | `code.review` | Review code changes |
| `code.build` | `code.build` | Build a project |
| `notify.send` | `notify.send` | Send a notification |
| `agent.ping` | `agent.ping` | Liveness check (required) |
| `agent.info` | `agent.info` | Return agent card (required) |

Agents can define custom namespaced capabilities (`custom.*`). Unknown capabilities are ignored.

### Agent Card Delivery

Agent Cards are delivered:
1. Automatically on WebSocket connection (server sends `card` message)
2. On request via the `agent.info` capability
3. Via HTTP discovery endpoint `GET /.well-known/polymesh` if HTTP transport is also enabled

---

## 6. Message Envelope

All messages follow a standard JSON envelope:

```json
{
  "type": "string (message type)",
  "id": "string (unique message ID, UUIDv7)",
  "timestamp": "ISO 8601 timestamp",
  "source": "string (agent_id of sender)",
  "target": "string (agent_id of recipient, or 'broadcast')",
  "thread": "string (conversation thread ID, optional)",
  "reply_to": "string (message ID this is a reply to, optional)",
  "payload": {}
}
```

### Message Types

| Type | Direction | Payload | Description |
|------|-----------|---------|-------------|
| `card` | server→client | `AgentCard` | Server announces its capabilities |
| `task` | client→server | `{capability, input, metadata}` | Request a task to be performed |
| `progress` | server→client | `{status, progress_pct, message}` | Intermediate progress update |
| `result` | server→client | `{capability, output, error?, metadata}` | Task completed (success or failure) |
| `ping` | any→any | `{}` | Liveness check |
| `pong` | any→any | `{}` | Liveness response |
| `error` | any→any | `{code, message, data?}` | Protocol error |

### Task Message Example

```json
{
  "type": "task",
  "id": "019f6e19-36a4-7c51-a3ed-58ea61d050ee",
  "timestamp": "2026-07-17T12:00:00Z",
  "source": "hermes-moses",
  "target": "mom-agent",
  "thread": "calendar-coordination-001",
  "payload": {
    "capability": "calendar.read",
    "input": {
      "date": "2026-07-21",
      "person": "moses"
    },
    "metadata": {
      "priority": "normal",
      "timeout_seconds": 30
    }
  }
}
```

### Result Message Example

```json
{
  "type": "result",
  "id": "019f6e19-36a4-7c51-a3ed-58ea61d050f1",
  "timestamp": "2026-07-17T12:00:02Z",
  "source": "mom-agent",
  "target": "hermes-moses",
  "reply_to": "019f6e19-36a4-7c51-a3ed-58ea61d050ee",
  "thread": "calendar-coordination-001",
  "payload": {
    "capability": "calendar.read",
    "output": {
      "free_slots": [
        {"start": "2026-07-21T18:00:00Z", "end": "2026-07-21T22:00:00Z"}
      ]
    }
  }
}
```

---

## 7. Discovery

PolyMesh defines three discovery mechanisms, listed in order of preference:

### 7.1 mDNS/DNS-SD (Local Network)

Agents advertise on `_polymesh._tcp.local` using multicast DNS. The mDNS TXT record contains:

| Key | Value | Required |
|-----|-------|----------|
| `agent_id` | Agent identifier | Yes |
| `version` | Protocol version | Yes |
| `port` | WebSocket port | Yes |
| `display_name` | Human-readable name | No |
| `capabilities` | Comma-separated capability names | No |

**Discovery flow:**
1. Agent comes online → starts WebSocket server on a port
2. Agent registers `_polymesh._tcp` service via mDNS
3. Other agents on the same network receive ADD notifications
4. Peers connect to the WebSocket port and receive the Agent Card

### 7.2 Brokerless Direct Connect (Default)

On **localhost**, agents can discover each other by scanning `localhost:9800-9899` for open WebSocket ports or by listening on a known port convention (`polymesh` broker on `:9854`).

**Fallback:** If no peers found within 5 seconds, the agent starts a broker on `:9854` and waits.

### 7.3 HTTP Discovery Endpoint (Optional)

Agents that also serve HTTP MAY publish `GET /.well-known/polymesh` returning their Agent Card. This is intended for remote agents that are reachable via Cloudflare Tunnel or similar.

```json
GET /.well-known/polymesh
Response: AgentCard
```

### 7.4 Broker Mode (Optional)

A PolyMesh **broker** is an agent that acts as a message relay. Brokers:
- Maintain a registry of connected agents and their cards
- Route messages between agents that cannot connect directly (NAT, firewalls)
- MAY store a persistent inbox for offline agents
- Brokers announce themselves via the same discovery mechanisms

---

## 8. Connection Lifecycle

```
1. Agent starts → binds to WebSocket port
2. Advertises via mDNS
3. Receives connections from peers
4. On connect: server sends `card` message
5. Client responds with its own `card` message
6. Both sides update local registry
7. Messages flow bidirectionally
8. On disconnect: agent is removed from registry
9. Automatic reconnection with exponential backoff (1s, 2s, 4s, 8s, max 60s)
```

### Heartbeat

The connection MUST be kept alive with `ping`/`pong` every 30 seconds. If no message is received for 90 seconds, the connection is considered dead and closed.

---

## 9. Task Delegation

### Simple Task

```
Sender                   Receiver
  │                         │
  │──── task ──────────────►│
  │                         │ (processing)
  │◄──── result ────────────│
  │                         │
```

### Streaming Progress

```
Sender                   Receiver
  │                         │
  │──── task ──────────────►│
  │◄──── progress (20%) ────│
  │◄──── progress (60%) ────│
  │◄──── progress (90%) ────│
  │◄──── result ────────────│
  │                         │
```

### Human-in-the-Loop

If a task requires human approval, the receiver responds with type `input-required`:

```json
{
  "type": "input-required",
  "id": "...",
  "source": "receiver-agent",
  "target": "sender-agent",
  "reply_to": "<original task id>",
  "payload": {
    "prompt": "Is it OK to send email to john@example.com?",
    "options": ["yes", "no", "modify"]
  }
}
```

The sender (or a human proxy like VekInbox) responds with another `task` message in the same thread:

```json
{
  "type": "task",
  "id": "...",
  "source": "sender-agent",
  "target": "receiver-agent",
  "reply_to": "<input-required message id>",
  "thread": "<original thread id>",
  "payload": {
    "capability": "calendar.write",
    "input": {
      "human_response": "yes",
      "original_input": { ... }
    }
  }
}
```

### Error Handling

Errors follow standard HTTP-inspired codes:

| Code | Meaning |
|------|---------|
| `400` | Bad request — malformed input |
| `401` | Unauthorized — sender cannot request this capability |
| `404` | Capability not found — receiver doesn't have this capability |
| `408` | Timeout — task exceeded the requested timeout |
| `500` | Internal error — something broke on the receiver |
| `503` | Busy — receiver is overloaded, try again later |

---

## 10. Delivery Semantics

| Message Type | Delivery | Description |
|-------------|----------|-------------|
| `task` | At-least-once | Receiver MUST acknowledge by sending `result` or `error` within the timeout |
| `result` | At-most-once | Best-effort delivery back to sender. If sender disconnects, result is lost |
| `progress` | At-most-once | Fire-and-forget intermediate updates |
| `ping` | At-most-once | Fire-and-forget liveness |
| `card` | At-least-once | Re-sent on every connection |

**Timeout:** If a sender doesn't receive `result` or `error` within `input.metadata.timeout_seconds` (default 60), it SHOULD consider the task failed.

**Idempotency:** Task `id` values (UUIDv7) MUST be unique per sender. Receivers SHOULD deduplicate by `(source, id)`.

---

## 11. Transport Binding: WebSocket

This section defines how PolyMesh maps onto WebSocket connections.

### Endpoint

The default WebSocket endpoint is `ws://localhost:9854`. The broker listens on this port.

### Subprotocol

The WebSocket subprotocol is `polymesh.0.1`.

### Connection Initiation

```
CLIENT → SERVER: WebSocket handshake with subprotocol "polymesh.0.1"
SERVER → CLIENT: {"type": "card", "id": "...", "source": "server", "payload": <AgentCard>}
CLIENT → SERVER: {"type": "card", "id": "...", "source": "client", "payload": <AgentCard>}
```

### Message Framing

Each message is a single JSON object, serialized to a string, and sent as a WebSocket text frame. Multiple messages may be sent in either direction concurrently (the protocol is fully asynchronous).

### Close

Either side MAY close the WebSocket at any time. The close reason SHOULD be one of:
- `shutdown` — agent is shutting down
- `reconnect` — agent is reconnecting (will reconnect soon)
- `protocol-error` — malformed message received
- `timeout` — heartbeat missed

---

## 12. Security Model

### Trust Model

PolyMesh operates on a **local trust** model:

- **On localhost:** All agents on the machine are trusted by default. This is appropriate for personal developer machines
- **On LAN:** Agents MAY authenticate via a shared secret set in environment or config
- **Over internet:** PolyMesh does not define auth. Use a tunnel (Cloudflare Tunnel, Tailscale) or WireGuard for remote connections

### Threats Considered

| Threat | Mitigation |
|--------|-----------|
| Rogue agent on localhost | None (local trust model — same as any local process) |
| Rogue agent on LAN | Shared secret authentication (optional) |
| Message injection | WebSocket is encrypted if using WSS. Only applicable over internet |
| Denial of service | Agents MAY rate-limit connections per source IP |
| Capability abuse | Each agent decides which capabilities it exposes. No agent can force another to execute a capability |

### Secrets / Crypto

None. PolyMesh explicitly does not define cryptographic identity. If you need authenticated identity, use a layer below (Tailscale, Cloudflare Access) or above (JWT in message metadata).

---

## 13. Implementation Guide

### Minimal Agent (Node.js, ~100 lines)

```javascript
import { WebSocketServer } from 'ws';
import { createSocket } from 'dgram';

const AGENT_CARD = {
  protocol: 'polymesh/0.1',
  agent_id: 'my-agent',
  display_name: 'My Custom Agent',
  version: '1.0.0',
  capabilities: [
    {
      name: 'agent.ping',
      description: 'Liveness check',
      input_schema: { type: 'object' },
      output_schema: { type: 'object' }
    }
  ],
  endpoints: [{ transport: 'ws', location: 'ws://localhost:9854', priority: 0 }],
  metadata: { description: 'A simple PolyMesh agent', tags: ['example'] }
};

// Start WebSocket broker
const wss = new WebSocketServer({ port: 9854 });

wss.on('connection', (ws) => {
  // Send our card
  ws.send(JSON.stringify({ type: 'card', payload: AGENT_CARD }));
  
  ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    handleMessage(ws, msg);
  });
});

function handleMessage(ws, msg) {
  if (msg.type === 'card') {
    registry.set(msg.source, msg.payload);
    console.log(`Discovered agent: ${msg.source}`);
  } else if (msg.type === 'task') {
    executeTask(msg).then(result => {
      ws.send(JSON.stringify({
        type: 'result',
        reply_to: msg.id,
        source: AGENT_CARD.agent_id,
        target: msg.source,
        payload: result
      }));
    });
  }
}

async function findAgent(capability) {
  for (const [id, card] of registry) {
    if (card.capabilities.some(c => c.name === capability)) return id;
  }
  return null;
}
```

### Python

```python
import asyncio, json, socket
import websockets

AGENT_CARD = {
    "protocol": "polymesh/0.1",
    "agent_id": "py-agent",
    "display_name": "Python Agent",
    "capabilities": [
        {"name": "agent.ping", "description": "Liveness check"}
    ],
    "endpoints": [{"transport": "ws", "location": "ws://localhost:9855"}]
}

async def handler(websocket):
    await websocket.send(json.dumps({"type": "card", "payload": AGENT_CARD}))
    async for raw in websocket:
        msg = json.loads(raw)
        if msg["type"] == "task":
            result = await execute(msg)
            await websocket.send(json.dumps({
                "type": "result",
                "reply_to": msg["id"],
                "payload": result
            }))

async def main():
    async with websockets.serve(handler, "localhost", 9855):
        await asyncio.Future()

asyncio.run(main())
```

### mDNS Registration (Node.js)

```javascript
import { Bonjour } from 'bonjour-service';

const bonjour = new Bonjour();

// Advertise on _polymesh._tcp
bonjour.publish({
  name: `polymesh-${AGENT_CARD.agent_id}`,
  type: 'polymesh',
  port: 9854,
  txt: {
    agent_id: AGENT_CARD.agent_id,
    version: '0.1.0',
    capabilities: AGENT_CARD.capabilities.map(c => c.name).join(',')
  }
});

// Discover peers
bonjour.find({ type: 'polymesh' }, (service) => {
  console.log(`Found agent: ${service.txt.agent_id} at ${service.host}:${service.port}`);
  connectTo(service.host, service.port);
});
```

---

## 14. Reference Implementation

A reference implementation will be provided in this repository under `ref/`:

| Language | Status | Location |
|----------|--------|----------|
| TypeScript | Planned | `ref/typescript/` |
| Python | Planned | `ref/python/` |
| Rust | Planned | `ref/rust/` |

Each reference implementation includes:
- WebSocket broker (server)
- Agent client (connect, send, receive)
- mDNS discovery (optional)
- CLI for testing

---

## 15. FAQ

**Q: How is this different from A2A (Agent-to-Agent protocol)?**
A: A2A is designed for enterprise multi-org scenarios — full lifecycle management, human-in-loop formalization, card resolution via HTTPS. PolyMesh targets the 90% use case: "I have 3 agents on my laptop, I want them to talk to each other." PolyMesh is simpler (no lifecycle states), local-first (no DNS needed), and usable in ~100 lines of code.

**Q: How is this different from MCP?**
A: MCP is agent→tool. PolyMesh is agent→agent. They complement each other: Agent A uses MCP to access tools, PolyMesh to talk to Agent B.

**Q: Do I need a broker?**
A: On localhost, no. Agents can connect directly. A broker helps when agents are behind NAT or need message queuing.

**Q: What if two agents claim the same agent_id?**
A: Last-wins on connection. Duplicate IDs are a configuration error.

**Q: Can I use this over the internet?**
A: Yes, with a tunnel (Tailscale, Cloudflare Tunnel, WireGuard). PolyMesh does not define internet-level discovery — that's the tunnel's job.

**Q: Does PolyMesh use blockchain?**
A: No. Zero blockchain, zero crypto, zero gas fees. It's WebSockets and JSON.

---

## Appendix A: Message Type State Machine

```
                 ┌──────────┐
                 │  card    │
                 └────┬─────┘
                      │
              ┌───────▼────────┐
              │  Established   │
              │  (session)     │
              └───────┬────────┘
                      │
          ┌───────────┼───────────┐
          │           │           │
          ▼           ▼           ▼
      ┌───────┐  ┌───────┐  ┌───────┐
      │ ping  │  │ task  │  │ card  │
      └───┬───┘  └───┬───┘  └───┬───┘
          │           │           │
          ▼           ▼           │
      ┌───────┐  ┌───────┐      │
      │ pong  │  │progress│      │
      └───────┘  └───┬───┘      │
                     │           │
                     ▼           │
                ┌────────┐       │
                │ result │       │
                │ error  │       │
                └────────┘       │
                          ┌──────▼──────┐
                          │  Reconnect  │
                          │  or Close   │
                          └─────────────┘
```

## Appendix B: Wire Format (BNF)

```
message      = "{" type "," id "," timestamp "," source "," target ["," thread] ["," reply_to] "," payload "}"
type         = "type: \"" msg_type "\""
msg_type     = "card" | "task" | "progress" | "result" | "ping" | "pong" | "error" | "input-required"
id           = "id: \"" uuid_v7 "\""
uuid_v7      = 8HEX "-" 4HEX "-7" 3HEX "-" 4HEX "-" 12HEX
timestamp    = "timestamp: \"" iso8601 "\""
source       = "source: \"" agent_id "\""
target       = "target: \"" (agent_id | "broadcast") "\""
thread       = "thread: \"" string "\""
reply_to     = "reply_to: \"" uuid_v7 "\""
payload      = "payload: " json_value
agent_id     = ALPHA (ALPHA | DIGIT | "-" | "_" | ".")*
```

## Appendix C: Reserved Port Numbers

| Port | Use |
|------|-----|
| 9854 | Default PolyMesh broker |
| 9850-9859 | Recommended range for agent endpoints |
| 5353 | mDNS (standard) |

---

*PolyMesh Protocol Specification v0.1.0 — MIT License*
