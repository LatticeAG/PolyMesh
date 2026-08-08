# Competitive positioning

Source of truth: `PM-V6-SPEC.md` Part D. If this document and the spec ever disagree, the spec wins and this file needs an update.

## Framing

PolyMesh v6 adopts A2A as a leaf dialect and hardens capability routing in the mesh core. This document does not reopen that decision. It presents PolyMesh as the network product that speaks A2A, not as a rival wire standard.

Every claim below follows the three-layer model:

```
┌─────────────────────────────────────────────────────┐
│  PRODUCT LAYER (PolyMesh owns this)                 │
│  - Capability routing (dispatch by what an agent    │
│    can do, not by address)                          │
│  - Mesh rooms, permissions, invite gates            │
│  - Local-first runtime + NAT-friendly tunnels       │
│  - Task lifecycle (submit→accept→progress→terminal) │
│  - Multi-language SDK DX (TS + Python)              │
│  - Free hosted relay (PM-G)                         │
├─────────────────────────────────────────────────────┤
│  WIRE LAYER (PolyMesh speaks these as dialects)     │
│  - polymesh.0.2 (native envelope)                   │
│  - A2A (JSON-RPC task exchange)  ← v6               │
│  - (future: MCP for tools, ACP for editor UIs)      │
├─────────────────────────────────────────────────────┤
│  STANDARDS LAYER (adopted, never competed with)     │
│  - A2A protocol (Linux Foundation)                  │
│  - MCP (Anthropic)                                  │
│  - ACP (Zed)                                        │
└─────────────────────────────────────────────────────┘
```

Product-layer wins are fair game for differentiation. Wire-layer and standards-layer claims must not imply PolyMesh replaces A2A, MCP, or ACP. Dialects translate at the leaf. The mesh core does not depend on any wire dialect.

## Landscape snapshot

| Project | What it is | What it is not |
|---------|------------|----------------|
| A2A (Linux Foundation, 150+ orgs) | Enterprise agent-to-agent wire standard; point-to-point JSON-RPC tasks over HTTPS; static AgentCard discovery | A mesh, a router, rooms, offline runtime, or permissions topology |
| ACP (Zed) | Editor <-> coding-agent UI protocol | An agent-to-agent network |
| AgentChat (agentchat.me) | Hosted identity, inbox, DMs ("WhatsApp for agents"); address-only chat | Capability dispatch, offline mesh, structured task completion with re-route |
| Caspian (TryCaspian) | Agent-to-human channel layer (email, WhatsApp, Slack, Discord from one handler) | Agent-to-agent mesh or capability routing |
| PolyMesh | Product-layer mesh: capability routing, rooms, permissions, local-first, task lifecycle; speaks A2A as a dialect | A competing wire format; a hosted DM identity platform |

## Positioning statements

These four sentences are the source of truth for README banners, pull quotes, and launch copy. Copy them exactly. Do not paraphrase inside the quote marks.

### 1. The neighborhood

"MCP gave agents tools. A2A gave agents a phone book. PolyMesh gives them a neighborhood - routing, rooms, permissions, and it works offline."

MCP solved tools: an agent can call structured functions. A2A solved directory and dial tone: an agent can find another agent's card and open a task over HTTPS. Neither one is a neighborhood. A neighborhood needs routing (who should take this job), rooms (who is in scope together), permissions (who is allowed to ask), and a way to keep working when the wider internet is gone.

PolyMesh sits in the product layer. It leaves MCP and A2A in the standards layer, speaks A2A as a wire dialect when needed, and owns what those standards don't: capability dispatch, membership topology, local authorization, and local-first operation. Use this statement for the shortest version of the stack story: tools, then phone book, then neighborhood.

### 2. The switchboard

"A2A is the phone line between agents. PolyMesh is the switchboard, the address book, and the wires that work when the phones are offline."

A phone line is necessary and not sufficient. Two known endpoints can exchange tasks reliably over A2A. They still need something to pick a capable worker, track who is healthy and authorized, and keep working when public endpoints are unreachable.

PolyMesh is that switchboard. On the wire it can speak A2A. On the product layer it ranks candidates, prefers native mesh paths, and re-routes on retryable failure. Offline is not a marketing word here: the launch demo runs three agents on one laptop with no internet. Use this statement when the audience already respects A2A and wants to know what comes next.

### 3. The factory floor

"AgentChat is WhatsApp for agents - message @alice. PolyMesh is the factory floor - dispatch the task to whoever can do it, track it to completion, re-route when a worker fails."

Addressable chat is useful. If you know `@alice` and want a conversation, a hosted inbox wins on social simplicity. Factory work is different: you don't care which badge is on the worker, only that the capability exists, the task is accepted, progress is visible, and a failed worker doesn't strand the job.

PolyMesh doesn't pretend these are the same product. It doesn't try to out-WhatsApp WhatsApp. It ships capability routing, structured lifecycle, and bounded re-route inside a mesh room. Use this statement when comparing to AgentChat, and stay respectful of their lane.

### 4. Speaking A2A

"We don't compete with A2A. We speak it. The mesh routes by capability; the wire is whatever the ecosystem speaks."

Competing with a Linux Foundation wire standard backed by 150+ organizations is a losing strategy and a confused product story. PolyMesh adopts A2A as a leaf dialect: translation happens at the agent edge, inbound and outbound, never inside a gateway that "learns" A2A and becomes a central protocol brain.

Capability routing stays native to the mesh. When the best or only peer is A2A-native, the adapter translates after the router resolves the target. When both peers are mesh members, native dialect wins on preference. Use this statement whenever messaging risks drifting into "we replace A2A." It's the correction sentence.

## Competitive matrix

| Dimension | PolyMesh | A2A | ACP | AgentChat | Caspian |
|-----------|----------|-----|-----|-----------|---------|
| Agent-to-agent | YES | YES | n/a (UI protocol; not a network protocol) | YES | no |
| Capability-based routing | YES | no | n/a (different layer) | no | no |
| Multi-agent topology / rooms | YES | no (wire is point-to-point; multi-agent runtimes on top of A2A exist independently) | n/a (different layer) | DMs + @mention group chats; no capability dispatch or re-route; hosted topology | no |
| Local-first offline | YES | no | n/a (different layer) | no | no |
| Structured task lifecycle | YES | YES (endpoint-local states); distributed mesh re-route: n/a | n/a (different layer) | no | no |
| Permissions within network | YES | partial | n/a (different layer) | platform | no |
| Multi-language SDK | YES (TS+Python) | YES (many) | partial | partial (Python-led) | YES (TS+Python) |
| Interops with A2A ecosystem | YES (v6 spec; ships with M5 release) | native | n/a | via A2A | via A2A |
| Hosted identity / DMs | no (rejected) | no | no | YES | no |
| Agent-to-human channels | no (out of scope) | no | no | no | YES |
| Editor UI protocol | deferred (v7 ACP) | no | YES | no | no |
| Discovery model | YES (local-first + mesh registry) | static AgentCard URL | editor session | hosted directory | channel connectors |
| Delivery semantics | YES (at-least-once + idempotency) | at-most-once HTTP | session/UI | chat delivery | channel delivery |
| Authorization locus | YES (local agent policy) | per-endpoint credentials | editor/agent session | platform account | channel auth |

### Distributed lifecycle, split out

The "structured task lifecycle" row bundles two different claims. Here they are separately, since this is the one A2A shops push back on most:

| Dimension | PolyMesh | A2A | ACP | AgentChat | Caspian |
|-----------|----------|-----|-----|-----------|---------|
| Structured task lifecycle (single endpoint) | YES | YES | n/a | no | no |
| Distributed lifecycle with mesh re-route | YES | n/a | n/a | no | no |

A2A defines full task states between two known endpoints. It has no concept of a mesh re-routing that task to a different endpoint after a failure. That's a PolyMesh product-layer claim, not a gap in the A2A wire format.

### Reading the matrix

- YES means the product ships or specifies the capability as a first-class surface.
- partial means related behavior exists but lacks PolyMesh's product-layer semantics.
- Evidence lines below are normative for docs. Don't invent softer or stronger claims without updating `PM-V6-SPEC.md` Part D.

### Evidence summary

- **Agent-to-agent.** PolyMesh, A2A, and AgentChat all move messages between agents. ACP is a UI protocol, not a network protocol. Caspian talks to humans, not other agents.
- **Capability-based routing.** PolyMesh's router ranks candidates by capability, health, permission, dialect preference, locality, and freshness, with explicit targeting optional. A2A tasks a known AgentCard URL. AgentChat addresses a handle. Neither picks among peers by what they can do.
- **Multi-agent topology and rooms.** PolyMesh has mesh membership, rooms, and invite gates. A2A WIRE is point-to-point; multi-agent runtimes on top of A2A exist independently (ADK, community routers). PolyMesh differentiation is integrated routing + rooms + local-first in one product layer. AgentChat has DMs and @mention group chats with no capability dispatch or re-route; hosted topology.
- **Local-first offline.** PolyMesh runs a local broker with same-host and LAN discovery, no public endpoint required. The launch demo runs with no internet. A2A assumes reachable HTTPS AgentCard endpoints. AgentChat needs its hosted service.
- **Structured task lifecycle.** See the split table above.
- **Permissions within network.** PolyMesh enforces capability authorization locally, per caller, target, and capability, while the gateway stays blind. A2A auth is per-endpoint credentials with no mesh-wide policy. AgentChat access control is the platform's account model.
- **Multi-language SDK.** PolyMesh ships first-party TypeScript and Python SDKs, with matching A2A adapter packages in both. A2A's ecosystem spans many languages under the Linux Foundation umbrella. AgentChat's public traction skews Python.
- **Interop with the A2A ecosystem.** `@latticeag/polymesh-a2a` and `polymesh-a2a` translate AgentCard, skills, and task states at the leaf, and ship with the M5 release. Native mesh paths stay preferred. A2A is the ecosystem wire itself.
- **Hosted identity and DMs.** Rejected for PolyMesh as a direction decision. It's AgentChat's core product.
- **Agent-to-human channels.** Out of scope for PolyMesh. It's Caspian's core product.
- **Editor UI protocol.** Deferred to v7 for PolyMesh. It's ACP's core product.
- **Discovery model.** PolyMesh uses local-first announcement plus a mesh registry with dialect tags, no global phone book required. A2A discovery is a static AgentCard URL. AgentChat is a hosted directory.
- **Delivery semantics.** PolyMesh uses at-least-once delivery with idempotency keys and replay of canonical outcomes. A2A is at-most-once over HTTP. AgentChat is chat-inbox delivery.
- **Authorization locus.** PolyMesh enforces policy locally on each agent. A2A trusts whatever the endpoint accepts. AgentChat trusts the platform account.

## Honest limits

What PolyMesh is not:

- Not an A2A replacement.
- Not a hosted DM identity network.
- Not an editor UI protocol in v6.
- Not an agent-to-human channel suite.

### When A2A alone is enough

Admit these cases plainly. Don't route people to a mesh they don't need.

1. **Two known HTTPS agents.** The caller already knows the other agent's AgentCard URL. Tasking it directly is correct. No candidate set, no ranking, no re-route requirement.
2. **Static topology.** Membership doesn't change. Failures get handled by human ops or an external orchestrator, not by mesh routing.
3. **Enterprise already standardized on A2A point-to-point.** Security review, gateways, and compliance already assume A2A endpoints. Adding a mesh is optional integration work, not a mandate.
4. **Single durable worker.** Only one agent can do the job. Capability routing among peers is empty math.

In these cases, recommend A2A. Suggest the leaf dialect only if those agents later join a PolyMesh room.

### What the matrix forbids

Docs must not:

- Claim PolyMesh beats A2A on wire completeness, org count, or standards politics.
- Claim PolyMesh is a hosted DM product because AgentChat is popular.
- Treat Caspian overlap as competition. Compliment the agent-to-human lane and stay in the agent-to-agent mesh lane.
- Claim ACP replacement. Defer, and optionally interoperate later.
- Collapse A2A endpoint-local task states into "no task lifecycle," or inflate them into "same as PolyMesh's distributed mesh lifecycle with re-route."

## FAQ

### Why not just use the A2A plugin?

**Q: Why not just use the A2A plugin?**

A: Use A2A when you already know which agent to call and that agent is reachable over HTTPS. That's the right tool for static point-to-point work. PolyMesh is for everything that starts after the phone book: pick a capable peer in a room, keep working offline, re-route when a worker dies, and enforce local permissions. v6 also speaks A2A as a dialect, so choosing the mesh doesn't mean abandoning the standard.

If you already have two known agents with stable HTTPS AgentCards, a static topology, and enterprise point-to-point A2A working, you may not need PolyMesh today. Use A2A.

### When PolyMesh wins

| Need | Why the A2A plugin alone falls short | What PolyMesh adds |
|------|----------------------------------|--------------------|
| Capability dispatch | You must pick the URL | Router selects among advertisers |
| Rooms / topology | No membership graph | Mesh rooms + invites |
| Offline / local-first | Needs reachable endpoints | Laptop / LAN mesh without public URLs |
| Re-route on worker failure | Caller's problem | Bounded re-route with exclusion set |
| Permissions topology | Per-endpoint credentials only | Local capability authorization among members |
| Mixed dialects | You speak one wire | Mesh routes; leaf speaks A2A when required |
| Observability of routing | Endpoint logs only | `task.routed` with candidate counts and reroute counts |

### AgentChat

**Q: How is PolyMesh different from AgentChat?**

A: AgentChat is WhatsApp for agents: hosted identity, inbox, DMs, message `@alice`. PolyMesh is the factory floor: dispatch by capability, track structured tasks to completion, re-route when a worker fails, run local-first.

We're not trying to win hosted-handle network effects. If your problem is conversational addressing between known agents on a hosted inbox, AgentChat fits. If your problem is work dispatch across a mesh of interchangeable capable peers, PolyMesh fits.

**Q: Can I use both?**

A: At the organization level, yes: a chat lane for humans-in-the-loop conversation, a mesh lane for capability work. PolyMesh doesn't implement AgentChat-style hosted DMs and doesn't claim to.

**Q: Will you add `@handles`?**

A: Hosted DM identity as a core bet is rejected for v6.

### Caspian

**Q: How is PolyMesh different from Caspian?**

A: Caspian is agent-to-human channel infrastructure (email, WhatsApp, Slack, Discord, and similar) behind one handler model. PolyMesh is agent-to-agent mesh infrastructure. Different layers. A production system might use Caspian to talk to humans and PolyMesh to coordinate agents.

**Q: Do you send Slack messages for us?**

A: No. Out of scope.

### ACP

**Q: How is PolyMesh different from ACP?**

A: ACP (Zed) is an editor to coding-agent UI protocol. PolyMesh is not an IDE protocol. We don't claim ACP replacement.

**Q: Will you support ACP?**

A: Deferred to v7 as a possible UI surface dialect.

**Q: Should coding-agent authors pick ACP or PolyMesh?**

A: If the surface is an editor session, start with ACP. If the surface is multiple agents coordinating tasks in a mesh, including agents that may later appear in an editor, use PolyMesh for the mesh and keep ACP for the UI edge when available.

### Side-by-side

| Question behind the question | Prefer | Avoid saying |
|------------------------------|--------|--------------|
| Who do I message? | AgentChat (handles) or A2A (URLs) | "PolyMesh is WhatsApp" |
| Who can do this job? | PolyMesh capability routing | "Just DM the team agent" |
| How do I talk to a human on Slack? | Caspian (or similar) | "We do channels too" |
| How does my editor drive a coding agent? | ACP | "PolyMesh replaces ACP" |
| How do two enterprise agents exchange a task over HTTPS? | A2A | "Don't use A2A" |
| How do N agents finish work offline with re-route? | PolyMesh | "A2A plugin is enough" |

### The complementary stack

```
Human channels          Editor UI              Agent wire           Agent network
──────────────         ─────────             ──────────          ─────────────
Caspian (A2H)           ACP (Zed)              A2A (LF)             PolyMesh mesh
                                                                   (+ A2A dialect)
```

PolyMesh owns the rightmost column. It speaks the agent wire. It does not claim the other columns.

## Offline re-route demo

**Thesis:** three agents on a laptop, no internet. One drops mid-task. The mesh re-routes the task to a peer with the capability. Zero config, no public endpoints.

This is the v6 launch demo. It's unbeatable on the axes that matter against A2A (needs endpoints), AgentChat (hosted), and ACP (not agent-to-agent).

Run it: `scripts/demo-offline-reroute.sh`

A successful run shows all nine of these:

1. **Offline proof.** The outbound internet check fails.
2. **Membership.** Three agents are present in one local mesh/room without cloud registration.
3. **Capability discovery.** Both workers are listed for the demo capability before submit.
4. **Capability dispatch.** The first route selects a worker without an explicit target address in the submit call.
5. **Lifecycle.** Events include submit, route, accept, progress, and terminal success.
6. **Failure.** Worker A disappears mid-task and gets classified as a retryable failure.
7. **Re-route.** The second route selects worker B, the exclusion set contains worker A, and the reroute count increments.
8. **Terminal success.** The coordinator receives a completed result from worker B.
9. **No public endpoints.** Process args and logs show no `https://` AgentCard URLs for the workers.

## Messaging bans

Docs, README, social copy, demo scripts, and partner decks must not:

1. **Say PolyMesh replaces A2A.** Banned: "A2A alternative," "better than A2A," "A2A killer," "you don't need A2A anymore."
2. **Position as a WhatsApp competitor.** Banned: "WhatsApp for agents" as our own label, "DM any agent" as the hero feature, "inbox for agents" as the product thesis.
3. **Compete on wire format.** Banned: "our JSON is the new standard," "fork A2A," "A2A-compatible but proprietary wire that supersedes LF A2A."
4. **Erase honest limits.** Banned: implying A2A never has task states, implying AgentChat can't do agent-to-agent chat, implying ACP is agent-to-agent.
5. **Steal adjacent lanes.** Banned: claiming agent-to-human channel leadership (Caspian's lane) or editor UI leadership (ACP's lane) in v6.
6. **Puffery.** Banned: groundbreaking, pivotal, revolutionary, unprecedented, "the only protocol that matters."
7. **Em dashes in normative banners.** The verbatim statements use hyphens. Keep it that way.

Before publishing anything that names a competitor, check:

- Does the claim live in the product layer?
- If it mentions A2A, does it adopt or speak, rather than replace?
- If it mentions AgentChat, does it respect the DM lane and stay on the factory-floor point?
- If it mentions Caspian or ACP, does it defer or complement rather than absorb?
- Does the offline claim match a demo we can actually run?
- Is the three-layer model still true after this sentence?

If any of those fail, rewrite before shipping.
