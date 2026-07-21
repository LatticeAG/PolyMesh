You are the PolyMesh Protocol Architect. Read the appended V2-SPEC-ULTRA.md, PYTHON-SDK-SPEC.md, current SPEC.md, and the repo state.

TASK: Produce a comprehensive "PolyMesh v0.3.0 — What Next" document. Use spawn_agent internally to evaluate.

SUB-AGENT 1 — Protocol Gaps
What's missing from the protocol spec that a v0.3.0 release should include?
- EdDSA envelope signing for transport-independent authentication
- MCP bridge (allow PolyMesh agents to consume MCP servers)
- Agent-to-agent streaming (long-running tasks with continuous output, not just progress updates)
- Pub/sub event channels (agents subscribe to topics)
- Delegated auth (Agent A authorizes Agent B to act on its behalf)
- Protocol compression on Unix sockets
- Multi-hop routing (A→B→C forwarding)
- Evaluate each: effort, benefit, complexity

SUB-AGENT 2 — SDK Gaps
What's missing from the TypeScript and Python SDKs?
- Python: envelope signing, streaming tasks, mDNS discovery (spec'd but not built)
- TypeScript: CLI improvements, plugin system, config file format
- Both: documentation site, quick-start template, Docker image
- Evaluate each: effort, benefit, complexity

SUB-AGENT 3 — Ecosystem & Adoption
What would make PolyMesh actually get used?
- GitHub Actions CI/CD for published packages
- Docker Compose demo (broker + two agents exchanging tasks)
- Hermes Agent integration (as a skill)
- LangChain / CrewAI tool adapter (let those frameworks use PolyMesh)
- Discord bot that runs a broker and lets people experiment
- Published RFC / whitepaper explaining the protocol
- Evaluate each: effort, benefit, complexity

SUB-AGENT 4 — CF Workers Deployment
The REST/SSE Gateway is built. What's needed to deploy it?
- wrangler.toml config for Workers relay
- SessionDO and MailboxDO Durable Objects
- Cloudflare Tunnel for broker<>worker connectivity
- Free-tier vs paid-tier hosting costs
- Evaluation: effort, benefit, complexity

SUB-AGENT 5 — v0.3.0 Release Plan
Compile the findings into a ranked roadmap:
- Group into: Protocol, SDK, Infrastructure, Ecosystem
- Score each item by (impact × reach) / effort
- v0.3.0 candidate items (what fits in one release)
- v0.4.0+ candidates
- What to deprecate or simplify

RULES:
- Output a single compiled markdown document
- Each item must have: name, what it is, effort (small/medium/large), impact (low/medium/high), recommendation
- Target 1000-2500 lines
- Be honest about what's actually valuable vs just cool

NO web searches. Use your training knowledge and the attached documents.
