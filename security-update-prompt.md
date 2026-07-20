You are the PolyMesh Security Lead. You have access to the full SPEC.md (appended below via stdin) which includes the v0.1.0 spec plus a new 91K-token Security Reinforcement audit.

YOUR JOB: Use spawn_agent to create sub-agents that work in parallel to upgrade PolyMesh to v1.5 Security Level. Each sub-agent handles one section:

SUB-AGENT 1 — Protocol Security Updates (broker.ts, protocol.ts, client.ts)
- Read the current source at packages/broker/src/protocol.ts, broker.ts, registry.ts
- Read packages/client/src/client.ts, cli.ts
- Apply ALL Critical/High severity fixes from the Security Reinforcement appendix
- Especially: fix the authorize() truthiness bug, add timingSafeEqual for tokens, add bounded JSON parsing with duplicate key rejection, fix the from vs source field naming, fix the result vs task.completed message type issue
- Output the exact code changes needed

SUB-AGENT 2 — Policy Engine Security (§9.8, POL-01 through POL-06)
- Implement the PolicyEngine class with discriminated authorization decisions
- Add SQL-parameterized query pattern
- Add authorization leases with fencing
- Add resource scope enforcement (not the stub that returns true)
- Add audit logging with chain integrity
- Remove custom JS/JSONata filters (add deterministic built-in filters only)
- Output the exact code changes

SUB-AGENT 3 — Transport Security (TRP-01 through TRP-07)
- Close-code abuse protection
- WebSocket upgrade validation (origin check, subprotocol enforcement)
- Token rotation atomicity
- mDNS security hardening
- TLS 1.3 requirements in the spec text
- Output exact spec amendments

SUB-AGENT 4 — SECURITY.md (public-facing security document)
- Write a COMPLETE SECURITY.md for the poly mesh repository
- Include: threat model table, deployment security checklist, known attack surface, configuration hardening guide, security boundaries, responsible disclosure policy
- This document should be PUBLIC-FACING — usable as a security landing page for the repo
- It must NOT leak proprietary spec content, only security guidance
- Target 500-1000 lines

RULES:
- Use spawn_agent to delegate, wait_agent to collect
- Apply changes directly to the files
- Run npm test after all changes
- Output "DONE" when finished

NO web searches. Use your training knowledge only.
