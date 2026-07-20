You are building PolyMesh v0.2.0 — durable persistence and multi-instance routing layer.

Read the full V2-ROADMAP.md at /home/ubuntu/polymesh/V2-ROADMAP.md for the architecture design.

YOUR JOB: Build Phase 1 of v0.2.0 using spawn_agent internally.

SUB-AGENT 1 — Durable Persistence Layer
- Read packages/broker/src/registry.ts (current in-memory registry)
- Read SPEC.md section 3 (durable persistence from security appendix) 
- Replace the in-memory registry with async storage interfaces:
  RegistryStore / TaskRouteStore / InboxStore / OutboxStore
- Implement SQLite backend using better-sqlite3 (journal_mode=WAL, synchronous=FULL, BEGIN IMMEDIATE)
- Tables: agent_instances, sessions, ingress_inbox, task_routes, execution_tasks, task_events, outbox, cancellation_tombstones
- Keep in-memory fallback for tests
- The current Registry class stays for tests; add DurableRegistry that extends it

SUB-AGENT 2 — Multi-Instance Routing
- Implement weighted rendezvous hashing for instance selection
- Health states: HEALTHY/SUSPECT/UNHEALTHY/DRAINING/OFFLINE
- Instance pinning: route locks to selected instance for task lifecycle
- Stale fence detection and discard
- Add to packages/broker/src/broker.ts

SUB-AGENT 3 — Token Bucket Rate Limiting
- Hierarchical token buckets keyed by (mesh_id, principal_id, operation_class)
- Per-connection, per-principal, per-target buckets
- zstd compression negotiation (also protocol extension)
- Add to packages/broker/src/broker.ts

SUB-AGENT 4 — Write tests for everything
- Durable persistence: crash recovery, transactional inbox/outbox, dedup persistence
- Multi-instance: rendezvous consistency, health transitions, fence enforcement
- Rate limiting: bucket refill, hierarchical limits, backlog under load

RULES:
- Use better-sqlite3 for SQLite (add to package.json)
- The current tests MUST still pass
- Run npm test after all changes
- Output "DONE" with test results summary

NO web searches. Use your training knowledge.
