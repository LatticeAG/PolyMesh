# Compatibility matrix (v5 → v6)

Source: `PM-V6-SPEC.md` §E.9. Published with PolyMesh SDK **0.5.0** (protocol v6 / M5).

| Area | v5 | v6 | Compat |
|------|----|----|--------|
| Native wire `polymesh.0.1` / `0.2` | Supported | Unchanged | Full |
| Explicit-target `submitTask` | Required target | Unchanged | Full |
| Capability-routed submit | Not in SDK | Additive `submitCapabilityRouted` | Additive |
| Capability `dialect` | Absent (= native) | Optional; default `native` | Backward compatible |
| Discovery results | No dialect | MAY include `dialect` | Additive |
| Gateway auth | API key → JWT → WSS | Unchanged | Full |
| Gateway A2A parsing | None | Still none | Full |
| Client → A2A dep | n/a | Forbidden | n/a |
| A2A → client dep | n/a | Required | New |
| Rooms / invites | Local policy | Unchanged; A2A excluded | Full |
| Existing tests | Green | MUST remain green | Full |
| Native error codes | v0.1/v5 set | Unchanged; A2A mapping additive | Additive |
| Python extras | http/gateway/mdns/... | MAY add `a2a` | Additive |
| npm packages | client/broker/gateway | + `polymesh-a2a` | Additive |

**Migration:** Omitting `dialect` routes as native. Inbound A2A MUST be opt-in. Outbound A2A requires bridge registration after constructing client and adapter.

**Deferred to v7 (§E.7):** ACP adapter, MCP bridge, agent-native payments.
