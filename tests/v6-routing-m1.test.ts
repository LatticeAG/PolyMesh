/**
 * PolyMesh v6 M1 — capability routing engine tests (§E.4.2 + Appendix H).
 */
import { describe, expect, it } from "vitest";

import {
  APPENDIX_H_VECTOR_IDS,
  CapabilityRouter,
  HEARTBEAT_MS,
  ROUTING_ERROR_CODES,
  RoutingError,
  capabilityExactMatch,
  capabilityGlobMatch,
  createCapabilityRouter,
  freezeRegistryView,
  freshnessBucket,
  isRetryableFailure,
  runAllAppendixHVectors,
  type RegistryAgentEntry,
  type RegistryView,
  type RoutingCandidate,
} from "../packages/client/src/router.js";

const FIXED_NOW = "2026-08-08T12:00:00.000Z";
const FIXED_NOW_MS = Date.parse(FIXED_NOW);

function agent(partial: {
  agent_id: string;
  capabilities: RegistryAgentEntry["capabilities"];
  health?: RegistryAgentEntry["health"];
  locality?: RegistryAgentEntry["locality"];
  last_seen?: string | null;
  mesh_member?: boolean;
  instance_id?: string;
  perm_hint?: RegistryAgentEntry["perm_hint"];
}): RegistryAgentEntry {
  return {
    agent_id: partial.agent_id,
    capabilities: partial.capabilities,
    health: partial.health ?? "healthy",
    locality: partial.locality ?? "lan",
    last_seen: partial.last_seen === undefined ? FIXED_NOW : partial.last_seen,
    mesh_member: partial.mesh_member ?? true,
    instance_id: partial.instance_id,
    perm_hint: partial.perm_hint,
  };
}

function registry(...agents: RegistryAgentEntry[]): RegistryView {
  return freezeRegistryView({ agents, last_refreshed_at: FIXED_NOW });
}

function router(view?: RegistryView, opts: ConstructorParameters<typeof CapabilityRouter>[0] = {}) {
  return createCapabilityRouter({
    registry: view ?? registry(),
    observedAt: () => FIXED_NOW,
    ...opts,
  });
}

describe("v6 M1 capability routing", () => {
  it("routing_capability_route_basic_native", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.cal",
          locality: "same_host",
          capabilities: [{ name: "calendar.check", dialect: "native" }],
        }),
      ),
    );
    const { winner, routed } = r.capabilityRoute({
      capability: "calendar.check",
      task_id: "t-basic",
    });
    expect(winner.agent_id).toBe("org.polymesh.cal");
    expect(winner.dialect).toBe("native");
    expect(routed.type).toBe("task.routed");
    expect(routed.chosen_agent).toBe("org.polymesh.cal");
    expect(routed.candidate_count).toBe(1);
    expect(routed.reroute_count).toBe(0);
  });

  it("routing_dialect_preference_native_over_a2a", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.dual",
          capabilities: [
            { name: "calendar.check", dialect: "a2a", a2a_url: "https://a2a.example/cal" },
            { name: "calendar.check", dialect: "native" },
          ],
        }),
      ),
    );
    const { winner } = r.capabilityRoute({ capability: "calendar.check" });
    expect(winner.dialect).toBe("native");
    expect(winner.agent_id).toBe("org.polymesh.dual");
  });

  it("routing_locality_preference_same_host_over_lan", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.lan-peer",
          locality: "lan",
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
        agent({
          agent_id: "org.polymesh.local",
          locality: "same_host",
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
      ),
    );
    const { winner, routed } = r.capabilityRoute({ capability: "ping" });
    expect(winner.agent_id).toBe("org.polymesh.local");
    expect(routed.locality_tier).toBe("same_host");
  });

  it("routing_freshness_bucket_quantization", () => {
    const g = HEARTBEAT_MS.same_host;
    const aMs = FIXED_NOW_MS - 5_000;
    const bMs = FIXED_NOW_MS - 10_000;
    const cMs = FIXED_NOW_MS - g - 1_000; // previous bucket
    expect(freshnessBucket(aMs, "same_host")).toBe(freshnessBucket(bMs, "same_host"));
    expect(freshnessBucket(aMs, "same_host")).not.toBe(freshnessBucket(cMs, "same_host"));

    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.b",
          locality: "same_host",
          last_seen: new Date(bMs).toISOString(),
          capabilities: [{ name: "echo", dialect: "native" }],
        }),
        agent({
          agent_id: "org.polymesh.a",
          locality: "same_host",
          last_seen: new Date(aMs).toISOString(),
          capabilities: [{ name: "echo", dialect: "native" }],
        }),
      ),
    );
    // Same bucket → Pref4 RR; cursor 0 → Unicode-first agent_id.
    const { winner } = r.capabilityRoute({ capability: "echo" });
    expect(winner.agent_id).toBe("org.polymesh.a");
  });

  it("routing_round_robin_advance_atomic_under_concurrency", async () => {
    const view = registry(
      agent({
        agent_id: "org.polymesh.worker-a",
        capabilities: [{ name: "work", dialect: "native" }],
      }),
      agent({
        agent_id: "org.polymesh.worker-b",
        capabilities: [{ name: "work", dialect: "native" }],
      }),
      agent({
        agent_id: "org.polymesh.worker-c",
        capabilities: [{ name: "work", dialect: "native" }],
      }),
    );
    const r = router(view);
    const N = 30;
    const candidates: RoutingCandidate[] = view.agents.map((a) => ({
      agent_id: a.agent_id,
      capability: "work",
      dialect: "native" as const,
      locality: a.locality,
      last_seen_ms: FIXED_NOW_MS,
      has_last_seen: true,
      health: "healthy" as const,
    }));

    await Promise.all(
      Array.from({ length: N }, () =>
        Promise.resolve(r.selectCandidate(candidates, { capability: "work", nowMs: FIXED_NOW_MS })),
      ),
    );

    const state = r.getRoundRobinState();
    const keys = [...state.keys()];
    expect(keys.length).toBeGreaterThanOrEqual(1);
    const cursor = state.get(keys[0]!) ?? 0;
    expect(cursor).toBe(N % 3);
  });

  it("routing_reroute_excludes_failed_agent_max_3", async () => {
    const fails = new Set(["org.polymesh.flaky", "org.polymesh.mid"]);
    const chosen: string[] = [];
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.flaky",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
        agent({
          agent_id: "org.polymesh.mid",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
        agent({
          agent_id: "org.polymesh.stable",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
      ),
      {
        nativeDispatch: async ({ agent_id }) => {
          chosen.push(agent_id);
          if (fails.has(agent_id)) {
            throw { code: "ETIMEDOUT", message: "transport timeout" };
          }
        },
      },
    );

    const routedEvents: number[] = [];
    r.onTaskRouted((e) => routedEvents.push(e.reroute_count));

    const result = await r.routeTask({ capability: "job", payload: {} });
    expect(result.chosen.agent_id).toBe("org.polymesh.stable");
    expect(chosen).toContain("org.polymesh.flaky");
    expect(chosen[chosen.length - 1]).toBe("org.polymesh.stable");
    // Initial + up to 2 re-routes; may succeed before the 3rd attempt.
    expect(routedEvents[0]).toBe(0);
    expect(routedEvents.length).toBeGreaterThanOrEqual(2);
    expect(routedEvents.length).toBeLessThanOrEqual(3);
    expect(routedEvents.every((n, i) => n === i)).toBe(true);
    expect(chosen.length).toBeLessThanOrEqual(3);

    // Exhaustion path: all agents fail → ALL_CANDIDATES_EXHAUSTED within 3.
    const exhaust = router(
      registry(
        agent({
          agent_id: "org.polymesh.a",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
        agent({
          agent_id: "org.polymesh.b",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
        agent({
          agent_id: "org.polymesh.c",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
      ),
      {
        nativeDispatch: async () => {
          throw { code: "ETIMEDOUT", message: "transport timeout" };
        },
      },
    );
    await expect(exhaust.routeTask({ capability: "job", payload: {} })).rejects.toMatchObject({
      code: "ALL_CANDIDATES_EXHAUSTED",
    });
  });

  it("routing_explicit_target_member_lookup", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.target",
          mesh_member: true,
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
      ),
    );
    const { winner, routed } = r.capabilityRoute({
      capability: "ping",
      target: "org.polymesh.target",
    });
    expect(winner.agent_id).toBe("org.polymesh.target");
    expect(routed.candidate_count).toBe(1);
  });

  it("routing_explicit_target_verify_capability_on_target", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.target",
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
      ),
    );
    expect(() =>
      r.capabilityRoute({
        capability: "calendar.check",
        target: "org.polymesh.target",
      }),
    ).toThrow(RoutingError);
    try {
      r.capabilityRoute({
        capability: "calendar.check",
        target: "org.polymesh.target",
      });
    } catch (e) {
      expect(e).toBeInstanceOf(RoutingError);
      expect((e as RoutingError).code).toBe("CAPABILITY_NOT_ADVERTISED");
    }
  });

  it("routing_explicit_target_ambiguous_target_code", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.personal.alice",
          capabilities: [{ name: "greet", dialect: "native" }],
        }),
        agent({
          agent_id: "org.work.alice",
          capabilities: [{ name: "greet", dialect: "native" }],
        }),
      ),
      { canonicalExpansion: { alice: ["org.personal.alice", "org.work.alice"] } },
    );
    try {
      r.capabilityRoute({ capability: "greet", target: "alice" });
      expect.fail("expected AMBIGUOUS_TARGET");
    } catch (e) {
      expect((e as RoutingError).code).toBe("AMBIGUOUS_TARGET");
    }
  });

  it("routing_explicit_target_target_unavailable_no_reroute", async () => {
    const targets: string[] = [];
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.only",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
        agent({
          agent_id: "org.polymesh.other",
          capabilities: [{ name: "job", dialect: "native" }],
        }),
      ),
      {
        nativeDispatch: async ({ agent_id }) => {
          targets.push(agent_id);
          throw { code: "ETIMEDOUT", message: "timeout" };
        },
      },
    );

    await expect(
      r.routeTask({
        capability: "job",
        payload: {},
        target: "org.polymesh.only",
      }),
    ).rejects.toMatchObject({ code: "TARGET_UNAVAILABLE" });

    expect(targets.every((t) => t === "org.polymesh.only")).toBe(true);
    expect(targets.length).toBe(3);
    expect(targets).not.toContain("org.polymesh.other");
  });

  it("routing_concurrent_submit_exclusion_independence", async () => {
    const view = registry(
      agent({
        agent_id: "org.polymesh.a",
        capabilities: [{ name: "job", dialect: "native" }],
      }),
      agent({
        agent_id: "org.polymesh.b",
        capabilities: [{ name: "job", dialect: "native" }],
      }),
    );

    let aFailsOnce = true;
    const r = router(view, {
      nativeDispatch: async ({ agent_id, task_id }) => {
        if (task_id.startsWith("task-fail") && aFailsOnce && agent_id === "org.polymesh.a") {
          aFailsOnce = false;
          throw { code: "ETIMEDOUT", message: "timeout" };
        }
      },
    });

    const [failing, ok] = await Promise.all([
      r.routeTask({ capability: "job", payload: {}, taskId: "task-fail-1" }),
      r.routeTask({ capability: "job", payload: {}, taskId: "task-ok-1" }),
    ]);

    // Failing task may have re-routed; succeeding task must still complete.
    expect(failing.task_id).toBe("task-fail-1");
    expect(ok.task_id).toBe("task-ok-1");
    expect(ok.chosen.agent_id).toMatch(/org\.polymesh\.(a|b)/);
  });

  it("routing_determinism_across_identical_snapshots", () => {
    const view = registry(
      agent({
        agent_id: "org.polymesh.worker-c",
        capabilities: [{ name: "work", dialect: "native" }],
      }),
      agent({
        agent_id: "org.polymesh.worker-a",
        capabilities: [{ name: "work", dialect: "native" }],
      }),
      agent({
        agent_id: "org.polymesh.worker-b",
        capabilities: [{ name: "work", dialect: "native" }],
      }),
    );
    const r1 = router(view);
    const r2 = router(freezeRegistryView(view));
    const a = r1.capabilityRoute({ capability: "work" });
    const b = r2.capabilityRoute({ capability: "work" });
    expect(a.winner.agent_id).toBe(b.winner.agent_id);
    expect(a.winner.dialect).toBe(b.winner.dialect);
    expect(a.winner.agent_id).toBe("org.polymesh.worker-a");
  });

  it("routing_health_changes_mid_decision_uses_frozen_view", () => {
    const live: RegistryView = {
      agents: [
        agent({
          agent_id: "org.polymesh.alive",
          health: "healthy",
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
      ],
      last_refreshed_at: FIXED_NOW,
    };
    const r = router(live);
    const snap = freezeRegistryView(live);
    // Mutate live registry after freeze.
    live.agents[0]!.health = "offline";
    r.setRegistry({
      agents: [
        agent({
          agent_id: "org.polymesh.alive",
          health: "offline",
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
      ],
    });
    // Routing against frozen snapshot still sees healthy.
    const { winner } = r.capabilityRoute(
      { capability: "ping" },
      [],
      0,
      snap,
      FIXED_NOW,
    );
    expect(winner.agent_id).toBe("org.polymesh.alive");
  });

  it("retryability_classifier_permission_denied_not_retryable", () => {
    expect(isRetryableFailure({ code: "PERMISSION_DENIED", message: "permission denied" })).toBe(
      false,
    );
  });

  it("retryability_classifier_schema_invalid_not_retryable", () => {
    expect(isRetryableFailure({ code: "INVALID_PARAMS", message: "schema invalid" })).toBe(false);
  });

  it("retryability_classifier_transport_timeout_retryable", () => {
    expect(isRetryableFailure({ code: "ETIMEDOUT", message: "transport timeout" })).toBe(true);
  });

  it("retryability_classifier_post_accept_disconnect_by_idempotency_class", () => {
    expect(
      isRetryableFailure(
        { code: "ECONNRESET", message: "disconnect" },
        { postAccept: true, idempotency: "pure", side_effects: "none" },
      ),
    ).toBe(true);
    expect(
      isRetryableFailure(
        { code: "ECONNRESET", message: "disconnect" },
        { postAccept: true, idempotency: "sensitive", side_effects: "write" },
      ),
    ).toBe(false);
    expect(
      isRetryableFailure(
        { code: "ECONNRESET", message: "disconnect" },
        { postAccept: true, idempotency: "idempotent", side_effects: "approval" },
      ),
    ).toBe(false);
  });

  it("routing_error_bare_codes_byte_identical", () => {
    expect([...ROUTING_ERROR_CODES]).toEqual([
      "NO_CANDIDATES",
      "ALL_CANDIDATES_EXHAUSTED",
      "TARGET_UNAVAILABLE",
      "AMBIGUOUS_TARGET",
      "CAPABILITY_NOT_ADVERTISED",
      "DIALECT_UNSUPPORTED",
    ]);
  });

  it("routing_cold_start_eager_discovery_no_reroute_increment", async () => {
    let discovered = false;
    const r = createCapabilityRouter({
      registry: registry(),
      observedAt: () => FIXED_NOW,
      coldStartPolicy: "lazy",
      onDiscover: async () => {
        discovered = true;
        r.setRegistry(
          registry(
            agent({
              agent_id: "org.polymesh.late",
              capabilities: [{ name: "ping", dialect: "native" }],
            }),
          ),
        );
      },
    });

    const routedCounts: number[] = [];
    r.onTaskRouted((e) => routedCounts.push(e.reroute_count));

    const result = await r.routeTask({ capability: "ping", payload: {} });
    expect(discovered).toBe(true);
    expect(result.chosen.agent_id).toBe("org.polymesh.late");
    expect(routedCounts).toEqual([0]);
    expect(result.routed.reroute_count).toBe(0);
  });

  it("routing_glob_discovery_filter", () => {
    expect(capabilityExactMatch("calendar.check", "calendar.check")).toBe(true);
    expect(capabilityExactMatch("calendar.check", "calendar.*")).toBe(false);
    expect(capabilityGlobMatch("calendar.check", "calendar.*")).toBe(true);
    expect(capabilityGlobMatch("calendar.check.extra", "calendar.*")).toBe(false);
    expect(capabilityGlobMatch("org.check", "*.check")).toBe(true);
    expect(capabilityGlobMatch("a.b.check", "*.check")).toBe(false);
    expect(capabilityGlobMatch("ping", "*")).toBe(true);
    expect(capabilityGlobMatch("a.b", "*")).toBe(false);
  });

  // ---- §E.4.2 expansions ----

  it("routing_rank_candidates_native_before_a2a", () => {
    const r = router();
    const ranked = r.rankCandidates(
      [
        {
          agent_id: "x",
          capability: "c",
          dialect: "a2a",
          a2a_url: "https://x",
          locality: "lan",
          last_seen_ms: FIXED_NOW_MS,
          health: "healthy",
        },
        {
          agent_id: "x",
          capability: "c",
          dialect: "native",
          locality: "lan",
          last_seen_ms: FIXED_NOW_MS,
          health: "healthy",
        },
      ],
      { capability: "c", nowMs: FIXED_NOW_MS },
    );
    expect(ranked[0]!.dialect).toBe("native");
  });

  it("routing_select_candidate_locality_then_freshness", () => {
    const r = router();
    const chosen = r.selectCandidate(
      [
        {
          agent_id: "lan",
          capability: "c",
          dialect: "native",
          locality: "lan",
          last_seen_ms: FIXED_NOW_MS,
          health: "healthy",
        },
        {
          agent_id: "host",
          capability: "c",
          dialect: "native",
          locality: "same_host",
          last_seen_ms: FIXED_NOW_MS - 10_000,
          health: "healthy",
        },
      ],
      { capability: "c", nowMs: FIXED_NOW_MS },
    );
    expect(chosen?.agent_id).toBe("host");
  });

  it("routing_task_routed_event_fields_complete", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.a",
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
      ),
    );
    const { routed } = r.capabilityRoute({ capability: "ping", task_id: "t1" });
    expect(routed.type).toBe("task.routed");
    expect(routed.task_id).toBe("t1");
    expect(typeof routed.candidate_count).toBe("number");
    expect(routed.chosen_agent).toBe("org.polymesh.a");
    expect(routed.dialect).toBe("native");
    expect(routed.reroute_count).toBe(0);
    expect(Array.isArray(routed.excluded_agents)).toBe(true);
    expect(routed.locality_tier).toBeDefined();
    expect(routed.observed_at).toBeTruthy();
  });

  it("routing_dialect_preference_hook_overrides_default", async () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.dual",
          capabilities: [
            { name: "calendar.check", dialect: "native" },
            { name: "calendar.check", dialect: "a2a", a2a_url: "https://a2a.example" },
          ],
        }),
      ),
      { adapterAvailable: true, a2aBridge: { send: async () => undefined } },
    );
    r.setDialectPreferenceHooks({
      preferDialects: () => ["a2a", "native"],
    });
    const result = await r.routeTask({ capability: "calendar.check", payload: {} });
    expect(result.chosen.dialect).toBe("a2a");
  });

  it("routing_explicit_target_deduped_candidate_count_1", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.t",
          capabilities: [
            { name: "ping", dialect: "native" },
            { name: "ping", dialect: "a2a", a2a_url: "https://x" },
          ],
        }),
      ),
      { adapterAvailable: true },
    );
    const { routed } = r.capabilityRoute({
      capability: "ping",
      target: "org.polymesh.t",
    });
    expect(routed.candidate_count).toBe(1);
    expect(routed.excluded_agents).toEqual([]);
    expect(routed.reroute_count).toBe(0);
  });

  it("routing_explicit_target_native_preferred_over_a2a_when_both_advertised", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.t",
          capabilities: [
            { name: "ping", dialect: "a2a", a2a_url: "https://x" },
            { name: "ping", dialect: "native" },
          ],
        }),
      ),
      { adapterAvailable: true },
    );
    const { winner } = r.capabilityRoute({
      capability: "ping",
      target: "org.polymesh.t",
    });
    expect(winner.dialect).toBe("native");
  });

  it("retryability_classifier_a2a_503_retryable", () => {
    expect(isRetryableFailure({ code: "A2A_ERROR", status: 503, message: "unavailable" })).toBe(
      true,
    );
  });

  it("retryability_classifier_target_unavailable_retryable", () => {
    expect(isRetryableFailure({ code: "TARGET_UNAVAILABLE" })).toBe(true);
  });

  it("core_without_adapter_package_builds_and_routes_native", () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.n",
          capabilities: [{ name: "ping", dialect: "native" }],
        }),
      ),
      { adapterAvailable: false, a2aBridge: null },
    );
    const { winner } = r.capabilityRoute({ capability: "ping" });
    expect(winner.dialect).toBe("native");
  });

  it("core_without_adapter_fails_closed_on_a2a_only_capability", async () => {
    const r = router(
      registry(
        agent({
          agent_id: "org.polymesh.a2a-only",
          mesh_member: false,
          capabilities: [
            { name: "remote.skill", dialect: "a2a", a2a_url: "https://a2a.example/skill" },
          ],
        }),
      ),
      { adapterAvailable: false, a2aBridge: null },
    );
    await expect(r.routeTask({ capability: "remote.skill", payload: {} })).rejects.toMatchObject({
      code: "DIALECT_UNSUPPORTED",
    });
  });

  it("appendix_h_conformance_vectors_all_pass", () => {
    const results = runAllAppendixHVectors();
    expect(results).toHaveLength(APPENDIX_H_VECTOR_IDS.length);
    for (const result of results) {
      expect(result.ok, `${JSON.stringify(result)}`).toBe(true);
    }
  });
});
