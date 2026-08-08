/**
 * PolyMesh v6 M2 — A2A outbound adapter tests (§E.4.2 outbound/poll/error/idempotency/auth).
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { uuidv7 } from "@latticeag/polymesh-broker";
import { CapabilityRouter, createCapabilityRouter } from "@latticeag/polymesh-client/router";

import {
  A2AAdapter,
  A2ADialectError,
  AdapterEventLog,
  IdempotencyStore,
  MapOutboundTaskId,
  MemoryTaskIdMap,
  computePollBase,
  computePollDelay,
  createMockA2AServer,
  forceMockTaskState,
  mapHttpTransportError,
  mapJsonRpcErrorToPolymesh,
  mayAdvanceState,
  skillNameFromCapabilityName,
} from "@latticeag/polymesh-a2a";

describe("v6 M2 A2A outbound", () => {
  it("outbound_skill_name_strip_org_prefix", () => {
    expect(skillNameFromCapabilityName("org.polymesh.calendar.check")).toBe("calendar.check");
    expect(skillNameFromCapabilityName("com.vendor.invoice.extract")).toBe(
      "com.vendor.invoice.extract",
    );
  });

  it("outbound_task_id_uuidv7_passthrough", () => {
    const id = uuidv7();
    const store = new MemoryTaskIdMap();
    expect(MapOutboundTaskId(id, store.asStore())).toBe(id);
  });

  it("outbound_task_id_bijection_map_durable", () => {
    const store = new MemoryTaskIdMap();
    const remote1 = MapOutboundTaskId(
      "local-task-1",
      store.asStore(),
      () => "01900000-0000-7000-8000-0000000000aa",
    );
    const remote2 = MapOutboundTaskId(
      "local-task-1",
      store.asStore(),
      () => "01900000-0000-7000-8000-0000000000bb",
    );
    expect(remote1).toBe("01900000-0000-7000-8000-0000000000aa");
    expect(remote2).toBe(remote1);
  });

  it("outbound_poll_backoff_schedule", () => {
    expect(computePollBase(0)).toBe(500);
    expect(computePollBase(1)).toBe(1000);
    expect(computePollBase(2)).toBe(2000);
    expect(computePollBase(3)).toBe(4000);
    expect(computePollBase(4)).toBe(8000);
    expect(computePollBase(5)).toBe(15_000);
    expect(computePollBase(8)).toBe(15_000);
  });

  it("outbound_poll_jitter_within_plus_minus_20_percent", () => {
    for (let n = 0; n < 6; n++) {
      const base = computePollBase(n);
      for (let i = 0; i < 50; i++) {
        const d = computePollDelay(n, () => i / 50);
        expect(d).toBeGreaterThanOrEqual(base * 0.8 - 1e-9);
        expect(d).toBeLessThanOrEqual(base * 1.2 + 1e-9);
      }
    }
  });

  it("outbound_monotonic_no_state_regression", () => {
    expect(mayAdvanceState("completed", "working")).toBe(false);
    expect(mayAdvanceState("working", "completed")).toBe(true);
    expect(mayAdvanceState("submitted", "working")).toBe(true);
    expect(mayAdvanceState("failed", "submitted")).toBe(false);
  });

  it("outbound_error_http_503_maps_target_unavailable_retryable", () => {
    const err = mapHttpTransportError(503);
    expect(err.code).toBe("TARGET_UNAVAILABLE");
    expect(err.retryable).toBe(true);
    expect(err.jsonRpcCode).toBe(-32008);
  });

  it("outbound_error_http_429_maps_rate_limited", () => {
    const err = mapHttpTransportError(429);
    expect(err.code).toBe("RATE_LIMITED");
    expect(err.retryable).toBe(true);
    expect(err.jsonRpcCode).toBe(-32002);
  });

  it("outbound_error_jsonrpc_auth_failed_maps_32001", () => {
    const err = mapJsonRpcErrorToPolymesh({
      code: -32001,
      message: "Authentication failed",
      data: { polymesh_code: "AUTHENTICATION_FAILED" },
    });
    expect(err.code).toBe("AUTHENTICATION_FAILED");
    expect(err.jsonRpcCode).toBe(-32001);
    expect(err.retryable).toBe(false);
  });

  it("outbound_idempotency_fingerprint_excludes_task_id", () => {
    const withKeyA = IdempotencyStore.fingerprint({
      capability_id: "org.polymesh.calendar.check",
      payload: { day: "2026-08-08" },
      task_id: "task-aaa",
      idempotency_key: "idem-1",
      principal_id: "caller",
    });
    const withKeyB = IdempotencyStore.fingerprint({
      capability_id: "org.polymesh.calendar.check",
      payload: { day: "2026-08-08" },
      task_id: "task-bbb",
      idempotency_key: "idem-1",
      principal_id: "caller",
    });
    expect(withKeyA.fingerprint).toBe(withKeyB.fingerprint);
    expect(withKeyA.dedup_key).toBe("idem-1");

    const noKeyA = IdempotencyStore.fingerprint({
      capability_id: "org.polymesh.calendar.check",
      payload: { day: "2026-08-08" },
      task_id: "task-aaa",
      principal_id: "caller",
    });
    const noKeyB = IdempotencyStore.fingerprint({
      capability_id: "org.polymesh.calendar.check",
      payload: { day: "2026-08-08" },
      task_id: "task-bbb",
      principal_id: "caller",
    });
    expect(noKeyA.fingerprint).not.toBe(noKeyB.fingerprint);
  });

  it("outbound_event_log_cap_1000_plus_terminal", () => {
    const log = new AdapterEventLog({ cap: 1000 });
    const taskId = "cap-task";
    for (let i = 0; i < 1005; i++) {
      log.append(taskId, "progress", { state: "RUNNING" });
    }
    log.append(taskId, "done", { state: "SUCCEEDED", terminal: true });
    const events = log.get(taskId);
    const nonTerminal = events.filter((e) => !e.terminal);
    const terminal = events.filter((e) => e.terminal);
    expect(nonTerminal.length).toBeLessThanOrEqual(1000);
    expect(terminal.length).toBe(1);
    expect(events.length).toBeLessThanOrEqual(1001);
  });

  it("outbound_send_mock_a2a_completion", async () => {
    const mock = await createMockA2AServer({ dropNPolls: 0, completeResult: { free: true } });
    try {
      const captures: string[] = [];
      const adapter = new A2AAdapter({
        config: {
          outbound_enabled: true,
          trusted_endpoints: [mock.url],
        },
        onRequest: (info) => captures.push(info.body),
        random: () => 0.5,
      });
      const result = await adapter.executeOutbound({
        a2a_url: mock.url,
        capability: "org.polymesh.calendar.check",
        payload: { day: "2026-08-08" },
        task_id: uuidv7(),
        deadline: Date.now() + 5_000,
      });
      expect(result.status).toBe("SUCCEEDED");
      expect(result.result).toEqual({ free: true });
      expect(captures.some((b) => b.includes("tasks/send") || b.includes('"method"'))).toBe(true);
      const sendBody = captures.find((b) => b.includes("tasks/send"));
      expect(sendBody).toContain("calendar.check");
      expect(sendBody).toContain("org.polymesh.calendar.check");
    } finally {
      await mock.close();
    }
  });

  it("outbound_poll_respects_mesh_task_deadline", async () => {
    const mock = await createMockA2AServer({ dropNPolls: 100, latencyGetMs: 5 });
    try {
      let now = Date.now();
      const adapter = new A2AAdapter({
        config: { outbound_enabled: true, trusted_endpoints: [mock.url] },
        now: () => now,
        sleep: async (ms) => {
          now += ms;
        },
        random: () => 0.5,
      });
      await expect(
        adapter.executeOutbound({
          a2a_url: mock.url,
          capability: "org.polymesh.agent.ping",
          payload: {},
          task_id: uuidv7(),
          deadline: now + 800,
        }),
      ).rejects.toMatchObject({ code: "DEADLINE" });
    } finally {
      await mock.close();
    }
  });

  it("outbound_poll_cancel_interrupted_during_wait_window", async () => {
    const mock = await createMockA2AServer({ dropNPolls: 100 });
    try {
      const ac = new AbortController();
      const adapter = new A2AAdapter({
        config: { outbound_enabled: true, trusted_endpoints: [mock.url] },
        sleep: async (ms, signal) => {
          await new Promise<void>((resolve, reject) => {
            const t = setTimeout(resolve, Math.min(ms, 50));
            signal?.addEventListener(
              "abort",
              () => {
                clearTimeout(t);
                reject(new A2ADialectError("CANCELLED", "aborted"));
              },
              { once: true },
            );
          });
        },
        random: () => 0.5,
      });
      const p = adapter.executeOutbound({
        a2a_url: mock.url,
        capability: "org.polymesh.agent.ping",
        payload: {},
        task_id: uuidv7(),
        deadline: Date.now() + 30_000,
        signal: ac.signal,
      });
      setTimeout(() => ac.abort(), 20);
      await expect(p).rejects.toMatchObject({ code: "CANCELLED" });
    } finally {
      await mock.close();
    }
  });

  it("outbound_idempotency_retry_returns_cached_state", async () => {
    const mock = await createMockA2AServer({ dropNPolls: 0, completeResult: { n: 1 } });
    try {
      const adapter = new A2AAdapter({
        config: { outbound_enabled: true, trusted_endpoints: [mock.url] },
        random: () => 0.5,
      });
      const input = {
        a2a_url: mock.url,
        capability: "org.polymesh.calendar.check",
        payload: { day: "x" },
        task_id: uuidv7(),
        idempotency_key: "idem-retry-1",
        deadline: Date.now() + 5_000,
      };
      const first = await adapter.executeOutbound(input);
      const sendsBefore = mock.requests.filter(
        (r) => (r.body as { method?: string })?.method === "tasks/send",
      ).length;
      const second = await adapter.executeOutbound({ ...input, task_id: uuidv7() });
      const sendsAfter = mock.requests.filter(
        (r) => (r.body as { method?: string })?.method === "tasks/send",
      ).length;
      expect(second.status).toBe(first.status);
      expect(second.result).toEqual(first.result);
      expect(second.from_cache).toBe(true);
      expect(sendsAfter).toBe(sendsBefore);
    } finally {
      await mock.close();
    }
  });

  it("outbound_credential_allowlist_mismatch_denied", async () => {
    const adapter = new A2AAdapter({
      config: {
        outbound_enabled: true,
        trusted_endpoints: ["http://trusted.example/a2a"],
      },
    });
    await expect(
      adapter.executeOutbound({
        a2a_url: "http://evil.example/a2a",
        capability: "org.polymesh.agent.ping",
        payload: {},
        task_id: uuidv7(),
      }),
    ).rejects.toMatchObject({ code: "AUTHORIZATION_DENIED" });
  });

  it("outbound_mesh_token_never_on_wire", async () => {
    const mock = await createMockA2AServer({ dropNPolls: 0 });
    try {
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtZXNoIn0.signaturepartgoesherexxxx";
      const capturedBodies: string[] = [];
      const adapter = new A2AAdapter({
        config: { outbound_enabled: true, trusted_endpoints: [mock.url] },
        onRequest: (info) => capturedBodies.push(info.body),
        random: () => 0.5,
      });
      await adapter.executeOutbound({
        a2a_url: mock.url,
        capability: "org.polymesh.agent.ping",
        payload: { token: jwt, note: `Bearer ${jwt}` },
        task_id: uuidv7(),
        deadline: Date.now() + 5_000,
      });
      const joined = capturedBodies.join("\n");
      expect(joined).not.toContain(jwt);
      expect(joined).toContain("[REDACTED]");
      expect(adapter.getRedactionLog().length).toBeGreaterThan(0);
    } finally {
      await mock.close();
    }
  });

  it("outbound_bridge_wires_capability_router", async () => {
    const mock = await createMockA2AServer({ dropNPolls: 0, completeResult: { routed: true } });
    try {
      const adapter = new A2AAdapter({
        config: { outbound_enabled: true, trusted_endpoints: [mock.url] },
        random: () => 0.5,
      });
      const router = createCapabilityRouter({
        registry: {
          agents: [
            {
              agent_id: "org.remote.a2a",
              health: "healthy",
              locality: "lan",
              last_seen: new Date().toISOString(),
              capabilities: [
                {
                  name: "org.polymesh.agent.ping",
                  dialect: "a2a",
                  a2a_url: mock.url,
                },
              ],
            },
          ],
        },
        a2aBridge: adapter.createOutboundBridge(),
        adapterAvailable: true,
      });
      const { chosen } = await router.routeTask({
        capability: "org.polymesh.agent.ping",
        payload: { ping: true },
        preferDialects: ["a2a"],
      });
      expect(chosen.dialect).toBe("a2a");
    } finally {
      await mock.close();
    }
  });
});

// silence unused import if tree-shaken oddly
void createHash;
void CapabilityRouter;
void forceMockTaskState;
