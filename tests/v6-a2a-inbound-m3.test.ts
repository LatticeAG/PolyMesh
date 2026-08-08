/**
 * PolyMesh v6 M3 — A2A inbound adapter tests (§E.4.2 / §E.5.3).
 */
import { describe, expect, it } from "vitest";
import { uuidv7 } from "@latticeag/polymesh-broker";

import {
  A2ADialectError,
  CAPABILITY_CAPACITY,
  CAPABILITIES_LIST,
  HierarchicalRateLimiter,
  IP_CAPACITY,
  InboundHandler,
  MESH_CREDENTIAL_HEADERS,
  PRINCIPAL_CAPACITY,
  createInboundHandler,
} from "@latticeag/polymesh-a2a";

const PING = {
  name: "org.polymesh.agent.ping",
  description: "ping",
  version: "1.0.0",
  input_schema: { type: "object" },
  result_schema: { type: "object" },
} as const;

const CALENDAR = {
  name: "org.polymesh.calendar.check",
  description: "check calendar",
  version: "1.0.0",
  input_schema: { type: "object" },
  result_schema: { type: "object" },
} as const;

const SHELL = {
  name: "org.polymesh.shell.exec",
  description: "shell",
  version: "1.0.0",
  approval: "always",
} as const;

const CAPS_LIST = {
  name: CAPABILITIES_LIST,
  description: "list published skills",
  version: "1.0.0",
  input_schema: { type: "object" },
  result_schema: { type: "object" },
} as const;

function sendParams(skill: string, payload: Record<string, unknown> = {}, id?: string) {
  return {
    ...(id ? { id } : {}),
    message: {
      role: "user",
      parts: [{ type: "data", data: { ...payload } }],
    },
    metadata: { skill },
  };
}

function handler(opts: ConstructorParameters<typeof InboundHandler>[0] = {}) {
  return createInboundHandler({
    inbound_enabled: true,
    capabilities: [PING, CALENDAR, SHELL, CAPS_LIST],
    auth: { mode: "none" },
    onSubmit: () => ({ state: "SUCCEEDED", result: { ok: true } }),
    ...opts,
  });
}

describe("v6 M3 A2A inbound", () => {
  it("inbound_tasks_send_accepts_valid_task", async () => {
    const h = handler();
    const task = await h.handleTasksSend(sendParams("agent.ping", { hello: 1 }));
    expect(task.id).toBeTruthy();
    expect(["submitted", "working", "completed"]).toContain(task.status.state);
    expect(task.metadata?.polymesh_capability_id).toBe("org.polymesh.agent.ping");
  });

  it("inbound_unknown_skill_returns_minus_32601", async () => {
    const h = handler();
    const res = await h.handle({
      jsonrpc: "2.0",
      id: 1,
      method: "tasks/send",
      params: sendParams("totally.unknown.skill"),
    });
    expect(res.error).toMatchObject({
      code: -32601,
      data: expect.objectContaining({ polymesh_code: "UNSUPPORTED_CAPABILITY" }),
    });
  });

  it("inbound_schema_invalid_rejected_fail_closed", async () => {
    const h = handler();
    const res = await h.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tasks/send",
      params: {
        message: { role: "user", parts: [{ type: "data", data: {} }], extraField: true },
        metadata: { skill: "agent.ping" },
      },
    });
    expect(res.error).toMatchObject({
      code: -32600,
      data: expect.objectContaining({ polymesh_code: "MALFORMED" }),
    });
  });

  it("inbound_auth_reject_invalid_credentials", async () => {
    const h = handler({
      auth: { mode: "bearer", token: "correct-secret" },
      allow_public_unauthenticated: false,
    });
    const res = await h.handle(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tasks/send",
        params: sendParams("agent.ping"),
      },
      { headers: { authorization: "Bearer wrong" } },
    );
    expect(res.error).toMatchObject({
      code: -32001,
      data: expect.objectContaining({ polymesh_code: "AUTHENTICATION_FAILED" }),
    });
  });

  it("inbound_mesh_credential_never_forwarded_inbound", async () => {
    const h = handler({
      auth: { mode: "bearer", token: "a2a-token" },
    });
    await h.handle(
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tasks/send",
        params: sendParams("agent.ping"),
      },
      {
        headers: {
          authorization: "Bearer a2a-token",
          "x-polymesh-token": "mesh-jwt-must-not-cross",
          "x-gateway-jwt": "gateway-secret",
        },
      },
    );
    const submit = h.getLastMeshSubmit();
    expect(submit).toBeTruthy();
    for (const name of MESH_CREDENTIAL_HEADERS) {
      expect(Object.keys(submit!.headers).map((k) => k.toLowerCase())).not.toContain(name);
    }
    expect(submit!.principal_id.startsWith("a2a:")).toBe(true);
    expect(submit!.rooms).toEqual([]);
  });

  it("inbound_cross_principal_task_get_uniform_not_found", async () => {
    const caps = [PING];
    const owner = handler({
      capabilities: caps,
      auth: { mode: "bearer", token: "owner-token" },
    });
    const other = handler({
      // Share task store via applying same handler instance for get as owner,
      // but authenticate as a different principal on the same handler.
      capabilities: caps,
      auth: { mode: "bearer", token: "owner-token" },
    });
    void other;

    const created = await owner.handleTasksSend(sendParams("agent.ping"), {
      headers: { authorization: "Bearer owner-token" },
    });

    // Same process, second credential maps to a different principal on a fresh handler
    // that does not own the task — uniform TASK_NOT_FOUND.
    const stranger = handler({
      capabilities: caps,
      auth: { mode: "bearer", token: "stranger-token" },
    });
    // Inject the owner's task id into stranger's empty store via direct get RPC:
    // stranger never saw the task, so not found.
    const missing = await stranger.handle(
      { jsonrpc: "2.0", id: 5, method: "tasks/get", params: { id: created.id } },
      { headers: { authorization: "Bearer stranger-token" } },
    );
    expect(missing.error).toMatchObject({
      code: -32004,
      data: expect.objectContaining({ polymesh_code: "TASK_NOT_FOUND" }),
    });

    // Same handler, different principal: create with token A, get with token B.
    const shared = createInboundHandler({
      inbound_enabled: true,
      capabilities: caps,
      auth: { mode: "api_key_header", token: "ignored", header_name: "X-API-Key" },
      onSubmit: () => ({ state: "RUNNING" }),
    });
    // Use bearer-like distinct subjects by swapping auth configs via terminate:
    // Simulate by creating with principal P1 then looking up as P2 on same store.
    const sendRes = await shared.handle(
      {
        jsonrpc: "2.0",
        id: 6,
        method: "tasks/send",
        params: sendParams("agent.ping", {}, uuidv7()),
      },
      { headers: { "x-api-key": "ignored" } },
    );
    const taskId = (sendRes.result as { id: string }).id;
    // Force principal mismatch by rewriting stored owner.
    const record = (shared as unknown as { tasks: Map<string, { principal_id: string }> }).tasks.get(
      taskId,
    );
    expect(record).toBeTruthy();
    record!.principal_id = "a2a:other-principal";
    const cross = await shared.handle(
      { jsonrpc: "2.0", id: 7, method: "tasks/get", params: { id: taskId } },
      { headers: { "x-api-key": "ignored" } },
    );
    expect(cross.error).toMatchObject({
      code: -32004,
      data: expect.objectContaining({ polymesh_code: "TASK_NOT_FOUND" }),
    });
  });

  it("inbound_rate_limit_bucket_capacity_and_refill", () => {
    let now = 1_000_000;
    const limiter = new HierarchicalRateLimiter({
      enabled: true,
      now: () => now,
      ipCapacity: IP_CAPACITY,
      ipRefillPerSec: 1,
      principalCapacity: PRINCIPAL_CAPACITY,
      principalRefillPerSec: 0.5,
      capabilityCapacity: CAPABILITY_CAPACITY,
      capabilityRefillPerSec: 0.167,
    });

    for (let i = 0; i < CAPABILITY_CAPACITY; i++) {
      expect(
        limiter.allow({
          ip: "10.0.0.1",
          principal: "a2a:p1",
          capability: "org.polymesh.agent.ping",
        }),
      ).toBe(true);
    }
    expect(
      limiter.allow({
        ip: "10.0.0.1",
        principal: "a2a:p1",
        capability: "org.polymesh.agent.ping",
      }),
    ).toBe(false);

    // Refill ~1 token after ~6s at 0.167/sec.
    now += 6_000;
    expect(
      limiter.allow({
        ip: "10.0.0.1",
        principal: "a2a:p1",
        capability: "org.polymesh.agent.ping",
      }),
    ).toBe(true);
  });

  it("inbound_capabilities_list_only_published_skills", async () => {
    const h = handler();
    const task = await h.handleTasksSend(sendParams("capabilities.list"));
    expect(task.status.state).toBe("completed");
    const skills = (task.artifacts?.[0]?.parts?.[0] as { data?: { skills?: Array<{ name: string }> } })
      ?.data?.skills;
    expect(skills).toBeTruthy();
    const names = skills!.map((s) => s.name);
    expect(names).toContain("agent.ping");
    expect(names).toContain("calendar.check");
    expect(names).not.toContain("shell.exec");
    expect(names.every((n) => n !== "org.polymesh.shell.exec")).toBe(true);

    const card = h.handleCardRequest();
    const cardSkills = card.skills as Array<{ name: string }>;
    expect(cardSkills.map((s) => s.name)).not.toContain("shell.exec");
  });

  it("inbound_second_class_no_room_access", async () => {
    const h = handler({
      capabilities: [
        PING,
        {
          name: "org.polymesh.room.join",
          description: "join room",
          version: "1.0.0",
        },
      ],
    });
    expect(() => h.joinRoom("room-1")).toThrow(A2ADialectError);
    expect(() => h.listMeshMembers()).toThrow(A2ADialectError);

    const res = await h.handle({
      jsonrpc: "2.0",
      id: 8,
      method: "tasks/send",
      params: sendParams("room.join"),
    });
    // Unpublished / room capability: either unsupported or authz denied.
    expect(res.error).toBeTruthy();
    const code = (res.error as { data?: { polymesh_code?: string } }).data?.polymesh_code;
    expect(["AUTHORIZATION_DENIED", "UNSUPPORTED_CAPABILITY"]).toContain(code);
    expect(h.trustScopeFor({}).rooms).toEqual([]);
    expect(h.trustScopeFor({}).topology_read).toBe(false);
  });

  it("inbound_sse_stream_replays_from_event_seq", async () => {
    const h = handler({
      onSubmit: () => ({ state: "RUNNING" }),
    });
    const task = await h.handleTasksSend(sendParams("agent.ping"));
    h.applyMeshEvent(task.id, { state: "RUNNING", progress: 0.5 });
    h.applyMeshEvent(task.id, { state: "SUCCEEDED", result: { done: true } });

    const events = h.streamEvents(task.id, { from_event_seq: 2 });
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0]!.adapter_seq).toBeGreaterThanOrEqual(2);
    expect(events.some((e) => e.task.status.state === "completed")).toBe(true);
  });

  it("inbound_sse_client_timeout_closes_stream", async () => {
    const h = handler({
      sse_client_timeout_ms: 45_000,
      onSubmit: () => ({ state: "RUNNING" }),
    });
    const task = await h.handleTasksSend(sendParams("agent.ping"));
    const closed = h.streamEvents(task.id, { client_timeout_ms: 0 });
    expect(closed).toEqual([]);
  });

  it("inbound_bidirectional_interop_mock_a2a_client_tasks_mesh_agent", async () => {
    const meshAgentWork: Array<{ capability: string; payload: unknown }> = [];
    const h = createInboundHandler({
      inbound_enabled: true,
      capabilities: [CALENDAR],
      auth: { mode: "none" },
      onSubmit: (env) => {
        meshAgentWork.push({ capability: env.capability, payload: env.payload });
        return { state: "SUCCEEDED", result: { free: true, day: (env.payload as { day?: string }).day } };
      },
    });
    await h.start();
    try {
      const response = await fetch(h.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "interop-1",
          method: "tasks/send",
          params: sendParams("calendar.check", { day: "2026-08-08" }),
        }),
      });
      const body = (await response.json()) as {
        result?: { id: string; status: { state: string }; artifacts?: unknown[] };
        error?: unknown;
      };
      expect(body.error).toBeUndefined();
      expect(body.result?.status.state).toBe("completed");
      expect(meshAgentWork).toHaveLength(1);
      expect(meshAgentWork[0]!.capability).toBe("org.polymesh.calendar.check");

      const getRes = await fetch(h.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "interop-2",
          method: "tasks/get",
          params: { id: body.result!.id },
        }),
      });
      const getBody = (await getRes.json()) as { result: { status: { state: string } } };
      expect(getBody.result.status.state).toBe("completed");
    } finally {
      await h.stop();
    }
  });

  it("inbound_cancel_returns_canceled_state", async () => {
    const h = handler({
      onSubmit: () => ({ state: "RUNNING" }),
    });
    const task = await h.handleTasksSend(sendParams("agent.ping"));
    const canceled = await h.handleTasksCancel({ id: task.id, reason: "user" });
    expect(canceled.status.state).toBe("canceled");
    expect(canceled.metadata?.polymesh_state).toBe("CANCELLED");
  });

  it("inbound_denied_skill_shell_exec_not_published", async () => {
    const h = handler();
    const res = await h.handle({
      jsonrpc: "2.0",
      id: 9,
      method: "tasks/send",
      params: sendParams("shell.exec", { cmd: "rm -rf /" }),
    });
    expect(res.error).toMatchObject({
      code: -32601,
      data: expect.objectContaining({ polymesh_code: "UNSUPPORTED_CAPABILITY" }),
    });
  });

  it("inbound_tasks_get_returns_translated_state", async () => {
    const h = handler({ onSubmit: () => ({ state: "RUNNING" }) });
    const created = await h.handleTasksSend(sendParams("agent.ping"));
    const got = await h.handleTasksGet({ id: created.id });
    expect(got.status.state).toBe("working");
    expect(got.metadata?.polymesh_state).toBe("RUNNING");
  });
});
