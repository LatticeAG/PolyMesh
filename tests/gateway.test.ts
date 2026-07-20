import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  InMemoryGatewayBroker,
  PolyMeshGateway,
  type GatewayEvent,
} from "../packages/gateway/src/index.js";

const gateways: PolyMeshGateway[] = [];
const meshId = "msh_gateway123456";
const principalId = "prn_gateway_test";

afterEach(async () => {
  await Promise.all(gateways.splice(0).map((gateway) => gateway.close()));
});

function taskBody(input: unknown = { prompt: "hello" }) {
  return {
    target: { mesh_id: meshId, agent_id: "com.example.executor" },
    capability: "com.example.echo",
    input,
    deadline: "2030-01-01T00:00:00.000Z",
  };
}

async function gatewayWithBroker(): Promise<{ gateway: PolyMeshGateway; broker: InMemoryGatewayBroker }> {
  const broker = new InMemoryGatewayBroker();
  broker.setContract("com.example.executor", "com.example.echo", {
    capability_version: "1.0.0",
    capability_contract_digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });
  const gateway = new PolyMeshGateway({
    broker,
    authenticate: (token) => token === "valid-bearer" ? {
      principal_id: principalId,
      mesh_id: meshId,
      delegation_id: "dlg_gateway_test",
    } : undefined,
  });
  gateways.push(gateway);
  await gateway.listen();
  return { gateway, broker };
}

function endpoint(gateway: PolyMeshGateway): { host: string; port: number } {
  const address = gateway.address() as AddressInfo;
  return { host: "127.0.0.1", port: address.port };
}

function request(
  gateway: PolyMeshGateway,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  const encoded = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      ...endpoint(gateway),
      method,
      path,
      headers: {
        authorization: "Bearer valid-bearer",
        ...(encoded === undefined ? {} : { "content-type": "application/json", "content-length": String(Buffer.byteLength(encoded)) }),
        ...headers,
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.once("error", reject);
    if (encoded !== undefined) req.write(encoded);
    req.end();
  });
}

function firstSseEvent(gateway: PolyMeshGateway, path: string): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      ...endpoint(gateway),
      method: "GET",
      path,
      headers: { authorization: "Bearer valid-bearer" },
    }, (response) => {
      let body = "";
      response.on("data", (chunk) => {
        body += Buffer.from(chunk).toString("utf8");
        if (!body.includes("\n\n")) return;
        resolve({ status: response.statusCode ?? 0, headers: response.headers, body });
        req.destroy();
      });
    });
    req.once("error", (error) => {
      // Destroying after the first SSE record is expected.
      if ((error as NodeJS.ErrnoException).code !== "ECONNRESET") reject(error);
    });
    req.end();
  });
}

describe("PolyMesh v2 REST/SSE gateway", () => {
  it("authenticates a caller, creates a sanitized v2 envelope, and replays idempotency", async () => {
    const { gateway, broker } = await gatewayWithBroker();
    const headers = { "idempotency-key": "gateway-submit-1" };
    const first = await request(gateway, "POST", "/v2/gateway/tasks", taskBody(), headers);
    expect(first.status).toBe(202);
    expect(first.headers["cache-control"]).toBe("no-store");
    const accepted = JSON.parse(first.body) as { task_id: string; events_url: string; receipt: string };
    expect(accepted.receipt).toBe("stored");
    expect(accepted.events_url).toContain(accepted.task_id);
    expect(broker.submissions).toHaveLength(1);
    expect(broker.submissions[0]!.envelope).toMatchObject({
      protocol: "polymesh.0.2",
      type: "task.submit",
      source: { mesh_id: meshId, agent_id: "org.polymesh.gateway" },
      target: taskBody().target,
      params: { task_id: accepted.task_id, capability: "com.example.echo" },
    });
    expect(JSON.stringify(broker.submissions[0]!.envelope)).not.toContain("valid-bearer");

    const retry = await request(gateway, "POST", "/v2/gateway/tasks", taskBody(), headers);
    expect(retry.status).toBe(202);
    expect(JSON.parse(retry.body).task_id).toBe(accepted.task_id);
    expect(broker.submissions).toHaveLength(1);

    const conflict = await request(gateway, "POST", "/v2/gateway/tasks", taskBody({ prompt: "changed" }), headers);
    expect(conflict.status).toBe(409);
    expect(JSON.parse(conflict.body).code).toBe("PMX.GATEWAY.IDEMPOTENCY_CONFLICT");
  });

  it("returns generic authentication failures and rejects a caller-selected mesh", async () => {
    const { gateway } = await gatewayWithBroker();
    const unauthenticated = await request(gateway, "POST", "/v2/gateway/tasks", taskBody(), {
      authorization: "Bearer invalid",
      "idempotency-key": "gateway-auth-1",
    });
    expect(unauthenticated.status).toBe(401);
    expect(JSON.parse(unauthenticated.body).code).toBe("AUTHENTICATION_FAILED");

    const denied = await request(gateway, "POST", "/v2/gateway/tasks", {
      ...taskBody(),
      target: { mesh_id: "msh_othermesh123", agent_id: "com.example.executor" },
    }, { "idempotency-key": "gateway-mesh-1" });
    expect(denied.status).toBe(403);
    expect(JSON.parse(denied.body).code).toBe("PMX.AUTHORIZATION_DENIED");
  });

  it("streams closed durable events as SSE and returns 410 for an expired cursor", async () => {
    const { gateway, broker } = await gatewayWithBroker();
    const submission = await request(gateway, "POST", "/v2/gateway/tasks", taskBody(), { "idempotency-key": "gateway-events-1" });
    const { task_id: taskId } = JSON.parse(submission.body) as { task_id: string };
    const event: GatewayEvent = {
      event_id: "evt_01234567890123456789",
      task_id: taskId,
      event_seq: 1,
      type: "task.accepted",
      occurred_at: "2026-07-20T12:00:04.000Z",
      data: { state: "accepted" },
    };
    broker.appendEvent(principalId, event);

    const stream = await firstSseEvent(gateway, `/v2/gateway/events?task_id=${taskId}`);
    expect(stream.status).toBe(200);
    expect(stream.headers["content-type"]).toContain("text/event-stream");
    expect(stream.headers["x-accel-buffering"]).toBe("no");
    expect(stream.body).toContain(`id: ${event.event_id}`);
    expect(stream.body).toContain("event: task.accepted");
    expect(stream.body).toContain(`"task_id":"${taskId}"`);

    const expired = await request(gateway, "GET", "/v2/gateway/events?after=evt_abcdefghijabcdefghij");
    expect(expired.status).toBe(410);
    expect(JSON.parse(expired.body).code).toBe("PMX.GATEWAY.CURSOR_EXPIRED");
  });
});
