import { describe, expect, it } from "vitest";

import {
  capabilityContractTuple,
  createAgentCard,
  createWirePair,
  randomInstanceId,
  V2ZstdStateMachine,
  uuidv7,
} from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

describe("native v2 TypeScript client", () => {
  it("selects the profile and maps a native task lifecycle to call()", async () => {
    const meshId = uuidv7();
    const sessionId = uuidv7();
    const brokerInstance = randomInstanceId();
    const executorInstance = randomInstanceId();
    const client = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.caller" }),
      profile: "polymesh.0.2",
      compression: ["none"],
    });
    const [clientWire, brokerWire] = createWirePair();
    const capability = { id: "org.example.echo", version: "1.0.0" };
    const contract = capabilityContractTuple(capability);
    const seen: unknown[] = [];

    brokerWire.on("message", (raw) => {
      const frame = JSON.parse(raw) as Record<string, any>;
      seen.push(frame);
      if (frame.type === "v2.init") {
        brokerWire.send(JSON.stringify({
          type: "v2.ack",
          profile: "polymesh.0.2",
          protocol: "polymesh.0.2",
          mesh_id: meshId,
          session_id: sessionId,
          agent_id: "org.polymesh.broker",
          instance_id: brokerInstance,
          compression: "none",
        }));
        return;
      }
      if (frame.type !== "task.submit") return;
      const now = new Date().toISOString();
      const native = (type: string, params: Record<string, unknown>, inReplyTo?: string) => ({
        protocol: "polymesh.0.2",
        profile: "polymesh.0.2",
        mesh_id: meshId,
        type,
        message_id: uuidv7(),
        timestamp: now,
        source: { agent_id: "com.example.executor", instance_id: executorInstance },
        target: { agent_id: client.card.agent_id, instance_id: client.card.instance_id },
        delivery: {
          delivery_id: uuidv7(),
          mode: "at_least_once",
          idempotency_key: `${type}:${frame.params.task_id}`,
          deadline: frame.delivery.deadline,
        },
        ...(inReplyTo === undefined ? {} : { in_reply_to: inReplyTo }),
        params,
      });
      brokerWire.send(JSON.stringify(native("task.accepted", {
        task_id: frame.params.task_id,
        event_seq: 1,
        accepted_at: now,
        capability: contract.capability_id,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
      }, frame.message_id)));
      brokerWire.send(JSON.stringify(native("task.completed", {
        task_id: frame.params.task_id,
        event_seq: 2,
        capability: contract.capability_id,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        terminal: { outcome: "succeeded", result: { echoed: frame.params.input }, completed_at: now },
      })));
    });

    await client.connectTransport(clientWire);
    await expect(client.call("com.example.executor", capability.id, { message: "hello" })).resolves.toEqual({
      echoed: { message: "hello" },
    });

    const init = seen.find((frame) => (frame as { type?: string }).type === "v2.init") as Record<string, unknown>;
    const submit = seen.find((frame) => (frame as { type?: string }).type === "task.submit") as Record<string, any>;
    expect(init).toMatchObject({ profile: "polymesh.0.2", protocol: "polymesh.0.2" });
    expect(submit).toMatchObject({
      profile: "polymesh.0.2",
      mesh_id: meshId,
      delivery: expect.objectContaining({ mode: "at_least_once" }),
      params: expect.objectContaining({ capability: capability.id, input: { message: "hello" } }),
    });
    expect(typeof submit.delivery.delivery_id).toBe("string");
    expect(submit.params.method).toBeUndefined();
    client.close();
  });

  it("waits for mutual zstd readiness and wraps native application frames", async () => {
    const meshId = uuidv7();
    const sessionId = uuidv7();
    const brokerInstance = randomInstanceId();
    const executorInstance = randomInstanceId();
    const client = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.compressed-caller" }),
      profile: "polymesh.0.2",
      compression: ["zstd", "none"],
    });
    const [clientWire, brokerWire] = createWirePair();
    const responder = new V2ZstdStateMachine({ meshId, sessionId }, "responder");
    const capability = { id: "org.example.echo", version: "1.0.0" };
    const contract = capabilityContractTuple(capability);
    let sawWrapper = false;
    let serverFailure: unknown;

    const native = (type: string, params: Record<string, unknown>, deadline: string, inReplyTo?: string) => ({
      protocol: "polymesh.0.2",
      profile: "polymesh.0.2",
      mesh_id: meshId,
      type,
      message_id: uuidv7(),
      timestamp: new Date().toISOString(),
      source: { agent_id: "com.example.executor", instance_id: executorInstance },
      target: { agent_id: client.card.agent_id, instance_id: client.card.instance_id },
      delivery: {
        delivery_id: uuidv7(),
        mode: "at_least_once",
        idempotency_key: `${type}:${params.task_id ?? "control"}`,
        deadline,
      },
      ...(inReplyTo === undefined ? {} : { in_reply_to: inReplyTo }),
      params,
    });

    brokerWire.on("message", (raw) => {
      void (async () => {
        try {
          const frame = JSON.parse(raw) as Record<string, any>;
          if (frame.type === "v2.init") {
            brokerWire.send(JSON.stringify({
              type: "v2.ack",
              profile: "polymesh.0.2",
              mesh_id: meshId,
              session_id: sessionId,
              agent_id: "org.polymesh.broker",
              instance_id: brokerInstance,
              compression: "zstd",
            }));
            return;
          }
          if (frame.type === "zstd.propose") {
            responder.receivePropose(frame);
            brokerWire.send(JSON.stringify(responder.createReady()));
            return;
          }
          if (frame.type === "zstd.ready") {
            responder.receiveReady(frame);
            return;
          }
          if (frame.type !== "zstd.wrapper") return;
          sawWrapper = true;
          const submit = JSON.parse(Buffer.from(await responder.unwrap(frame)).toString("utf8")) as Record<string, any>;
          const accepted = native("task.accepted", {
            task_id: submit.params.task_id,
            event_seq: 1,
            accepted_at: new Date().toISOString(),
            capability: contract.capability_id,
            capability_version: contract.capability_version,
            capability_contract_digest: contract.capability_contract_digest,
          }, submit.delivery.deadline, submit.message_id);
          const completed = native("task.completed", {
            task_id: submit.params.task_id,
            event_seq: 2,
            capability: contract.capability_id,
            capability_version: contract.capability_version,
            capability_contract_digest: contract.capability_contract_digest,
            terminal: { outcome: "succeeded", result: { compressed: true }, completed_at: new Date().toISOString() },
          }, submit.delivery.deadline);
          brokerWire.send(JSON.stringify(await responder.wrap(Buffer.from(JSON.stringify(accepted), "utf8"))));
          brokerWire.send(JSON.stringify(await responder.wrap(Buffer.from(JSON.stringify(completed), "utf8"))));
        } catch (error) {
          serverFailure = error;
        }
      })();
    });

    await client.connectTransport(clientWire);
    expect(responder.active).toBe(true);
    await expect(client.call("com.example.executor", capability.id, { message: "compressed" })).resolves.toEqual({ compressed: true });
    expect(serverFailure).toBeUndefined();
    expect(sawWrapper).toBe(true);
    client.close();
  });
});
