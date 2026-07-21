import { describe, expect, it } from "vitest";

import {
  capabilityContractTuple,
  createAgentCard,
  createEnvelope,
  parseStrictJson,
  randomInstanceId,
  validateCapability,
  uuidv7,
  validateEnvelope,
} from "@latticeag/polymesh-broker";

const source = { agent_id: "alice", instance_id: randomInstanceId() };
const target = { agent_id: "bob", instance_id: randomInstanceId() };
const echoContract = capabilityContractTuple({ id: "org.example.echo", version: "1.0.0" });

describe("strict protocol input handling", () => {
  it("rejects duplicate JSON members before they become application objects", () => {
    expect(parseStrictJson('{"type":"ping","type":"pong"}')).toMatchObject({
      ok: false,
      code: "DUPLICATE_MEMBER",
    });
  });

  it("enforces structural budgets before accepting JSON", () => {
    expect(parseStrictJson("[[[[]]]]", { maxDepth: 3 })).toMatchObject({
      ok: false,
      code: "RESOURCE_EXHAUSTED",
    });
    expect(parseStrictJson("[0,1,2]", { maxArrayItems: 2 })).toMatchObject({
      ok: false,
      code: "RESOURCE_EXHAUSTED",
    });
  });

  it("uses a closed envelope grammar and forbids broadcast targets", () => {
    const ping = createEnvelope({
      type: "ping",
      source,
      target,
      params: { n: 1 },
    });
    expect(validateEnvelope(ping).ok).toBe(true);

    const withUnknown = { ...ping, injected: true };
    expect(validateEnvelope(withUnknown).ok).toBe(false);

    const broadcast = {
      ...ping,
      target: { agent_id: "*" },
    };
    expect(validateEnvelope(broadcast).ok).toBe(false);
  });

  it("requires task submit deadlines to be bound to delivery deadlines", () => {
    const deadline = new Date(Date.now() + 60_000).toISOString();
    const submit = createEnvelope({
      type: "task.submit",
      source,
      target,
      delivery: { mode: "at_least_once", idempotency_key: "submit:deadline", deadline },
      params: {
        task_id: uuidv7(),
        method: "org.example.echo",
        capability_version: echoContract.capability_version,
        capability_contract_digest: echoContract.capability_contract_digest,
        params: {},
        deadline,
      },
    });
    expect(validateEnvelope(submit).ok).toBe(true);
    expect(validateEnvelope({
      ...submit,
      params: { ...submit.params, deadline: new Date(Date.now() + 120_000).toISOString() },
    }).ok).toBe(false);
  });

  it("accepts only a closed terminal shape for task.completed", () => {
    const deadline = new Date(Date.now() + 60_000).toISOString();
    const completed = createEnvelope({
      type: "task.completed",
      source,
      target,
      delivery: { mode: "at_least_once", idempotency_key: "completed:shape", deadline },
      params: {
        task_id: uuidv7(),
        event_seq: 2,
        ...echoContract,
        terminal: { outcome: "succeeded", result: { ok: true }, completed_at: new Date().toISOString() },
      },
    });
    expect(validateEnvelope(completed).ok).toBe(true);
    expect(validateEnvelope({
      ...completed,
      params: {
        ...completed.params,
        terminal: {
          ...completed.params.terminal,
          error: { code: "INJECTED", message: "must not accompany result" },
        },
      },
    }).ok).toBe(false);
  });

  it("rejects schema assertions that the restricted runtime cannot enforce", () => {
    expect(() => createAgentCard({
      agent_id: "schema-agent",
      capabilities: [{
        id: "org.example.unenforceable",
        version: "1.0.0",
        input_schema: { $ref: "https://attacker.example/schema.json" },
      }],
    })).toThrow(/restricted secure schema profile/);

    expect(() => createAgentCard({
      agent_id: "schema-agent-valid",
      capabilities: [{
        id: "org.example.restricted",
        version: "1.0.0",
        input_schema: {
          type: "object",
          required: ["value"],
          properties: { value: { type: "string", maxLength: 64 } },
          additionalProperties: false,
        },
      }],
    })).not.toThrow();
  });

  it("permits an internal hyphen only in the final lowercase capability label", () => {
    expect(validateCapability({ id: "org.example.file-read", version: "1.0.0" }).ok).toBe(true);
    expect(validateCapability({ id: "org.example.file-", version: "1.0.0" }).ok).toBe(false);
    expect(validateCapability({ id: "org.Example.file-read", version: "1.0.0" }).ok).toBe(false);
  });
});
