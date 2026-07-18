import { describe, expect, it } from "vitest";

import {
  capabilityContractTuple,
  createEnvelope,
  randomInstanceId,
  uuidv7,
  type Envelope,
  type JsonObject,
} from "@polymesh/broker";
import {
  InMemoryReplayLedger,
  replayLedgerKeys,
  type ReplayAdmission,
} from "@polymesh/client";

const deadline = "2026-07-18T12:10:00.000Z";
const target = { agent_id: "com.example.target", instance_id: randomInstanceId() };
const principal = { principalId: "key:caller-key", keyId: "caller-key" };

interface SubmitParams extends JsonObject {
  task_id: string;
  method: string;
  capability_version: string;
  capability_contract_digest: string;
  params: JsonObject;
  deadline: string;
}

const writeContract = capabilityContractTuple({ id: "org.example.write", version: "1.0.0" });

function submit(overrides: {
  sourceInstance?: string;
  messageId?: string;
  idempotencyKey?: string;
  input?: JsonObject;
  taskId?: string;
} = {}): Envelope<"task.submit", SubmitParams> {
  const taskId = overrides.taskId ?? uuidv7(1_000);
  return createEnvelope<"task.submit", SubmitParams>({
    type: "task.submit",
    source: { agent_id: "com.example.caller", instance_id: overrides.sourceInstance ?? randomInstanceId() },
    target,
    message_id: overrides.messageId ?? uuidv7(1_001),
    delivery: {
      mode: "at_least_once",
      idempotency_key: overrides.idempotencyKey ?? "stable-submit",
      deadline,
    },
    params: {
      task_id: taskId,
      method: "org.example.write",
      capability_version: writeContract.capability_version,
      capability_contract_digest: writeContract.capability_contract_digest,
      params: overrides.input ?? { value: 1 },
      deadline,
    },
  });
}

function admission(envelope: ReturnType<typeof submit>, now = 2_000): ReplayAdmission {
  return {
    principal,
    target,
    envelope,
    taskId: envelope.params.task_id,
    now,
    expiresAt: 10_000,
  };
}

describe("ReplayLedger", () => {
  it("keys idempotency by stable verified principal rather than source instance", async () => {
    const ledger = new InMemoryReplayLedger({ now: () => 2_000 });
    const first = submit({ sourceInstance: randomInstanceId(), messageId: uuidv7(1_001) });
    const retry = submit({
      sourceInstance: randomInstanceId(),
      messageId: uuidv7(1_002),
      taskId: first.params.task_id,
    });

    const firstResult = await ledger.admit(admission(first));
    const retryResult = await ledger.admit(admission(retry));

    expect(firstResult.disposition).toBe("new");
    expect(retryResult.disposition).toBe("duplicate");
    expect(ledger.snapshot()).toHaveLength(1);
    expect(replayLedgerKeys(admission(first)).idempotency).toBe(replayLedgerKeys(admission(retry)).idempotency);
  });

  it("distinguishes message reuse, idempotency reuse, and task-id conflicts", async () => {
    const ledger = new InMemoryReplayLedger();
    const first = submit({ messageId: uuidv7(2_001), taskId: uuidv7(2_000) });
    await ledger.admit(admission(first));

    const changedMessage = submit({
      messageId: first.message_id,
      taskId: first.params.task_id,
      input: { value: 2 },
    });
    await expect(ledger.admit(admission(changedMessage))).resolves.toMatchObject({ disposition: "message-conflict" });

    const changedIdempotency = submit({
      messageId: uuidv7(2_002),
      taskId: first.params.task_id,
      input: { value: 2 },
    });
    await expect(ledger.admit(admission(changedIdempotency))).resolves.toMatchObject({ disposition: "idempotency-conflict" });

    const changedTask = submit({
      messageId: uuidv7(2_003),
      idempotencyKey: "new-key",
      taskId: first.params.task_id,
      input: { value: 2 },
    });
    await expect(ledger.admit(admission(changedTask))).resolves.toMatchObject({ disposition: "task-conflict" });
  });

  it("retains terminal replay artifacts through the supplied result-retention expiry", async () => {
    let now = 3_000;
    const ledger = new InMemoryReplayLedger({ now: () => now });
    const taskId = uuidv7(3_000);
    const input = submit({ taskId, messageId: uuidv7(3_001) });
    const accepted = await ledger.admit({ ...admission(input, now), expiresAt: 8_000 });
    if (accepted.disposition !== "new") throw new Error("expected fresh admission");
    const completion = createEnvelope({
      type: "task.completed",
      source: target,
      target: input.source,
      delivery: { mode: "at_least_once", idempotency_key: `completed:${taskId}:2`, deadline },
      params: {
        task_id: taskId,
        event_seq: 2,
        ...writeContract,
        terminal: { outcome: "succeeded", result: { ok: true }, completed_at: "2026-07-18T12:00:01.000Z" },
      },
    });
    await ledger.recordArtifacts({
      taskKey: accepted.record.keys.task,
      artifacts: { events: [completion], terminal: true },
      expiresAt: 9_000,
    });

    now = 8_500;
    const duplicate = await ledger.admit({ ...admission(input, now), expiresAt: 9_000 });
    expect(duplicate).toMatchObject({ disposition: "duplicate", record: { artifacts: { terminal: true } } });
    if (duplicate.disposition !== "duplicate") throw new Error("expected duplicate");
    expect(duplicate.record.artifacts.events).toHaveLength(1);

    now = 9_001;
    await ledger.prune(now);
    expect(ledger.snapshot()).toEqual([]);
  });

  it("does not advertise process-local storage as durable by default", () => {
    expect(new InMemoryReplayLedger().durable).toBe(false);
    expect(new InMemoryReplayLedger({ durableForTesting: true }).durable).toBe(true);
  });
});
