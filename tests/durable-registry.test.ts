import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  DurableIdentityCollisionError,
  DurableRegistry,
} from "@polymesh/broker";
import {
  InMemoryDurableStore,
  SqliteDurableStore,
} from "../packages/broker/src/durable-store.js";

const sqliteStores = new Set<SqliteDurableStore>();
const directories: string[] = [];

afterEach(async () => {
  for (const store of sqliteStores) {
    try {
      store.close();
    } catch {
      // A test may already have closed the first process's database handle.
    }
  }
  sqliteStores.clear();
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function databasePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "polymesh-durable-registry-"));
  directories.push(directory);
  return join(directory, "registry.sqlite");
}

function openStore(filename: string, clock: () => number): SqliteDurableStore {
  const store = new SqliteDurableStore({ filename, clock });
  sqliteStores.add(store);
  return store;
}

function closeForRestart(store: SqliteDurableStore): void {
  store.close();
  sqliteStores.delete(store);
}

describe("DurableRegistry", () => {
  it("allows multiple physical instances for one principal and rejects an identity collision", async () => {
    const now = 10_000;
    const registry = new DurableRegistry<{ connection: string }, { revision: number }>({
      store: new InMemoryDurableStore(),
      meshId: "msh-registry",
      principalId: "principal:executor",
      ttlMs: 1_000,
      clock: () => now,
    });

    await registry.registerDurable({
      agentId: "com.example.executor",
      instanceId: "executor-a",
      sessionId: "session-a",
      transport: { connection: "socket-a" },
      card: { revision: 1 },
    });
    await registry.registerDurable({
      agentId: "com.example.executor",
      instanceId: "executor-b",
      sessionId: "session-b",
      transport: { connection: "socket-b" },
      card: { revision: 1 },
    });

    await expect(registry.listDurable({ agentId: "com.example.executor" })).resolves.toEqual(expect.arrayContaining([
      expect.objectContaining({
        agentId: "com.example.executor",
        instanceId: "executor-a",
        principalId: "principal:executor",
        transport: { connection: "socket-a" },
      }),
      expect.objectContaining({
        agentId: "com.example.executor",
        instanceId: "executor-b",
        principalId: "principal:executor",
        transport: { connection: "socket-b" },
      }),
    ]));

    await expect(registry.registerDurable({
      agentId: "com.example.executor",
      instanceId: "executor-untrusted",
      sessionId: "session-untrusted",
      principalId: "principal:other",
    })).rejects.toBeInstanceOf(DurableIdentityCollisionError);
  });

  it("keeps the SQLite registration after a process restart but rebuilds only its local transport index", async () => {
    let now = 20_000;
    const filename = await databasePath();
    const firstStore = openStore(filename, () => now);
    const firstRegistry = new DurableRegistry<{ connection: string }, { revision: number }>({
      store: firstStore,
      meshId: "msh-reopen",
      principalId: "principal:executor",
      ttlMs: 1_000,
      clock: () => now,
    });
    const firstTransport = { connection: "process-one-socket" };
    const first = await firstRegistry.registerDurable({
      agentId: "com.example.executor",
      instanceId: "executor-a",
      sessionId: "session-one",
      transport: firstTransport,
      card: { revision: 7 },
      cardDigest: "digest-7",
      cardRevision: 7,
    });
    expect(first.transport).toBe(firstTransport);
    await expect(firstStore.getInstance("msh-reopen", "com.example.executor", "executor-a")).resolves.toMatchObject({
      principalId: "principal:executor",
      card: { revision: 7 },
      cardDigest: "digest-7",
      registrationFence: first.registrationFence,
      sessionFence: first.sessionFence,
    });
    closeForRestart(firstStore);

    now += 1;
    const restartedStore = openStore(filename, () => now);
    const restartedRegistry = new DurableRegistry<{ connection: string }, { revision: number }>({
      store: restartedStore,
      meshId: "msh-reopen",
      principalId: "principal:executor",
      ttlMs: 1_000,
      clock: () => now,
    });

    const recovered = await restartedRegistry.lookupDurable("com.example.executor", "executor-a");
    expect(recovered).toMatchObject({
      principalId: "principal:executor",
      sessionId: "session-one",
      registrationFence: first.registrationFence,
      sessionFence: first.sessionFence,
    });
    expect(recovered).not.toHaveProperty("transport");
    expect(restartedRegistry.transportFor("com.example.executor", "executor-a")).toBeUndefined();

    const secondTransport = { connection: "process-two-socket" };
    const reconnected = await restartedRegistry.registerDurable({
      agentId: "com.example.executor",
      instanceId: "executor-a",
      sessionId: "session-two",
      transport: secondTransport,
    });
    expect(reconnected).toMatchObject({
      registrationFence: first.registrationFence + 1,
      sessionFence: first.sessionFence + 1,
    });
    expect(reconnected.transport).toBe(secondTransport);
    expect(restartedRegistry.transportFor("com.example.executor", "executor-a")).toBe(secondTransport);
  });

  it("does not let a stale disconnect fence remove a replacement connection", async () => {
    const now = 30_000;
    const registry = new DurableRegistry<{ connection: string }>({
      store: new InMemoryDurableStore(),
      meshId: "msh-fence",
      principalId: "principal:executor",
      ttlMs: 1_000,
      clock: () => now,
    });
    const oldTransport = { connection: "old-socket" };
    const original = await registry.registerDurable({
      agentId: "com.example.executor",
      instanceId: "executor-a",
      sessionId: "session-old",
      transport: oldTransport,
    });
    const replacementTransport = { connection: "replacement-socket" };
    const replacement = await registry.registerDurable({
      agentId: "com.example.executor",
      instanceId: "executor-a",
      sessionId: "session-new",
      transport: replacementTransport,
    });
    expect(replacement.registrationFence).toBe(original.registrationFence + 1);
    expect(replacement.sessionFence).toBe(original.sessionFence + 1);

    await expect(registry.removeDurable({
      agentId: "com.example.executor",
      instanceId: "executor-a",
      registrationFence: original.registrationFence,
      sessionFence: original.sessionFence,
    })).resolves.toBe(false);
    await expect(registry.lookupDurable("com.example.executor", "executor-a")).resolves.toMatchObject({
      registrationFence: replacement.registrationFence,
      sessionFence: replacement.sessionFence,
      transport: replacementTransport,
    });

    await expect(registry.removeDurable({
      agentId: "com.example.executor",
      instanceId: "executor-a",
      registrationFence: replacement.registrationFence,
      sessionFence: replacement.sessionFence,
    })).resolves.toBe(true);
    await expect(registry.lookupDurable("com.example.executor", "executor-a")).resolves.toBeUndefined();
    expect(registry.transportFor("com.example.executor", "executor-a")).toBeUndefined();
  });
});
