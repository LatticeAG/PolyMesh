import { afterEach, describe, expect, it } from "vitest";

import { Broker, createAgentCard, createWirePair, generateRuntimeToken } from "@polymesh/broker";
import {
  AuditChain,
  HmacAuditSigner,
  InMemoryPolicyStore,
  PolicyEngine,
  PolyMeshClient,
  SqlPolicyStore,
  type ParameterizedSqlExecutor,
  type ParameterizedSqlResult,
  type PolicyAuthorizationRequest,
  type PolicySubject,
} from "@polymesh/client";

const caller = {
  principalId: "key:caller",
  agentId: "com.example.caller",
  keyId: "caller-key",
  authStrength: "enrolled-key" as const,
};

const subjects: PolicySubject[] = [
  { principalId: caller.principalId, agentId: caller.agentId, enabled: true, minimumAuthStrength: "enrolled-key" },
  { principalId: "key:target", agentId: "com.example.target", enabled: true },
];

function request(overrides: Partial<PolicyAuthorizationRequest> = {}): PolicyAuthorizationRequest {
  return {
    principal: caller,
    targetPrincipal: "key:target",
    capability: "org.example.echo",
    input: {},
    taskId: "task-1",
    messageId: "message-1",
    ...overrides,
  };
}

function engineWithRules(rules: ConstructorParameters<typeof InMemoryPolicyStore>[1], now = 1_000) {
  const store = new InMemoryPolicyStore(subjects, rules, 7);
  return new PolicyEngine({ store, now: () => now, leaseTtlMs: 10_000 });
}

describe("PolicyEngine", () => {
  it("uses authenticated principals and makes any matching deny win", async () => {
    const engine = engineWithRules([
      {
        id: "wide-allow",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.example.*",
        effect: "allow",
        priority: 100,
      },
      {
        id: "specific-deny",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.example.echo",
        effect: "deny",
        priority: -100,
      },
    ]);

    await expect(engine.authorize(request())).resolves.toEqual({ effect: "deny", code: "EXPLICIT_DENY" });
    expect(engine.getAuditRecords()).toEqual([
      expect.objectContaining({ effect: "deny", ruleId: "specific-deny", callerPrincipal: "key:caller" }),
    ]);

    await expect(engine.authorize(request({ principal: { ...caller, agentId: "forged-agent" } }))).resolves.toEqual({
      effect: "deny",
      code: "AUTHORIZATION_DENIED",
    });
  });

  it("enforces concrete calendar selectors and maximum results before work", async () => {
    const engine = engineWithRules([
      {
        id: "calendar-dad-work",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.polymesh.calendar.read",
        effect: "allow",
        resourceScope: { users: ["dad"], calendars: ["work"] },
        maxResults: 5,
      },
    ]);

    const permitted = await engine.authorize(request({
      capability: "org.polymesh.calendar.read",
      input: { user: "dad", calendar: "work", range: { from: "2026-01-01", to: "2026-01-02" } },
    }));
    expect(permitted).toMatchObject({ effect: "allow", maxResults: 5, constrainedInput: expect.objectContaining({ page_size: 5 }) });

    await expect(engine.authorize(request({
      capability: "org.polymesh.calendar.read",
      input: { user: "mum", calendar: "work", range: {} },
    }))).resolves.toEqual({ effect: "deny", code: "RESOURCE_SCOPE_VIOLATION" });

    await expect(engine.authorize(request({
      capability: "org.polymesh.calendar.read",
      input: { user: "dad", calendar: "work", page_size: 6, range: {} },
    }))).resolves.toEqual({ effect: "deny", code: "RESOURCE_SCOPE_VIOLATION" });
  });

  it("denies scoped rules without an implementation-owned scope adapter", async () => {
    const engine = engineWithRules([
      {
        id: "unsafe-generic-scope",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.example.echo",
        effect: "allow",
        resourceScope: { tenant: "expected" },
      },
    ]);

    await expect(engine.authorize(request())).resolves.toEqual({ effect: "deny", code: "RESOURCE_SCOPE_VIOLATION" });
  });

  it("does not let a wildcard allow grant an unknown or sensitive capability", async () => {
    const wildcardRule = {
      id: "broad-rule",
      targetPrincipal: "key:target",
      callerPrincipal: "key:caller",
      capability: "org.example.*",
      effect: "allow" as const,
    };
    const unknownEngine = engineWithRules([wildcardRule]);
    await expect(unknownEngine.authorize(request())).resolves.toEqual({
      effect: "deny",
      code: "WILDCARD_CAPABILITY_DENIED",
    });

    const knownEngine = new PolicyEngine({
      store: new InMemoryPolicyStore(subjects, [wildcardRule], 7),
      now: () => 1_000,
      capabilityDescriptors: [{ id: "org.example.echo", risk: "read" }],
    });
    await expect(knownEngine.authorize(request())).resolves.toMatchObject({ effect: "allow", ruleId: "broad-rule" });
  });

  it("fences revoked leases and filters only while their recipient lease is live", async () => {
    const engine = engineWithRules([
      {
        id: "filtered-read",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.example.echo",
        effect: "allow",
        dataFilter: "no_personal",
      },
    ]);
    const decision = await engine.authorize(request());
    if (decision.effect !== "allow") throw new Error("expected allow");

    expect(engine.validateLease(decision.leaseId, request(), decision.lease.fence)).toBe(true);
    expect(engine.filterForRelease(decision.leaseId, request(), {
      public: "safe",
      email: "person@example.test",
      nested: { phone: "+44 20 0000 0000", status: "ok" },
    })).toEqual({ public: "safe", nested: { status: "ok" } });

    expect(engine.revokeLease(decision.leaseId)).toBe(true);
    expect(engine.validateLease(decision.leaseId, request(), decision.lease.fence)).toBe(false);
    expect(engine.filterForRelease(decision.leaseId, request(), { public: "must not release" })).toBeUndefined();
  });

  it("allows only deterministic built-in filters and detects audit-chain tampering", () => {
    expect(() => new InMemoryPolicyStore(subjects, [{
      id: "custom-filter",
      targetPrincipal: "key:target",
      callerPrincipal: "key:caller",
      capability: "org.example.echo",
      effect: "allow",
      dataFilter: "javascript:process.env" as never,
    }])).toThrow(/Invalid permission rule/);

    const audit = new AuditChain(new HmacAuditSigner(Buffer.alloc(32, 7)));
    audit.append({
      timestamp: 1,
      targetPrincipal: "key:target",
      callerPrincipal: "key:caller",
      capability: "org.example.echo",
      effect: "allow",
      reason: "test",
      policyGeneration: 1,
    });
    const records = audit.snapshot();
    expect(audit.verify(records)).toBe(true);
    const tampered = [{ ...records[0]!, reason: "rewritten" }];
    expect(audit.verify(tampered)).toBe(false);
  });

  it("uses static SQL with bound parameters for every policy lookup", async () => {
    const calls: Array<{ statement: string; parameters: readonly (string | number | boolean | null)[] }> = [];
    const executor: ParameterizedSqlExecutor = {
      query: async <Row extends Record<string, unknown>>(
        statement: string,
        parameters: readonly (string | number | boolean | null)[],
      ): Promise<ParameterizedSqlResult<Row>> => {
        calls.push({ statement, parameters });
        let rows: Record<string, unknown>[] = [];
        if (statement.includes("FROM policy_generation")) rows = [{ generation: 3 }];
        else if (statement.includes("FROM agents")) {
          const principal = parameters[0];
          rows = [{
            principal_id: principal,
            agent_id: principal === "key:caller" ? "com.example.caller" : "com.example.target",
            enabled: true,
            minimum_auth_strength: principal === "key:caller" ? "enrolled-key" : null,
            credential_id: null,
          }];
        } else if (statement.includes("FROM permissions")) {
          rows = [{
            id: "sql-rule",
            target_principal: "key:target",
            caller_principal: "key:caller",
            capability: "org.example.echo",
            resource_scope: null,
            data_filter: "full",
            max_results: null,
            priority: 0,
            effect: "allow",
            enabled: true,
            expires_at: null,
            min_auth_strength: null,
            credential_id: null,
          }];
        }
        return { rows: rows as Row[] };
      },
      transaction: async <T>(operation: (transaction: ParameterizedSqlExecutor) => Promise<T>): Promise<T> => operation(executor),
    };
    const engine = new PolicyEngine({ store: new SqlPolicyStore(executor), now: () => 1_000 });

    await expect(engine.authorize(request())).resolves.toMatchObject({ effect: "allow", ruleId: "sql-rule" });
    const permissionQuery = calls.find((call) => call.statement.includes("FROM permissions"));
    expect(permissionQuery?.parameters).toHaveLength(3);
    expect(permissionQuery?.parameters.slice(0, 2)).toEqual(["key:target", "key:caller"]);
    expect(permissionQuery?.statement).not.toContain("key:caller");
  });
});

describe("client authorization decision boundary", () => {
  const clients: PolyMeshClient[] = [];
  const brokers: Broker[] = [];

  afterEach(async () => {
    for (const client of clients.splice(0)) client.close();
    await Promise.all(brokers.splice(0).map((broker) => broker.close()));
  });

  it("fails closed for truthy and malformed authorization callback values", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token });
    brokers.push(broker);
    const callerClient = new PolyMeshClient({ card: createAgentCard({ agent_id: "caller" }) });
    let invoked = 0;
    const malformedClient = new PolyMeshClient({
      card: createAgentCard({ agent_id: "malformed", capabilities: [{ id: "org.example.echo", version: "1.0.0" }] }),
      handlers: { "org.example.echo": () => { invoked += 1; return {}; } },
      authorize: (() => ({ allowed: false })) as never,
    });
    const truthyClient = new PolyMeshClient({
      card: createAgentCard({ agent_id: "truthy", capabilities: [{ id: "org.example.echo", version: "1.0.0" }] }),
      handlers: { "org.example.echo": () => { invoked += 1; return {}; } },
      authorize: (() => true) as never,
    });
    clients.push(callerClient, malformedClient, truthyClient);

    const [callerWire, brokerCallerWire] = createWirePair();
    const [malformedWire, brokerMalformedWire] = createWirePair();
    const [truthyWire, brokerTruthyWire] = createWirePair();
    broker.attach(brokerCallerWire, { token });
    broker.attach(brokerMalformedWire, { token });
    broker.attach(brokerTruthyWire, { token });
    await Promise.all([
      callerClient.connectTransport(callerWire),
      malformedClient.connectTransport(malformedWire),
      truthyClient.connectTransport(truthyWire),
    ]);

    await expect(callerClient.call("malformed", "org.example.echo", {})).rejects.toMatchObject({ code: "AUTHORIZATION_DENIED" });
    await expect(callerClient.call("truthy", "org.example.echo", {})).rejects.toMatchObject({ code: "AUTHORIZATION_DENIED" });
    expect(invoked).toBe(0);
  });

  it("uses the verified-principal policy path to constrain input and filter terminal output", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token });
    brokers.push(broker);
    const engine = new PolicyEngine({
      store: new InMemoryPolicyStore(subjects, [{
        id: "calendar-policy",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.polymesh.calendar.read",
        effect: "allow",
        resourceScope: { users: ["dad"], calendars: ["work"] },
        maxResults: 2,
        dataFilter: "no_personal",
      }], 7),
      now: () => 1_000,
      leaseTtlMs: 10_000,
    });
    const callerClient = new PolyMeshClient({ card: createAgentCard({ agent_id: "com.example.caller" }) });
    let handlerInput: Record<string, unknown> | undefined;
    const targetClient = new PolyMeshClient({
      card: createAgentCard({
        agent_id: "com.example.target",
        capabilities: [{ id: "org.polymesh.calendar.read", version: "1.0.0" }],
      }),
      handlers: {
        "org.polymesh.calendar.read": (input) => {
          handlerInput = input;
          return {
            status: "ok",
            email: "dad@example.test",
            nested: { body: "private calendar content", count: 1 },
          };
        },
      },
      // This legacy allow must not be consulted when PolicyEngine is present.
      authorize: () => ({ effect: "allow", ruleId: "legacy", policyGeneration: 0, leaseId: "legacy" }),
      policyEngine: engine,
      policyTargetPrincipal: "key:target",
      resolveVerifiedPrincipal: ({ source }) => {
        if (source.agent_id !== "com.example.caller") throw new Error("unverified source");
        return caller;
      },
    });
    clients.push(callerClient, targetClient);

    const [callerWire, brokerCallerWire] = createWirePair();
    const [targetWire, brokerTargetWire] = createWirePair();
    broker.attach(brokerCallerWire, { token });
    broker.attach(brokerTargetWire, { token });
    await Promise.all([callerClient.connectTransport(callerWire), targetClient.connectTransport(targetWire)]);

    await expect(callerClient.call("com.example.target", "org.polymesh.calendar.read", {
      user: "dad",
      calendar: "work",
      range: { from: "2026-01-01", to: "2026-01-02" },
    })).resolves.toEqual({ status: "ok", nested: { count: 1 } });
    expect(handlerInput).toMatchObject({ user: "dad", calendar: "work", page_size: 2 });
  });

  it("fails closed when principal resolution fails rather than falling back to authorize", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token });
    brokers.push(broker);
    const engine = new PolicyEngine({
      store: new InMemoryPolicyStore(subjects, [{
        id: "echo-policy",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.example.echo",
        effect: "allow",
      }], 7),
      now: () => 1_000,
    });
    const callerClient = new PolyMeshClient({ card: createAgentCard({ agent_id: "com.example.caller" }) });
    let invoked = 0;
    const targetClient = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.target", capabilities: [{ id: "org.example.echo", version: "1.0.0" }] }),
      handlers: { "org.example.echo": () => { invoked += 1; return {}; } },
      authorize: () => ({ effect: "allow", ruleId: "legacy", policyGeneration: 0, leaseId: "legacy" }),
      policyEngine: engine,
      policyTargetPrincipal: "key:target",
      resolveVerifiedPrincipal: () => { throw new Error("no provenance"); },
    });
    clients.push(callerClient, targetClient);

    const [callerWire, brokerCallerWire] = createWirePair();
    const [targetWire, brokerTargetWire] = createWirePair();
    broker.attach(brokerCallerWire, { token });
    broker.attach(brokerTargetWire, { token });
    await Promise.all([callerClient.connectTransport(callerWire), targetClient.connectTransport(targetWire)]);

    await expect(callerClient.call("com.example.target", "org.example.echo", {})).rejects.toMatchObject({ code: "AUTHORIZATION_DENIED" });
    expect(invoked).toBe(0);
  });

  it("re-checks the authorization lease before releasing a handler result", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token });
    brokers.push(broker);
    const engine = new PolicyEngine({
      store: new InMemoryPolicyStore(subjects, [{
        id: "lease-policy",
        targetPrincipal: "key:target",
        callerPrincipal: "key:caller",
        capability: "org.example.echo",
        effect: "allow",
      }], 7),
      now: () => 1_000,
      leaseTtlMs: 10_000,
    });
    const callerClient = new PolyMeshClient({ card: createAgentCard({ agent_id: "com.example.caller" }) });
    const terminals: unknown[] = [];
    callerClient.on("envelope", (envelope) => {
      if (envelope.type === "task.completed") terminals.push(envelope.params.terminal);
    });
    const targetClient = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.target", capabilities: [{ id: "org.example.echo", version: "1.0.0" }] }),
      handlers: {
        "org.example.echo": () => {
          engine.revokeAllForPolicyChange(8);
          return { secret: "must-not-leave-the-target" };
        },
      },
      policyEngine: engine,
      policyTargetPrincipal: "key:target",
      resolveVerifiedPrincipal: () => caller,
    });
    clients.push(callerClient, targetClient);

    const [callerWire, brokerCallerWire] = createWirePair();
    const [targetWire, brokerTargetWire] = createWirePair();
    broker.attach(brokerCallerWire, { token });
    broker.attach(brokerTargetWire, { token });
    await Promise.all([callerClient.connectTransport(callerWire), targetClient.connectTransport(targetWire)]);

    await expect(callerClient.call("com.example.target", "org.example.echo", {})).rejects.toMatchObject({ code: "AUTHORIZATION_DENIED" });
    expect(JSON.stringify(terminals)).not.toContain("must-not-leave-the-target");
    expect(terminals).toContainEqual(expect.objectContaining({ outcome: "failed", error: expect.objectContaining({ code: "AUTHORIZATION_DENIED" }) }));
  });
});
