#!/usr/bin/env node
/**
 * PolyMesh v6 M4 — offline re-route demo (in-process, 3-agent orchestration).
 *
 * Normative demo spec: PM-V6-SPEC.md §D.3 (thesis §D.3.1, roles §D.3.2/§D.3.3,
 * expected output §D.3.6 — the nine observations this script prints).
 *
 * This process plays the role of all three agents (demo.coordinator,
 * demo.worker-a, demo.worker-b) in one Node runtime, using the REAL M1
 * CapabilityRouter for routing/re-route decisions. Only loopback/in-process
 * communication is used — no sockets, no public endpoints, nothing that
 * requires internet.
 *
 * Prints OBSERVATION 2/9 .. OBSERVATION 9/9 (OBSERVATION 1/9 — the offline
 * network check — is proven by the parent shell script before this process
 * is even started).
 */

import {
  createCapabilityRouter,
  freezeRegistryView,
} from "../../packages/client/dist/router.js";

const CAPABILITY = "org.polymesh.demo.summarize";
const AGENT_COORDINATOR = "demo.coordinator";
const AGENT_WORKER_A = "demo.worker-a";
const AGENT_WORKER_B = "demo.worker-b";

// ---------------------------------------------------------------------------
// Logging — every printed line is captured so OBSERVATION 9/9 can verify (for
// real, not by assumption) that no https:// AgentCard URL ever appeared.
// ---------------------------------------------------------------------------

const printedLines = [];
function log(line) {
  printedLines.push(line);
  console.log(line);
}
function fail(message) {
  console.error(`DEMO FAILED: ${message}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Step 1 — Build the RegistryView (§B.11): three agents in one local mesh.
// No cloud registration, no a2a_url, loopback/in-process only.
// ---------------------------------------------------------------------------

const nowIso = new Date().toISOString();

const registry = freezeRegistryView({
  agents: [
    {
      agent_id: AGENT_COORDINATOR,
      display_name: "Demo Coordinator",
      capabilities: [],
      health: "healthy",
      last_seen: nowIso,
      locality: "same_host",
      mesh_member: true,
    },
    {
      agent_id: AGENT_WORKER_A,
      display_name: "Demo Worker A",
      capabilities: [{ name: CAPABILITY, dialect: "native" }],
      health: "healthy",
      last_seen: nowIso,
      locality: "same_host",
      mesh_member: true,
    },
    {
      agent_id: AGENT_WORKER_B,
      display_name: "Demo Worker B",
      capabilities: [{ name: CAPABILITY, dialect: "native" }],
      health: "healthy",
      last_seen: nowIso,
      locality: "same_host",
      mesh_member: true,
    },
  ],
  last_refreshed_at: nowIso,
});

log(
  `OBSERVATION 2/9: Membership — three agents in one local mesh (${AGENT_COORDINATOR}, ${AGENT_WORKER_A}, ${AGENT_WORKER_B})`,
);
for (const a of registry.agents) {
  log(`  [membership] agent=${a.agent_id} locality=${a.locality} health=${a.health} mesh_member=${a.mesh_member}`);
}

// ---------------------------------------------------------------------------
// Step 2 — Capability discovery (§B.4): both workers advertise the demo
// capability before any task is submitted.
// ---------------------------------------------------------------------------

const advertisers = registry.agents.filter((a) =>
  a.capabilities.some((c) => c.name === CAPABILITY),
);

log(`OBSERVATION 3/9: Capability discovery — both workers advertise ${CAPABILITY}`);
for (const a of advertisers) {
  log(`  [discovery] agent=${a.agent_id} capability=${CAPABILITY} dialect=native health=${a.health}`);
}
if (advertisers.length !== 2 || !advertisers.some((a) => a.agent_id === AGENT_WORKER_A) || !advertisers.some((a) => a.agent_id === AGENT_WORKER_B)) {
  fail(`expected exactly demo.worker-a and demo.worker-b to advertise ${CAPABILITY}, got: ${advertisers.map((a) => a.agent_id).join(", ")}`);
}

// ---------------------------------------------------------------------------
// Step 3 — Simulated worker behavior wired through nativeDispatch (§B.3 —
// native dialect dispatch). worker-a always fails mid-task (simulating a
// kill: ETIMEDOUT, a retryable transport failure per §B.7.3). worker-b always
// succeeds.
// ---------------------------------------------------------------------------

let workerACalls = 0;
let workerBCalls = 0;
let workerBResult = null;

async function nativeDispatch(input) {
  if (input.agent_id === AGENT_WORKER_A) {
    workerACalls += 1;
    log(`[lifecycle] accept agent=${AGENT_WORKER_A}`);
    await sleep(5);
    log(`[lifecycle] progress agent=${AGENT_WORKER_A}`);
    await sleep(5);
    log(
      `OBSERVATION 5/9: Lifecycle — submit, route, accept, progress observed`,
    );
    // Simulate the worker process being killed mid-task (SIGKILL analogue):
    // a retryable transport failure (§B.7.3 — ETIMEDOUT classifies retryable).
    const err = new Error("worker-a killed mid-task");
    err.code = "ETIMEDOUT";
    throw err;
  }

  if (input.agent_id === AGENT_WORKER_B) {
    workerBCalls += 1;
    log(`[lifecycle] accept agent=${AGENT_WORKER_B}`);
    await sleep(5);
    log(`[lifecycle] progress agent=${AGENT_WORKER_B}`);
    await sleep(5);
    workerBResult = { summary: `Summary of: ${String(input.payload?.text ?? "").slice(0, 40)}` };
    return;
  }

  throw new Error(`unexpected dispatch target: ${input.agent_id}`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Step 4 — Wire the CapabilityRouter (REAL M1 engine) and observe events.
// ---------------------------------------------------------------------------

const router = createCapabilityRouter({
  registry,
  nativeDispatch,
  adapterAvailable: false,
  observedAt: () => new Date(),
});

const routedEvents = [];
const rerouteEvents = [];

router.onTaskRouted((event) => {
  routedEvents.push(event);
  const excludedNote = event.excluded_agents.length > 0 ? ` excluded=[${event.excluded_agents.join(",")}]` : "";
  log(`[lifecycle] route chosen=${event.chosen_agent} reroute_count=${event.reroute_count}${excludedNote}`);

  if (event.reroute_count === 0) {
    if (event.chosen_agent !== AGENT_WORKER_A) {
      fail(`expected first route to choose ${AGENT_WORKER_A} without explicit target, got ${event.chosen_agent}`);
    }
    log(
      `OBSERVATION 4/9: Capability dispatch — first route selected ${AGENT_WORKER_A} without explicit target`,
    );
  } else if (event.reroute_count === 1) {
    if (event.chosen_agent !== AGENT_WORKER_B) {
      fail(`expected second route to choose ${AGENT_WORKER_B}, got ${event.chosen_agent}`);
    }
    if (!event.excluded_agents.includes(AGENT_WORKER_A)) {
      fail(`expected excluded_agents to contain ${AGENT_WORKER_A}, got: ${event.excluded_agents.join(",")}`);
    }
    log(
      `OBSERVATION 7/9: Re-route — second route selected ${AGENT_WORKER_B}; exclusion contains ${AGENT_WORKER_A}; reroute_count=1`,
    );
  }
});

router.onReroute((event) => {
  rerouteEvents.push(event);
  const retryable = event.reason !== "policy_reject";
  log(`[lifecycle] fail agent=${event.failed_agent} retryable=${retryable}`);
  if (event.failed_agent === AGENT_WORKER_A) {
    if (!retryable) {
      fail(`expected demo.worker-a failure to classify retryable, reason=${event.reason}`);
    }
    log(
      `OBSERVATION 6/9: Failure — demo.worker-a disappeared mid-task; failure classified retryable`,
    );
  }
});

// ---------------------------------------------------------------------------
// Step 5 — Submit the task with NO explicit target: the mesh, not the
// caller, picks the worker (§B.3.1 — capability dispatch).
// ---------------------------------------------------------------------------

log("[lifecycle] submit");

let result;
try {
  result = await router.routeTask({
    capability: CAPABILITY,
    payload: { text: "Three agents on a laptop, no internet. One drops mid-task." },
    side_effects: "none",
    idempotency: "pure",
    maxReroutes: 3,
  });
} catch (err) {
  fail(`routeTask threw unexpectedly: ${err && err.message ? err.message : String(err)}`);
}

// ---------------------------------------------------------------------------
// Step 6 — Validate the full sequence and print terminal-success observation.
// ---------------------------------------------------------------------------

if (routedEvents.length !== 2) {
  fail(`expected exactly 2 task.routed events (first + reroute), got ${routedEvents.length}`);
}
if (rerouteEvents.length !== 1) {
  fail(`expected exactly 1 reroute event, got ${rerouteEvents.length}`);
}
if (result.chosen.agent_id !== AGENT_WORKER_B) {
  fail(`expected final dispatch to land on ${AGENT_WORKER_B}, got ${result.chosen.agent_id}`);
}
if (workerACalls !== 1 || workerBCalls !== 1) {
  fail(`expected worker-a and worker-b each dispatched exactly once, got a=${workerACalls} b=${workerBCalls}`);
}
if (!workerBResult) {
  fail("expected demo.worker-b to produce a result payload");
}

log(`[lifecycle] complete agent=${AGENT_WORKER_B}`);
log(
  `OBSERVATION 8/9: Terminal success — coordinator received completed result from ${AGENT_WORKER_B}`,
);
log(`  [result] task_id=${result.task_id} summary="${workerBResult.summary}"`);

// ---------------------------------------------------------------------------
// Step 7 — Real verification (not assumption) that no public AgentCard URL
// ever appeared in anything this process printed, nor in its own argv.
// ---------------------------------------------------------------------------

const allPriorOutput = printedLines.join("\n");
const argvJoined = process.argv.join(" ");
if (allPriorOutput.includes("https://") || argvJoined.includes("https://")) {
  fail("found an https:// URL in demo output or process args — public endpoints are forbidden for this demo");
}

log(
  "OBSERVATION 9/9: No public endpoints — no https:// AgentCard URLs in process args or logs",
);
