import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Broker, createAgentCard, generateRuntimeToken } from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

const runtimeDirectory = "/run/polymesh";
const tokenFile = join(runtimeDirectory, "runtime-token");
const brokerReadyFile = join(runtimeDirectory, "broker-ready");
const bobReadyFile = join(runtimeDirectory, "bob-ready");
const completedFile = join(runtimeDirectory, "demo-complete");
const failedFile = join(runtimeDirectory, "demo-failed");
const maxWaitMs = 30_000;
const pollIntervalMs = 100;

const allow = () => ({
  effect: "allow",
  ruleId: "compose-demo",
  policyGeneration: 1,
  leaseId: "compose-demo-lease",
});

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function fileExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function waitForAny(paths, timeoutMs = maxWaitMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const path of paths) {
      if (await fileExists(path)) return path;
    }
    await delay(pollIntervalMs);
  }
  throw new Error(`Timed out waiting for ${paths.map((path) => path.split("/").at(-1)).join(" or ")}`);
}

async function readToken() {
  return (await readFile(tokenFile, "utf8")).trim();
}

async function writeMarker(path) {
  await writeFile(path, "\n", { mode: 0o600 });
}

async function resetRuntimeDirectory() {
  await mkdir(runtimeDirectory, { recursive: true, mode: 0o700 });
  await Promise.all([
    rm(tokenFile, { force: true }),
    rm(brokerReadyFile, { force: true }),
    rm(bobReadyFile, { force: true }),
    rm(completedFile, { force: true }),
    rm(failedFile, { force: true }),
  ]);
}

function developmentClient(card, token, handlers = {}) {
  return new PolyMeshClient({
    card,
    url: "ws://127.0.0.1:7337/polymesh",
    token,
    allowInsecureLoopbackDevelopment: true,
    handlers,
    authorize: allow,
  });
}

async function runBroker() {
  await resetRuntimeDirectory();
  const token = generateRuntimeToken();
  await writeFile(tokenFile, `${token}\n`, { mode: 0o600 });
  const broker = new Broker({
    host: "127.0.0.1",
    port: 7337,
    token,
    allowInsecureLoopbackDevelopment: true,
  });

  try {
    await broker.start();
    await writeMarker(brokerReadyFile);
    process.stdout.write("[broker] ready on its development-only loopback endpoint\n");
    const outcome = await waitForAny([completedFile, failedFile]);
    if (outcome === failedFile) throw new Error("an agent reported a failed demo");
    process.stdout.write("[broker] task completed; closing demo broker\n");
  } catch (error) {
    await writeMarker(failedFile);
    throw error;
  } finally {
    await broker.close();
    // The token is runtime-only and is removed even when the named Docker
    // volume survives after the demonstration exits.
    await Promise.all([rm(tokenFile, { force: true }), rm(brokerReadyFile, { force: true })]);
  }
}

async function runBob() {
  let client;

  try {
    await waitForAny([brokerReadyFile, failedFile]);
    if (await fileExists(failedFile)) throw new Error("broker did not become ready");
    const token = await readToken();
    client = developmentClient(
      createAgentCard({
        agent_id: "com.example.bob",
        capabilities: [{ id: "org.example.echo", version: "1.0.0" }],
      }),
      token,
      {
        "org.example.echo": (input) => {
          const message = typeof input.message === "string" ? input.message : "";
          process.stdout.write(`[bob] echoing: ${message}\n`);
          return { echoed: message };
        },
      },
    );
    await client.connect();
    await writeMarker(bobReadyFile);
    process.stdout.write("[bob] echo capability ready\n");
    const outcome = await waitForAny([completedFile, failedFile]);
    if (outcome === failedFile) throw new Error("the caller could not complete the echo task");
    process.stdout.write("[bob] demo complete\n");
  } catch (error) {
    await writeMarker(failedFile);
    throw error;
  } finally {
    client?.close();
  }
}

async function runAlice() {
  let client;

  try {
    await waitForAny([brokerReadyFile, failedFile]);
    if (await fileExists(failedFile)) throw new Error("broker did not become ready");
    await waitForAny([bobReadyFile, failedFile]);
    if (await fileExists(failedFile)) throw new Error("bob did not become ready");
    client = developmentClient(createAgentCard({ agent_id: "com.example.alice" }), await readToken());
    await client.connect();
    process.stdout.write("[alice] calling bob's echo capability\n");
    const result = await client.call("com.example.bob", "org.example.echo", { message: "hello from alice" });
    process.stdout.write(`[alice] received: ${JSON.stringify(result)}\n`);
    await writeMarker(completedFile);
  } catch (error) {
    await writeMarker(failedFile);
    throw error;
  } finally {
    client?.close();
  }
}

async function main() {
  switch (process.argv[2]) {
    case "broker":
      await runBroker();
      return;
    case "bob":
      await runBob();
      return;
    case "alice":
      await runAlice();
      return;
    default:
      throw new Error("Usage: service.js <broker|bob|alice>");
  }
}

void main().catch((error) => {
  process.stderr.write(`[demo] ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
