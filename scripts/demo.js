import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const runtimeDirectory = await mkdtemp(join(tmpdir(), "polymesh-demo-"));
const service = fileURLToPath(new URL("../templategen/docker/service.js", import.meta.url));
const children = [];

function start(role) {
  const child = spawn(process.execPath, [service, role], {
    env: { ...process.env, POLYMESH_DEMO_RUNTIME_DIR: runtimeDirectory },
    stdio: "inherit",
  });
  children.push(child);
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${role} exited with ${signal || `code ${code}`}`));
    });
  });
}

try {
  await Promise.all([start("broker"), start("bob"), start("alice")]);
  console.log("DEMO RESULT: PASSED (two-agent echo)");
} catch (error) {
  console.error(`DEMO RESULT: FAILED reason=${JSON.stringify(error.message)}`);
  process.exitCode = 1;
} finally {
  for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill();
  await Promise.all(children.map((child) => child.exitCode !== null || child.signalCode !== null
    ? Promise.resolve() : new Promise((resolve) => child.once("exit", resolve))));
  await rm(runtimeDirectory, { recursive: true, force: true });
}
