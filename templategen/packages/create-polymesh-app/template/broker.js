import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { Broker, generateRuntimeToken } from "@latticeag/polymesh-broker";

/**
 * Start a token-protected, numeric-loopback-only development broker.
 * This is intentionally local-only: use an enrolled WSS configuration for
 * LAN or remote deployments.
 */
export async function startBroker({ port = 0, token = generateRuntimeToken() } = {}) {
  const broker = new Broker({
    host: "127.0.0.1",
    port,
    token,
    allowInsecureLoopbackDevelopment: true,
  });
  await broker.start();
  return { broker, token, url: broker.url };
}

async function tokenFromFile() {
  const tokenFile = process.env.POLYMESH_TOKEN_FILE;
  if (!tokenFile) {
    throw new Error("Set POLYMESH_TOKEN_FILE, or run the self-contained `npm run demo` command.");
  }
  return (await readFile(tokenFile, "utf8")).trim();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { broker, url } = await startBroker({ token: await tokenFromFile(), port: 7337 });
  process.stdout.write(`PolyMesh development broker listening at ${url}\n`);
  const close = async () => {
    await broker.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void close());
  process.once("SIGTERM", () => void close());
}
