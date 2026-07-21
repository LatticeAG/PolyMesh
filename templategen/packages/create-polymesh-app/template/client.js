import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { createAgentCard } from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

/** Call the broker's built-in ping capability and wait for its pong result. */
export async function pingBroker({ url, token }) {
  const client = new PolyMeshClient({
    card: createAgentCard({ agent_id: "com.example.quickstart-client" }),
    url,
    token,
    allowInsecureLoopbackDevelopment: true,
  });

  try {
    await client.connect();
    return await client.call("org.polymesh.broker", "org.polymesh.agent.ping", {});
  } finally {
    client.close();
  }
}

async function tokenFromFile() {
  const tokenFile = process.env.POLYMESH_TOKEN_FILE;
  if (!tokenFile) throw new Error("Set POLYMESH_TOKEN_FILE, or run `npm run demo`.");
  return (await readFile(tokenFile, "utf8")).trim();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const url = process.env.POLYMESH_URL ?? "ws://127.0.0.1:7337/polymesh";
  await pingBroker({ url, token: await tokenFromFile() });
  process.stdout.write("Received pong from the PolyMesh broker.\n");
}
