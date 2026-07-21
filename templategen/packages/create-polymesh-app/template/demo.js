import { startBroker } from "./broker.js";
import { pingBroker } from "./client.js";

// The token only exists in this process. It is never written to disk, logged,
// or placed in a URL.
const { broker, token, url } = await startBroker();

try {
  await pingBroker({ url, token });
  process.stdout.write("PolyMesh ping/pong completed successfully.\n");
} finally {
  await broker.close();
}
