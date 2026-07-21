import { defineConfig } from "vitest/config";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@latticeag/polymesh-broker/protocol": fileURLToPath(new URL("./packages/broker/src/protocol.ts", import.meta.url)),
      "@latticeag/polymesh-broker": fileURLToPath(new URL("./packages/broker/src/index.ts", import.meta.url)),
      "@latticeag/polymesh-client": fileURLToPath(new URL("./packages/client/src/index.ts", import.meta.url)),
      "@latticeag/polymesh-gateway": fileURLToPath(new URL("./packages/gateway/src/index.ts", import.meta.url)),
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 10_000,
    hookTimeout: 10_000
  }
});
