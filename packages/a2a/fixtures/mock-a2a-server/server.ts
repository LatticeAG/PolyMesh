/**
 * §E.1.2 fixture entry point for the mock A2A JSON-RPC server.
 * The implementation lives in `src/` so it ships with the built package.
 */
export {
  createMockA2AServer,
  type CapturedRequest,
  type MockA2AFailure,
  type MockA2AServer,
  type MockA2AServerOptions,
} from "../../src/mock-a2a-server.js";
