/**
 * PolyMesh v6 M4 — offline re-route demo as executable conformance test
 * (PM-V6-SPEC.md §D.3.6 observations, §E.4.6 demo-as-conformance-test).
 *
 * Spawns scripts/demo-offline-reroute.sh and asserts that all nine
 * normative OBSERVATION markers appear in stdout, strictly in order, and
 * that the final `DEMO RESULT: PASSED` line is present.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const scriptPath = path.join(root, "scripts", "demo-offline-reroute.sh");

const EXPECTED_OBSERVATIONS = [
  "OBSERVATION 1/9: Offline proof — outbound internet check failed",
  "OBSERVATION 2/9: Membership — three agents in one local mesh (demo.coordinator, demo.worker-a, demo.worker-b)",
  "OBSERVATION 3/9: Capability discovery — both workers advertise org.polymesh.demo.summarize",
  "OBSERVATION 4/9: Capability dispatch — first route selected demo.worker-a without explicit target",
  "OBSERVATION 5/9: Lifecycle — submit, route, accept, progress observed",
  "OBSERVATION 6/9: Failure — demo.worker-a disappeared mid-task; failure classified retryable",
  "OBSERVATION 7/9: Re-route — second route selected demo.worker-b; exclusion contains demo.worker-a; reroute_count=1",
  "OBSERVATION 8/9: Terminal success — coordinator received completed result from demo.worker-b",
  "OBSERVATION 9/9: No public endpoints — no https:// AgentCard URLs in process args or logs",
];

describe("PolyMesh v6 M4 — offline re-route demo (§D.3.6)", () => {
  it(
    "prints all nine normative observations in order and reports PASSED",
    () => {
      const result = spawnSync("bash", [scriptPath], {
        cwd: root,
        encoding: "utf8",
        timeout: 100_000,
      });

      const combinedOutput = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;

      expect(
        result.error,
        `demo script failed to spawn: ${String(result.error)}`,
      ).toBeUndefined();
      expect(
        result.status,
        `demo script exited non-zero.\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`,
      ).toBe(0);

      let previousIndex = -1;
      for (const marker of EXPECTED_OBSERVATIONS) {
        const idx = result.stdout.indexOf(marker);
        expect(idx, `missing or out-of-order marker: ${marker}\n--- stdout ---\n${result.stdout}`).toBeGreaterThan(
          previousIndex,
        );
        previousIndex = idx;
      }

      expect(result.stdout).toContain("DEMO RESULT: PASSED");
      expect(result.stdout.indexOf("DEMO RESULT: PASSED")).toBeGreaterThan(previousIndex);

      // §D.3.6 observation 9 is also a hard invariant of the whole run.
      // (Matches an actual URL, e.g. `https://host/...`; the OBSERVATION 9/9
      // marker text itself legitimately mentions the string "https://" in
      // prose — "no https:// AgentCard URLs" — so a bare substring check
      // would false-positive on the marker describing its own absence.)
      expect(combinedOutput).not.toMatch(/https:\/\/\S/);
    },
    120_000,
  );
});
