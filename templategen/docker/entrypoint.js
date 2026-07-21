import { chmodSync, chownSync, mkdirSync } from "node:fs";

// This exact, container-local path is the only place the demo shares its
// short-lived runtime token. Do not make it configurable while this entrypoint
// is privileged.
const runtimeDirectory = "/run/polymesh";
// The official Node image's built-in `node` account is uid/gid 1000. fs.chown
// takes numeric IDs (unlike process.setuid/setgid, which also accept names).
const nodeUid = 1000;
const nodeGid = 1000;

if (process.getuid?.() === 0) {
  mkdirSync(runtimeDirectory, { recursive: true, mode: 0o700 });
  chownSync(runtimeDirectory, nodeUid, nodeGid);
  chmodSync(runtimeDirectory, 0o700);
  process.setgid(nodeGid);
  process.setuid(nodeUid);
}

await import("./service.js");
