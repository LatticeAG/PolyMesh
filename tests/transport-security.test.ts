import { chmod, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createConnection } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  Broker,
  RuntimeTokenAuthority,
  createWirePair,
  decodeRuntimeToken,
  generateRuntimeToken,
  isValidWebSocketCloseCode,
  normalizePeerClose,
  sanitizeCloseReason,
  writeRuntimeTokenAtomically,
} from "@latticeag/polymesh-broker";

const brokers: Broker[] = [];

afterEach(async () => {
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function rawUpgrade(port: number, requestTarget: string, token: string, extraHeaders: string[] = []): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    let response = "";
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error("timed out waiting for upgrade response"));
    }, 2_000);
    socket.setEncoding("utf8");
    socket.on("connect", () => {
      socket.write([
        `GET ${requestTarget} HTTP/1.1`,
        "Host: 127.0.0.1",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Protocol: polymesh.0.1",
        `X-PolyMesh-Token: ${token}`,
        ...extraHeaders,
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk: string) => { response += chunk; });
    socket.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    socket.on("close", () => {
      clearTimeout(timeout);
      resolve(response);
    });
  });
}

describe("transport security", () => {
  it("uses canonical fixed-size tokens and gives normal rotations bounded epochs", () => {
    let now = 1_000;
    const first = generateRuntimeToken();
    const second = generateRuntimeToken();
    const authority = new RuntimeTokenAuthority(first, () => now);

    expect(decodeRuntimeToken(first)).toHaveLength(32);
    expect(decodeRuntimeToken(`${first}=`)).toBeUndefined();
    expect(decodeRuntimeToken("not-a-runtime-token")).toBeUndefined();
    expect(authority.verify(first)).toEqual({ valid: true, authEpoch: 1 });

    authority.rotate(second, { overlapMs: 30 });
    expect(authority.verify(second)).toEqual({ valid: true, authEpoch: 2 });
    expect(authority.verify(first)).toEqual({ valid: true, authEpoch: 1 });
    now += 30;
    authority.clearExpiredPrevious();
    expect(authority.verify(first)).toEqual({ valid: false });
  });

  it("atomically invalidates broker sessions on a hard token rotation", () => {
    const first = generateRuntimeToken();
    const second = generateRuntimeToken();
    const broker = new Broker({ token: first });
    brokers.push(broker);
    const [, brokerWire] = createWirePair();
    const peer = broker.attach(brokerWire, { token: first });

    expect(peer.authEpoch).toBe(1);
    expect(broker.rotateToken(second, { hard: true })).toBe(2);
    expect(peer.phase).toBe("closed");
  });

  it("writes runtime token replacement atomically into an owner-only directory", async () => {
    const directory = await mkdtemp(join(tmpdir(), "polymesh-token-"));
    await chmod(directory, 0o700);
    const path = join(directory, "runtime.token");
    try {
      const token = await writeRuntimeTokenAtomically(path);
      expect(await readFile(path, "utf8")).toBe(token);
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      await expect(writeRuntimeTokenAtomically(path, { token: "not-valid" })).rejects.toThrow(/32 random bytes/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects plaintext network listeners unless numeric-loopback development is explicitly enabled", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ port: 0, host: "127.0.0.1", token });
    brokers.push(broker);
    await expect(broker.start()).rejects.toMatchObject({ code: "INSECURE_TRANSPORT_DISABLED" });

    const development = new Broker({
      port: 0,
      host: "127.0.0.1",
      token,
      allowInsecureLoopbackDevelopment: true,
    });
    brokers.push(development);
    await expect(development.start()).resolves.toBe(development);
  });

  it("rejects token-in-URL, browser origins, duplicate security headers, and extensions before WebSocket allocation", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({
      port: 0,
      host: "127.0.0.1",
      token,
      allowInsecureLoopbackDevelopment: true,
    });
    brokers.push(broker);
    await broker.start();
    const port = broker.port!;

    await expect(rawUpgrade(port, `/polymesh?token=${token}`, token)).resolves.toMatch(/^HTTP\/1\.1 404 /);
    await expect(rawUpgrade(port, "/polymesh", token, [`X-PolyMesh-Token: ${token}`])).resolves.toMatch(/^HTTP\/1\.1 400 /);
    await expect(rawUpgrade(port, "/polymesh", token, ["Origin: https://evil.example"])).resolves.toMatch(/^HTTP\/1\.1 403 /);
    await expect(rawUpgrade(port, "/polymesh", token, ["Sec-WebSocket-Extensions: permessage-deflate"])).resolves.toMatch(/^HTTP\/1\.1 400 /);
  });

  it("treats native close metadata as bounded transport diagnostics", () => {
    expect(isValidWebSocketCloseCode(1000)).toBe(true);
    expect(isValidWebSocketCloseCode(1006)).toBe(false);
    expect(isValidWebSocketCloseCode(1015)).toBe(false);
    expect(isValidWebSocketCloseCode(4999)).toBe(true);
    expect(sanitizeCloseReason(Buffer.alloc(124))).toBe("invalid close reason");
    expect(normalizePeerClose(1006, "retry immediately")).toEqual({ code: 1002, reason: "invalid peer close", valid: false });
  });

  it("never emits reserved 1006 from the in-memory termination path", () => {
    const [left, right] = createWirePair();
    let closeCode: number | undefined;
    right.on("close", (code) => { closeCode = code; });

    left.terminate();
    expect(closeCode).toBe(1000);
  });

  it("normalizes invalid in-memory close codes and oversized reasons", () => {
    const [left, right] = createWirePair();
    let close: { code: number; reason: string } | undefined;
    right.on("close", (code, reason) => { close = { code, reason: reason.toString("utf8") }; });

    left.close(1006, "x".repeat(124));
    expect(close).toEqual({ code: 1000, reason: "connection closed" });
  });
});
