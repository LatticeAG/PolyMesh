import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  HierarchicalRateLimiter,
  InMemoryAtomicTokenBucketStore,
  SqliteAtomicTokenBucketStore,
  rateLimitBucketKey,
  type AtomicTokenBucketStore,
} from "../packages/broker/src/rate-limit.js";
import {
  compressionRateLimitCharges,
  isCompressionRecordType,
  negotiateCompression,
  validateCompressionRecordBinding,
  validateDecompressedOutput,
  validateCompressionFrame,
} from "../packages/broker/src/compression.js";

describe("HierarchicalRateLimiter", () => {
  it("refills token buckets and returns an exact retry_after_ms", () => {
    let now = 0;
    const limiter = new HierarchicalRateLimiter({
      clock: () => now,
      policies: {
        principalOperation: {
          envelope_count: { capacity: 2, refillPerMs: 0.01 },
        },
      },
    });
    const context = { meshId: "mesh-a", principalId: "principal-a" };

    expect(limiter.consume(context, "envelope_count").allowed).toBe(true);
    expect(limiter.consume(context, "envelope_count").allowed).toBe(true);
    expect(limiter.consume(context, "envelope_count")).toMatchObject({
      allowed: false,
      code: "RATE_LIMITED",
      retry_after_ms: 100,
    });

    now = 40;
    expect(limiter.consume(context, "envelope_count")).toMatchObject({
      allowed: false,
      retry_after_ms: 60,
    });
    now = 100;
    expect(limiter.consume(context, "envelope_count").allowed).toBe(true);
  });

  it("checks every configured hierarchy bucket atomically", () => {
    let now = 0;
    const store = new InMemoryAtomicTokenBucketStore();
    const policies = {
      principalOperation: {
        envelope_count: { capacity: 10, refillPerMs: 0 },
      },
      principalTarget: {
        envelope_count: { capacity: 1, refillPerMs: 0 },
      },
    };
    const limiter = new HierarchicalRateLimiter({ policies, store, clock: () => now });
    const context = { meshId: "mesh-a", principalId: "principal-a", targetAgentId: "target-a" };

    expect(limiter.consume(context, "envelope_count", 2)).toMatchObject({
      allowed: false,
      code: "RATE_LIMITED",
      retry_after_ms: null,
    });
    const principalKey = rateLimitBucketKey("principal_operation", context, "envelope_count");
    expect(store.get(principalKey)).toBeUndefined();

    // Use the same shared store with a narrower policy to prove the failed
    // target quota did not debit the principal quota first.
    const principalOnly = new HierarchicalRateLimiter({
      store,
      clock: () => now,
      policies: { principalOperation: policies.principalOperation },
    });
    expect(principalOnly.consume({ meshId: "mesh-a", principalId: "principal-a" }, "envelope_count", 10).allowed).toBe(true);
  });

  it("fails closed when a configured scope has no trusted key material", () => {
    const limiter = new HierarchicalRateLimiter({
      clock: () => 0,
      policies: { connection: { handshake: { capacity: 5, refillPerMs: 1 } } },
    });

    expect(limiter.consume({}, "handshake")).toEqual({
      allowed: false,
      code: "RATE_LIMIT_CONTEXT_MISSING",
      retry_after_ms: null,
      missingScopes: ["connection"],
      bucketKeys: [],
    });
    expect(limiter.admit({}, [{ operation: "handshake", cost: 1 }], { missingScopeBehavior: "skip" })).toEqual({
      allowed: true,
      code: undefined,
      retry_after_ms: 0,
      bucketKeys: [],
    });
  });

  it("does not oversubscribe a fixed bucket under a burst of admissions", async () => {
    const limiter = new HierarchicalRateLimiter({
      clock: () => 0,
      policies: { connection: { envelope_count: { capacity: 3, refillPerMs: 0 } } },
    });
    const context = { preAuthIp: "127.0.0.1", connectionId: "connection-a" };
    const decisions = await Promise.all(
      Array.from({ length: 12 }, () => Promise.resolve(limiter.consume(context, "envelope_count"))),
    );

    expect(decisions.filter((decision) => decision.allowed)).toHaveLength(3);
    expect(decisions.filter((decision) => !decision.allowed && decision.code === "RATE_LIMITED")).toHaveLength(9);
  });

  it("coordinates one fixed quota across separate SQLite-backed broker stores", async () => {
    const directory = await mkdtemp(join(tmpdir(), "polymesh-rate-limit-"));
    const filename = join(directory, "limits.sqlite");
    let now = 50_000;
    const firstStore = new SqliteAtomicTokenBucketStore(filename);
    const secondStore = new SqliteAtomicTokenBucketStore(filename);
    try {
      const policies = { principalOperation: { envelope_count: { capacity: 2, refillPerMs: 0 } } };
      const first = new HierarchicalRateLimiter({ policies, store: firstStore, clock: () => now });
      const second = new HierarchicalRateLimiter({ policies, store: secondStore, clock: () => now });
      const context = { meshId: "mesh-shared", principalId: "principal-shared" };
      expect(first.distributed).toBe(true);
      expect(first.consume(context, "envelope_count").allowed).toBe(true);
      expect(second.consume(context, "envelope_count").allowed).toBe(true);
      expect(first.consume(context, "envelope_count")).toMatchObject({ allowed: false, retry_after_ms: null });
      now += 1;
      expect(second.consume(context, "envelope_count")).toMatchObject({ allowed: false, retry_after_ms: null });
    } finally {
      firstStore.close();
      secondStore.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("does not compare process-local monotonic clock origins through SQLite", async () => {
    const directory = await mkdtemp(join(tmpdir(), "polymesh-rate-limit-clock-"));
    const filename = join(directory, "limits.sqlite");
    const firstStore = new SqliteAtomicTokenBucketStore(filename);
    const secondStore = new SqliteAtomicTokenBucketStore(filename);
    try {
      // These values model two Node processes whose `performance.now()`
      // origins are unrelated. A refill needs over eleven days of shared
      // elapsed time, so a normal test run cannot accidentally satisfy it.
      const policies = { principalOperation: { envelope_count: { capacity: 1, refillPerMs: 0.000_001 } } };
      const first = new HierarchicalRateLimiter({ policies, store: firstStore, clock: () => 1 });
      const second = new HierarchicalRateLimiter({ policies, store: secondStore, clock: () => 9_000_000_000 });
      const context = { meshId: "mesh-shared-clock", principalId: "principal-shared-clock" };

      expect(first.consume(context, "envelope_count").allowed).toBe(true);
      expect(second.consume(context, "envelope_count")).toMatchObject({
        allowed: false,
        code: "RATE_LIMITED",
      });
    } finally {
      firstStore.close();
      secondStore.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("fails closed without throwing when its atomic coordinator fails", () => {
    const unavailableStore: AtomicTokenBucketStore = {
      distributed: true,
      consume: () => {
        throw new Error("coordinator unavailable");
      },
    };
    const limiter = new HierarchicalRateLimiter({
      store: unavailableStore,
      clock: () => 0,
      policies: { principalOperation: { envelope_count: { capacity: 1, refillPerMs: 0 } } },
    });
    const context = { meshId: "mesh-unavailable", principalId: "principal-unavailable" };

    expect(() => limiter.consume(context, "envelope_count")).toThrow("coordinator unavailable");
    expect(limiter.consumeFailClosed(context, "envelope_count")).toEqual({
      allowed: false,
      code: "RATE_LIMIT_UNAVAILABLE",
      retry_after_ms: null,
      bucketKeys: [],
    });
    expect(limiter.admitFailClosed(context, [{ operation: "envelope_count", cost: 1 }])).toMatchObject({
      allowed: false,
      code: "RATE_LIMIT_UNAVAILABLE",
    });
  });
});

describe("compression negotiation policy", () => {
  const local = {
    algorithms: ["none", "zstd"] as const,
    limits: { maxCompressedBytes: 1_000, maxUncompressedBytes: 4_000, maxExpansionRatio: 8 },
  };
  const remote = {
    algorithms: ["none", "zstd"] as const,
    limits: { maxCompressedBytes: 700, maxUncompressedBytes: 2_000, maxExpansionRatio: 4 },
  };

  it("only negotiates zstd after READY and uses the strictest bounds", () => {
    expect(negotiateCompression(local, remote, { ready: false })).toEqual({
      ok: false,
      code: "COMPRESSION_NEGOTIATION_BEFORE_READY",
    });
    expect(negotiateCompression(local, remote, { ready: true })).toEqual({
      ok: true,
      value: {
        algorithm: "zstd",
        limits: { maxCompressedBytes: 700, maxUncompressedBytes: 2_000, maxExpansionRatio: 4 },
      },
    });
  });

  it("rejects compressed auth/receipt records and expansion bombs", () => {
    const negotiated = negotiateCompression(local, remote, { ready: true });
    if (!negotiated.ok) throw new Error("expected zstd negotiation");

    expect(validateCompressionFrame(negotiated.value, {
      algorithm: "zstd",
      recordType: "auth",
      compressedBytes: 10,
      uncompressedBytes: 10,
    })).toEqual({ ok: false, code: "COMPRESSION_FORBIDDEN_RECORD" });
    expect(validateCompressionFrame(negotiated.value, {
      algorithm: "zstd",
      recordType: "delivery.receipt",
      compressedBytes: 10,
      uncompressedBytes: 10,
    })).toEqual({ ok: false, code: "COMPRESSION_FORBIDDEN_RECORD" });
    expect(validateCompressionFrame(negotiated.value, {
      algorithm: "zstd",
      recordType: "task.submit",
      compressedBytes: 10,
      uncompressedBytes: 41,
    })).toEqual({ ok: false, code: "COMPRESSION_EXPANSION_LIMIT" });
  });

  it("generates separate compressed and uncompressed byte charges", () => {
    expect(compressionRateLimitCharges({
      algorithm: "zstd",
      recordType: "task.submit",
      compressedBytes: 12,
      uncompressedBytes: 96,
    })).toEqual([
      { operation: "compressed_bytes", cost: 12 },
      { operation: "uncompressed_bytes", cost: 96 },
    ]);
  });

  it("rejects codec output that differs from a safe declared size", () => {
    const negotiated = negotiateCompression(local, remote, { ready: true });
    if (!negotiated.ok) throw new Error("expected zstd negotiation");
    const frame = {
      algorithm: "zstd" as const,
      recordType: "task.submit",
      compressedBytes: 20,
      uncompressedBytes: 80,
    };

    expect(validateDecompressedOutput(negotiated.value, frame, 80)).toEqual({ ok: true, uncompressedBytes: 80 });
    expect(validateDecompressedOutput(negotiated.value, frame, 79)).toEqual({
      ok: false,
      code: "COMPRESSION_OUTPUT_SIZE_MISMATCH",
    });
  });

  it("requires a closed record vocabulary and binds metadata to decoded records", () => {
    const negotiated = negotiateCompression(local, remote, { ready: true });
    if (!negotiated.ok) throw new Error("expected zstd negotiation");
    const frame = {
      algorithm: "zstd" as const,
      recordType: "task.submit",
      compressedBytes: 20,
      uncompressedBytes: 80,
    };

    expect(isCompressionRecordType("task.submit")).toBe(true);
    expect(isCompressionRecordType("auth ")).toBe(false);
    expect(validateCompressionFrame(negotiated.value, {
      ...frame,
      recordType: "auth ",
    })).toEqual({ ok: false, code: "COMPRESSION_METADATA_INVALID" });
    expect(validateCompressionRecordBinding(frame, { type: "auth" })).toEqual({
      ok: false,
      code: "COMPRESSION_RECORD_TYPE_MISMATCH",
    });
    expect(validateCompressionRecordBinding(frame, { type: "task.submit" })).toEqual({
      ok: true,
      recordType: "task.submit",
    });
    expect(validateCompressionRecordBinding({ ...frame, recordType: "auth" }, { type: "auth" })).toEqual({
      ok: false,
      code: "COMPRESSION_FORBIDDEN_RECORD",
    });
    expect(() => compressionRateLimitCharges({ ...frame, recordType: "unknown.record" })).toThrow("metadata is invalid");
  });
});
