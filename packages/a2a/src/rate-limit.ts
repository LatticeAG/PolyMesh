/**
 * Hierarchical inbound token-bucket rate limiting (§A.16.1).
 *
 * Buckets (capacity / refill-per-sec):
 *   - connection/IP: 60 / 1.0
 *   - principal: 30 / 0.5
 *   - capability × principal: 10 / 0.167
 */

export const IP_CAPACITY = 60;
export const IP_REFILL_PER_SEC = 1;
export const PRINCIPAL_CAPACITY = 30;
export const PRINCIPAL_REFILL_PER_SEC = 0.5;
export const CAPABILITY_CAPACITY = 10;
export const CAPABILITY_REFILL_PER_SEC = 0.167;

export interface TokenBucketOptions {
  capacity: number;
  refillPerSec: number;
  now?: () => number;
}

export class TokenBucket {
  private tokens: number;
  private lastRefillMs: number;
  private readonly now: () => number;
  readonly capacity: number;
  readonly refillPerSec: number;

  constructor(options: TokenBucketOptions) {
    this.capacity = Math.max(0, options.capacity);
    this.refillPerSec = Math.max(0, options.refillPerSec);
    this.now = options.now ?? Date.now;
    this.tokens = this.capacity;
    this.lastRefillMs = this.now();
  }

  get available(): number {
    this.refill();
    return this.tokens;
  }

  has(count = 1): boolean {
    this.refill();
    return this.tokens >= count;
  }

  tryConsume(count = 1): boolean {
    this.refill();
    if (this.tokens < count) return false;
    this.tokens -= count;
    return true;
  }

  private refill(): void {
    const nowMs = this.now();
    const elapsed = Math.max(0, nowMs - this.lastRefillMs);
    if (elapsed === 0) return;
    this.lastRefillMs = nowMs;
    this.tokens = Math.min(this.capacity, this.tokens + (elapsed / 1000) * this.refillPerSec);
  }
}

export interface RateLimiter {
  allow(key: string): boolean;
}

/** Per-principal token buckets keyed by mesh-local trust principal. */
export class KeyedRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, TokenBucket>();

  constructor(private readonly options: TokenBucketOptions) {}

  allow(key: string): boolean {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = new TokenBucket(this.options);
      this.buckets.set(key, bucket);
    }
    return bucket.tryConsume(1);
  }

  tokens(key: string): number {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = new TokenBucket(this.options);
      this.buckets.set(key, bucket);
    }
    return bucket.available;
  }

  has(key: string, count = 1): boolean {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = new TokenBucket(this.options);
      this.buckets.set(key, bucket);
    }
    return bucket.has(count);
  }
}

export interface HierarchicalRateLimitOptions {
  enabled?: boolean;
  now?: () => number;
  ipCapacity?: number;
  ipRefillPerSec?: number;
  principalCapacity?: number;
  principalRefillPerSec?: number;
  capabilityCapacity?: number;
  capabilityRefillPerSec?: number;
}

export interface HierarchicalAllowArgs {
  ip: string;
  principal: string;
  capability?: string;
  cost?: number;
}

/**
 * §A.16.1 hierarchical limiter. Every applicable bucket must admit the request.
 */
export class HierarchicalRateLimiter {
  readonly enabled: boolean;
  readonly ip: KeyedRateLimiter;
  readonly principal: KeyedRateLimiter;
  readonly capability: KeyedRateLimiter;

  constructor(options: HierarchicalRateLimitOptions = {}) {
    const now = options.now;
    this.enabled = options.enabled ?? true;
    this.ip = new KeyedRateLimiter({
      capacity: options.ipCapacity ?? IP_CAPACITY,
      refillPerSec: options.ipRefillPerSec ?? IP_REFILL_PER_SEC,
      now,
    });
    this.principal = new KeyedRateLimiter({
      capacity: options.principalCapacity ?? PRINCIPAL_CAPACITY,
      refillPerSec: options.principalRefillPerSec ?? PRINCIPAL_REFILL_PER_SEC,
      now,
    });
    this.capability = new KeyedRateLimiter({
      capacity: options.capabilityCapacity ?? CAPABILITY_CAPACITY,
      refillPerSec: options.capabilityRefillPerSec ?? CAPABILITY_REFILL_PER_SEC,
      now,
    });
  }

  allow(args: HierarchicalAllowArgs): boolean {
    if (!this.enabled) return true;
    const cost = args.cost ?? 1;
    const capKey = args.capability ? `${args.principal}|${args.capability}` : null;
    if (!this.ip.has(args.ip, cost)) return false;
    if (!this.principal.has(args.principal, cost)) return false;
    if (capKey && !this.capability.has(capKey, cost)) return false;
    this.ip.allow(args.ip);
    this.principal.allow(args.principal);
    if (capKey) this.capability.allow(capKey);
    // KeyedRateLimiter.allow always consumes 1; re-consume for cost > 1 if needed.
    for (let i = 1; i < cost; i++) {
      this.ip.allow(args.ip);
      this.principal.allow(args.principal);
      if (capKey) this.capability.allow(capKey);
    }
    return true;
  }
}

/** Barrel-facing name for the inbound limiter (§E.1.2). */
export { HierarchicalRateLimiter as RateLimit };

export function createRateLimit(
  options?: TokenBucketOptions | HierarchicalRateLimitOptions,
): KeyedRateLimiter | HierarchicalRateLimiter {
  if (options && "capacity" in options && typeof options.capacity === "number") {
    return new KeyedRateLimiter(options);
  }
  return new HierarchicalRateLimiter(options as HierarchicalRateLimitOptions | undefined);
}
