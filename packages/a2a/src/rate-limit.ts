/**
 * Token-bucket rate limiting for the inbound JSON-RPC surface (§E.1.2).
 *
 * M2 is outbound-only; the bucket is implemented but not yet bound to a
 * server, which arrives with the inbound handler in M3.
 */
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
    this.capacity = Math.max(1, options.capacity);
    this.refillPerSec = Math.max(0, options.refillPerSec);
    this.now = options.now ?? Date.now;
    this.tokens = this.capacity;
    this.lastRefillMs = this.now();
  }

  get available(): number {
    this.refill();
    return this.tokens;
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
}

/** Barrel-facing name for the inbound limiter (§E.1.2). */
export { KeyedRateLimiter as RateLimit };

export function createRateLimit(options: TokenBucketOptions): KeyedRateLimiter {
  return new KeyedRateLimiter(options);
}
