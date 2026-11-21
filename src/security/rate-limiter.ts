export interface RateLimiterOptions {
  maxFailures: number;
  windowMs: number;
  lockoutMs: number;
  maxTrackedIps?: number;
}

interface Bucket {
  failures: number[];
  lockedUntil: number;
  lastSeen: number;
}

export class IpRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly maxTrackedIps: number;

  constructor(private readonly opts: RateLimiterOptions) {
    this.maxTrackedIps = opts.maxTrackedIps ?? 10_000;
  }

  private prune(now: number): void {
    if (this.buckets.size < this.maxTrackedIps) return;
    const staleCutoff = now - Math.max(this.opts.windowMs, this.opts.lockoutMs);
    for (const [ip, bucket] of this.buckets) {
      if (bucket.lockedUntil <= now && bucket.lastSeen < staleCutoff) {
        this.buckets.delete(ip);
      }
    }
    while (this.buckets.size >= this.maxTrackedIps) {
      const oldestKey = this.buckets.keys().next().value;
      if (!oldestKey) break;
      this.buckets.delete(oldestKey);
    }
  }

  check(ip: string, now = Date.now()): { allowed: boolean; retryAfterSec: number } {
    const bucket = this.buckets.get(ip);
    if (!bucket) {
      return { allowed: true, retryAfterSec: 0 };
    }
    if (bucket.lockedUntil > now) {
      return {
        allowed: false,
        retryAfterSec: Math.max(1, Math.ceil((bucket.lockedUntil - now) / 1000)),
      };
    }
    const staleCutoff = now - Math.max(this.opts.windowMs, this.opts.lockoutMs);
    if (bucket.lastSeen < staleCutoff) {
      this.buckets.delete(ip);
    }
    return { allowed: true, retryAfterSec: 0 };
  }

  recordFailure(ip: string, now = Date.now()): { locked: boolean; retryAfterSec: number } {
    this.prune(now);
    const bucket = this.buckets.get(ip) ?? { failures: [], lockedUntil: 0, lastSeen: now };
    const cutoff = now - this.opts.windowMs;
    bucket.failures = bucket.failures.filter((ts) => ts > cutoff);
    bucket.failures.push(now);
    bucket.lastSeen = now;

    if (bucket.failures.length >= this.opts.maxFailures) {
      bucket.lockedUntil = now + this.opts.lockoutMs;
      bucket.failures = [];
      this.buckets.set(ip, bucket);
      return {
        locked: true,
        retryAfterSec: Math.max(1, Math.ceil(this.opts.lockoutMs / 1000)),
      };
    }

    this.buckets.set(ip, bucket);
    return { locked: false, retryAfterSec: 0 };
  }

  recordSuccess(ip: string): void {
    this.buckets.delete(ip);
  }
}
