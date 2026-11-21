export interface RateLimiterOptions {
  maxFailures: number;
  windowMs: number;
  lockoutMs: number;
}

interface Bucket {
  failures: number[];
  lockedUntil: number;
}

export class IpRateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly opts: RateLimiterOptions) {}

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
    return { allowed: true, retryAfterSec: 0 };
  }

  recordFailure(ip: string, now = Date.now()): { locked: boolean; retryAfterSec: number } {
    const bucket = this.buckets.get(ip) ?? { failures: [], lockedUntil: 0 };
    const cutoff = now - this.opts.windowMs;
    bucket.failures = bucket.failures.filter((ts) => ts > cutoff);
    bucket.failures.push(now);

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
