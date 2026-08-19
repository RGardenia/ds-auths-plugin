export interface FailureRateLimitPolicy {
  windowMs: number
  account: BucketPolicy
  source: BucketPolicy
  pair: BucketPolicy
  baseDelayMs: number
  maxDelayMs: number
  maxBuckets: number
}

export interface BucketPolicy {
  freeAttempts: number
  hardLimit: number
}

export interface LoginAttemptKey {
  account: string
  source: string
}

export type RateLimitDecision = { allowed: true } | { allowed: false; retryAfterMs: number }

interface Bucket {
  failures: number[]
  blockedUntil: number
  lastSeenAt: number
}

export class FailureRateLimiter {
  private readonly buckets = new Map<string, Bucket>()

  constructor(
    private readonly policy: FailureRateLimitPolicy,
    private readonly now: () => number = Date.now,
  ) {
    assertPolicy(policy)
  }

  check(key: LoginAttemptKey): RateLimitDecision {
    const now = this.now()
    const candidates = this.keys(key)
      .map(([bucketKey, policy]) => ({ bucketKey, policy, bucket: this.readBucket(bucketKey, now) }))
    const retryAfterMs = candidates.reduce((maximum, candidate) => (
      candidate.bucket === undefined ? maximum : Math.max(maximum, candidate.bucket.blockedUntil - now)
    ), 0)
    return retryAfterMs > 0 ? { allowed: false, retryAfterMs } : { allowed: true }
  }

  recordFailure(key: LoginAttemptKey): void {
    const now = this.now()
    for (const [bucketKey, policy] of this.keys(key)) {
      const bucket = this.readBucket(bucketKey, now) ?? { failures: [], blockedUntil: 0, lastSeenAt: now }
      bucket.failures.push(now)
      bucket.lastSeenAt = now
      const failures = bucket.failures.length
      if (failures >= policy.freeAttempts) {
        const exponent = Math.max(0, failures - policy.freeAttempts)
        const delay = Math.min(this.policy.maxDelayMs, this.policy.baseDelayMs * (2 ** exponent))
        bucket.blockedUntil = Math.max(bucket.blockedUntil, now + delay)
      }
      if (failures >= policy.hardLimit) bucket.blockedUntil = Math.max(bucket.blockedUntil, now + this.policy.maxDelayMs)
      this.buckets.delete(bucketKey)
      this.buckets.set(bucketKey, bucket)
    }
    this.prune(now)
  }

  recordSuccess(key: LoginAttemptKey): void {
    this.buckets.delete(`account:${key.account}`)
    this.buckets.delete(`pair:${key.account}\u0000${key.source}`)
  }

  private keys(key: LoginAttemptKey): [string, BucketPolicy][] {
    return [
      [`account:${key.account}`, this.policy.account],
      [`source:${key.source}`, this.policy.source],
      [`pair:${key.account}\u0000${key.source}`, this.policy.pair],
    ]
  }

  private readBucket(key: string, now: number): Bucket | undefined {
    const bucket = this.buckets.get(key)
    if (bucket === undefined) return undefined
    bucket.failures = bucket.failures.filter(timestamp => now - timestamp <= this.policy.windowMs)
    if (bucket.failures.length === 0 && bucket.blockedUntil <= now) {
      this.buckets.delete(key)
      return undefined
    }
    return bucket
  }

  private prune(now: number): void {
    for (const key of this.buckets.keys()) this.readBucket(key, now)
    while (this.buckets.size > this.policy.maxBuckets) {
      const oldest = this.buckets.keys().next().value as string | undefined
      if (oldest === undefined) break
      this.buckets.delete(oldest)
    }
  }
}

function assertPolicy(policy: FailureRateLimitPolicy): void {
  for (const [name, value] of Object.entries({
    windowMs: policy.windowMs,
    baseDelayMs: policy.baseDelayMs,
    maxDelayMs: policy.maxDelayMs,
    maxBuckets: policy.maxBuckets,
  })) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive safe integer`)
  }
  for (const [name, value] of Object.entries({ account: policy.account, source: policy.source, pair: policy.pair })) {
    if (!Number.isSafeInteger(value.freeAttempts) || value.freeAttempts < 1) throw new Error(`${name}.freeAttempts must be positive`)
    if (!Number.isSafeInteger(value.hardLimit) || value.hardLimit < value.freeAttempts) throw new Error(`${name}.hardLimit must be at least freeAttempts`)
  }
}
