import { describe, expect, it } from 'vitest'
import { FailureRateLimiter } from '../src/rate-limiter.js'

const policy = {
  windowMs: 60_000,
  account: { freeAttempts: 4, hardLimit: 6 },
  source: { freeAttempts: 5, hardLimit: 8 },
  pair: { freeAttempts: 3, hardLimit: 5 },
  baseDelayMs: 1_000,
  maxDelayMs: 30_000,
  maxBuckets: 100,
}

describe('FailureRateLimiter', () => {
  it('applies exponential delay to the account-source pair without globally blocking other users', () => {
    let now = 10_000
    const limiter = new FailureRateLimiter(policy, () => now)
    const attempt = { account: 'admin', source: '127.0.0.1' }

    expect(limiter.check(attempt)).toEqual({ allowed: true })
    limiter.recordFailure(attempt)
    limiter.recordFailure(attempt)
    expect(limiter.check(attempt)).toEqual({ allowed: true })
    limiter.recordFailure(attempt)
    expect(limiter.check(attempt)).toEqual({ allowed: false, retryAfterMs: 1_000 })
    expect(limiter.check({ account: 'other', source: '127.0.0.2' })).toEqual({ allowed: true })

    now += 1_001
    expect(limiter.check(attempt)).toEqual({ allowed: true })
    limiter.recordFailure(attempt)
    expect(limiter.check(attempt)).toEqual({ allowed: false, retryAfterMs: 2_000 })
  })

  it('limits distributed account attacks and password spraying by source', () => {
    let now = 20_000
    const limiter = new FailureRateLimiter(policy, () => now)
    for (let index = 0; index < 4; index += 1) {
      limiter.recordFailure({ account: 'victim', source: `10.0.0.${String(index)}` })
    }
    expect(limiter.check({ account: 'victim', source: '10.0.1.1' })).toEqual({ allowed: false, retryAfterMs: 1_000 })

    now += 1_001
    const source = '192.0.2.10'
    for (let index = 0; index < 5; index += 1) {
      limiter.recordFailure({ account: `user-${String(index)}`, source })
    }
    expect(limiter.check({ account: 'new-target', source })).toEqual({ allowed: false, retryAfterMs: 1_000 })
  })

  it('clears account and pair penalties after a valid login and expires old windows', () => {
    let now = 30_000
    const limiter = new FailureRateLimiter(policy, () => now)
    const attempt = { account: 'admin', source: '127.0.0.1' }
    for (let index = 0; index < 3; index += 1) limiter.recordFailure(attempt)
    expect(limiter.check(attempt).allowed).toBe(false)

    limiter.recordSuccess(attempt)
    expect(limiter.check(attempt)).toEqual({ allowed: true })

    for (let index = 0; index < 3; index += 1) limiter.recordFailure(attempt)
    now += 60_001
    expect(limiter.check(attempt)).toEqual({ allowed: true })
  })
})
