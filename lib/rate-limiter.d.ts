export interface FailureRateLimitPolicy {
    windowMs: number;
    account: BucketPolicy;
    source: BucketPolicy;
    pair: BucketPolicy;
    baseDelayMs: number;
    maxDelayMs: number;
    maxBuckets: number;
}
export interface BucketPolicy {
    freeAttempts: number;
    hardLimit: number;
}
export interface LoginAttemptKey {
    account: string;
    source: string;
}
export type RateLimitDecision = {
    allowed: true;
} | {
    allowed: false;
    retryAfterMs: number;
};
export declare class FailureRateLimiter {
    private readonly policy;
    private readonly now;
    private readonly buckets;
    constructor(policy: FailureRateLimitPolicy, now?: () => number);
    check(key: LoginAttemptKey): RateLimitDecision;
    recordFailure(key: LoginAttemptKey): void;
    recordSuccess(key: LoginAttemptKey): void;
    private keys;
    private readBucket;
    private prune;
}
//# sourceMappingURL=rate-limiter.d.ts.map