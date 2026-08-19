import type { PasswordHasher } from './password-hasher.js';
export type AuthState = 'uninitialized_locked' | 'ready';
export interface Principal {
    userId: string;
    sessionId: string;
    username: string;
    displayName: string;
    roles: readonly string[];
    permissions: ReadonlySet<string>;
    authVersion: number;
    policyVersion: number;
}
export interface AuthSession {
    token: string;
    csrfToken: string;
    principal: Principal;
    idleExpiresAt: number;
    absoluteExpiresAt: number;
}
export interface AuthServiceOptions {
    databasePath: string;
    bootstrapToken?: string;
    bootstrapTtlMs: number;
    sessionIdleTtlMs: number;
    sessionAbsoluteTtlMs: number;
    passwordHasher: PasswordHasher;
    now?: () => number;
}
export interface BootstrapInput {
    bootstrapToken: string;
    username: string;
    displayName: string;
    password: string;
}
export interface LoginInput {
    username: string;
    password: string;
}
export type AuthFailureCode = 'AUTH_ALREADY_INITIALIZED' | 'AUTH_BOOTSTRAP_INVALID' | 'AUTH_INVALID_CREDENTIALS' | 'AUTH_INVALID_INPUT' | 'AUTH_NOT_INITIALIZED';
export declare class AuthFailure extends Error {
    readonly code: AuthFailureCode;
    readonly status: number;
    constructor(code: AuthFailureCode);
}
export declare class AuthService {
    readonly issuedBootstrapToken: string | undefined;
    private readonly db;
    private readonly passwordHasher;
    private readonly dummyHash;
    private readonly now;
    private readonly sessionIdleTtlMs;
    private readonly sessionAbsoluteTtlMs;
    private closed;
    private constructor();
    static open(options: AuthServiceOptions): Promise<AuthService>;
    getStatus(): {
        state: AuthState;
    };
    bootstrap(input: BootstrapInput): Promise<AuthSession>;
    login(input: LoginInput): Promise<AuthSession>;
    authenticate(token: string): Promise<Principal | null>;
    verifyCsrf(token: string, csrfToken: string): boolean;
    logout(token: string): Promise<void>;
    close(): void;
    private materializeSession;
    private toPrincipal;
    private requireOpen;
}
//# sourceMappingURL=auth-service.d.ts.map