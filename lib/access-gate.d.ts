import type { IncomingMessage } from 'node:http';
import type { Principal } from './auth-service.js';
export interface SessionAuthenticator {
    authenticate(token: string): Promise<Principal | null>;
}
export interface AccessGateOptions {
    sessionCookieName: string;
    isTrustedOrigin?: (request: IncomingMessage) => boolean;
}
export type AccessDecision = {
    kind: 'public';
} | {
    kind: 'redirect';
    location: string;
} | {
    kind: 'deny';
    status: 401 | 403;
    code: 'AUTH_REQUIRED' | 'AUTH_ORIGIN_REJECTED';
} | {
    kind: 'allow';
    principal: Principal;
    token: string;
};
export declare class AccessGate {
    private readonly authenticator;
    private readonly options;
    constructor(authenticator: SessionAuthenticator, options: AccessGateOptions);
    evaluateHttp(request: IncomingMessage): Promise<AccessDecision>;
    evaluateUpgrade(request: IncomingMessage): Promise<AccessDecision>;
    authenticateRequest(request: IncomingMessage): Promise<{
        principal: Principal;
        token: string;
    } | null>;
    private originAllowed;
    private readPrincipal;
}
export declare function readUniqueCookie(request: IncomingMessage, name: string): string | null;
//# sourceMappingURL=access-gate.d.ts.map