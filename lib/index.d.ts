import { Service } from '@deepseek-ai/cordis';
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { AuthService, type AuthSession, type BootstrapInput, type LoginInput, type Principal } from './auth-service.js';
export interface Config {
    databasePath: string;
    bootstrapToken: string;
    bootstrapTtlMs: number;
    sessionIdleTtlMs: number;
    sessionAbsoluteTtlMs: number;
    scryptCost: number;
}
export declare class AuthGateway extends Service {
    private readonly config;
    static Config: z<Config>;
    private service;
    private readonly revocationListeners;
    constructor(ctx: Context, config: Config);
    protected [Service.init](): Promise<void>;
    getStatus(): ReturnType<AuthService['getStatus']>;
    bootstrap(input: BootstrapInput): Promise<AuthSession>;
    login(input: LoginInput): Promise<AuthSession>;
    authenticate(token: string): Promise<Principal | null>;
    verifyCsrf(token: string, csrfToken: string): boolean;
    logout(token: string): Promise<void>;
    onSessionRevoked(listener: (sessionId: string) => void): () => void;
    private requireService;
}
export type { AuthSession, BootstrapInput, LoginInput, Principal };
export { AuthFailure } from './auth-service.js';
export { ScryptPasswordHasher, type PasswordHasher } from './password-hasher.js';
export default AuthGateway;
//# sourceMappingURL=index.d.ts.map