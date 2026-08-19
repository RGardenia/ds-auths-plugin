import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { Context, Service } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { AuthGateway } from './index.js';
declare module '@deepseek-ai/cordis' {
    interface Context {
        authGateway: AuthGateway;
        webServer: AuthAwareWebServer;
    }
}
export type WebRouteKind = 'exact' | 'prefix';
export interface WebRoute {
    kind: WebRouteKind;
    path: string;
    handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>;
}
export interface WebUpgradeRoute {
    path: string;
    handler: (request: IncomingMessage, socket: Duplex, head: Buffer) => void | Promise<void>;
}
export interface Config {
    host: '127.0.0.1' | '0.0.0.0';
    port: number;
    cookieSecure: 'auto' | 'required' | 'development';
    trustedHosts: string[];
}
export declare class AuthAwareWebServer extends Service {
    private readonly config;
    static inject: string[];
    static Config: z<Config>;
    private readonly exact;
    private readonly prefixes;
    private readonly upgrades;
    private readonly upgradedSockets;
    private readonly socketsBySession;
    private readonly indexTaps;
    private readonly cookiePolicy;
    private readonly gate;
    private readonly loginLimiter;
    private readonly bootstrapLimiter;
    private fallback;
    private server;
    private listenedPort;
    constructor(ctx: Context, config: Config);
    get port(): number;
    get host(): Config['host'];
    register(route: WebRoute): () => void;
    registerUpgrade(route: WebUpgradeRoute): () => void;
    registerFallback(handler: WebRoute['handler']): () => void;
    tapIndex(transform: (html: string) => string): () => void;
    applyIndexTaps(html: string): string;
    protected [Service.init](): Promise<void>;
    private handle;
    private handleAuthRoute;
    private requireRateLimit;
    private requirePublicWriteProtection;
    private readOrIssuePreAuthCsrf;
    private setSessionCookies;
    private clearSessionCookies;
    private handleUpgrade;
    private match;
    private sendProblem;
}
export default AuthAwareWebServer;
//# sourceMappingURL=webserver.d.ts.map