import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { Context, Service } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { AuthGateway } from './index.js';
import { type IndexInjection } from './index-injections.js';
import { type WebResource } from './web-resource.js';
declare module '@deepseek-ai/cordis' {
    interface Context {
        authGateway: AuthGateway;
        webServer: AuthAwareWebServer;
    }
    interface Events {
        'webserver/index-inject'(table: IndexInjection[], peer?: object): void;
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
export interface WebResourceRoute {
    kind: WebRouteKind;
    path: string;
    resource: WebResource;
}
export interface Config {
    host: string;
    port: number;
    tls?: {
        certFile: string;
        keyFile: string;
    };
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
    private readonly tlsSockets;
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
    get protocol(): 'http:' | 'https:';
    getOrigin(): string;
    register(route: WebRoute | WebResourceRoute): () => void;
    registerUpgrade(route: WebUpgradeRoute): () => void;
    registerFallback(handler: WebRoute['handler'] | Pick<WebResourceRoute, 'resource'>): () => void;
    tapIndex(transform: (html: string) => string): () => void;
    applyIndexTaps(html: string): string;
    collectIndexInjections(peer?: object): IndexInjection[];
    renderIndex(html: string, peer?: object): string;
    /** In-process callers admit their own Peer; HTTP always passes the session gate. */
    readResource(request: Request, peer: object): Promise<Response>;
    protected [Service.init](): Promise<void>;
    private handle;
    private bridgeAuthentication;
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