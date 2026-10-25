import type { IncomingMessage } from 'node:http';
/** The public Connection methods shared by Harness 0.2.1 and current master. */
export interface BrowserConnection {
    authenticatedUrl(baseUrl: string): string;
    authorizeIndex(request: {
        url: string;
        method: string;
        headers: IncomingMessage['headers'];
    }, response: {
        writeHead(status: number, headers?: Record<string, string>): void;
        end(body?: string): void;
    }): boolean;
}
/**
 * Exchange the host's launch token only after our revocable session is admitted.
 * The native cookie stays on this server-side request; it is never issued to
 * the browser or accepted as a replacement for the gateway session.
 */
export declare function bridgeBrowserAuthentication(connection: BrowserConnection, request: IncomingMessage): void;
//# sourceMappingURL=browser-bridge.d.ts.map