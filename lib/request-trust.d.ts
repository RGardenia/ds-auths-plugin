import type { IncomingHttpHeaders } from 'node:http';
interface TrustRequest {
    headers: IncomingHttpHeaders | Headers;
}
export declare function assertTrustedAuthority(entry: string): void;
export declare function isTrustedRequest(request: TrustRequest, trustedHosts: readonly string[]): boolean;
export declare function hasTrustedOrigin(request: TrustRequest, trustedHosts: readonly string[]): boolean;
export {};
//# sourceMappingURL=request-trust.d.ts.map