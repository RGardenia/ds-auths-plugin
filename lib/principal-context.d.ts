import type { Principal } from './auth-service.js';
declare class PrincipalContext {
    private readonly storage;
    run<T>(principal: Principal, operation: () => T): T;
    current(): Principal | undefined;
    require(): Principal;
}
export declare const principalContext: PrincipalContext;
export {};
//# sourceMappingURL=principal-context.d.ts.map