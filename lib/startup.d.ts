import type { Context } from '@deepseek-ai/cordis';
export declare const name = "auth-web-startup";
export declare const inject: string[];
/** Validate a listener address without resolving an untrusted hostname. */
export declare function validateHost(host: string): string;
/** Parse the Web flags while allowing wildcard listeners behind the authentication gateway. */
export declare function apply(ctx: Context): void;
//# sourceMappingURL=startup.d.ts.map