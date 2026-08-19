export interface PasswordHasher {
    hash(password: string): Promise<string>;
    verify(password: string, encoded: string): Promise<boolean>;
    needsRehash(encoded: string): boolean;
}
export interface ScryptParameters {
    cost: number;
    blockSize: number;
    parallelization: number;
    keyLength: number;
}
export declare class ScryptPasswordHasher implements PasswordHasher {
    readonly parameters: ScryptParameters;
    constructor(parameters?: Partial<ScryptParameters>);
    hash(password: string): Promise<string>;
    verify(password: string, encoded: string): Promise<boolean>;
    needsRehash(encoded: string): boolean;
}
//# sourceMappingURL=password-hasher.d.ts.map