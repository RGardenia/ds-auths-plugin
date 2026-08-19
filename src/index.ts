import { Service } from '@deepseek-ai/cordis'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import {
  AuthService,
  type AuthServiceOptions,
  type AuthSession,
  type BootstrapInput,
  type LoginInput,
  type Principal,
} from './auth-service.js'
import { ScryptPasswordHasher } from './password-hasher.js'

export interface Config {
  databasePath: string
  bootstrapToken: string
  bootstrapTtlMs: number
  sessionIdleTtlMs: number
  sessionAbsoluteTtlMs: number
  scryptCost: number
}

export class AuthGateway extends Service {
  static Config: z<Config> = z.object({
    databasePath: z.string().default('auth.db'),
    bootstrapToken: z.string().default(''),
    bootstrapTtlMs: z.natural().min(60_000).default(900_000),
    sessionIdleTtlMs: z.natural().min(60_000).default(28_800_000),
    sessionAbsoluteTtlMs: z.natural().min(60_000).default(86_400_000),
    scryptCost: z.natural().min(1024).max(1_048_576).default(32_768),
  })

  private service: AuthService | undefined
  private readonly revocationListeners = new Set<(sessionId: string) => void>()

  constructor(ctx: Context, private readonly config: Config) {
    super(ctx, 'authGateway')
  }

  protected async [Service.init](): Promise<void> {
    const options: AuthServiceOptions = {
      databasePath: this.config.databasePath,
      bootstrapTtlMs: this.config.bootstrapTtlMs,
      sessionIdleTtlMs: this.config.sessionIdleTtlMs,
      sessionAbsoluteTtlMs: this.config.sessionAbsoluteTtlMs,
      passwordHasher: new ScryptPasswordHasher({ cost: this.config.scryptCost }),
      ...(this.config.bootstrapToken.length === 0 ? {} : { bootstrapToken: this.config.bootstrapToken }),
    }
    const service = await AuthService.open(options)
    this.service = service
    if (service.issuedBootstrapToken !== undefined) {
      console.warn(
        `ds-auths-plugin is locked. Complete bootstrap with this one-time token: ${service.issuedBootstrapToken}`,
      )
    }
    this.ctx.effect(() => () => {
      service.close()
      this.service = undefined
    }, 'authGateway.database')
  }

  getStatus(): ReturnType<AuthService['getStatus']> {
    return this.requireService().getStatus()
  }

  bootstrap(input: BootstrapInput): Promise<AuthSession> {
    return this.requireService().bootstrap(input)
  }

  login(input: LoginInput): Promise<AuthSession> {
    return this.requireService().login(input)
  }

  authenticate(token: string): Promise<Principal | null> {
    return this.requireService().authenticate(token)
  }

  verifyCsrf(token: string, csrfToken: string): boolean {
    return this.requireService().verifyCsrf(token, csrfToken)
  }

  async logout(token: string): Promise<void> {
    const principal = await this.requireService().authenticate(token)
    await this.requireService().logout(token)
    if (principal !== null) {
      for (const listener of this.revocationListeners) listener(principal.sessionId)
    }
  }

  onSessionRevoked(listener: (sessionId: string) => void): () => void {
    this.revocationListeners.add(listener)
    return () => { this.revocationListeners.delete(listener) }
  }

  private requireService(): AuthService {
    if (this.service === undefined) throw new Error('authGateway is not ready')
    return this.service
  }
}

export type { AuthSession, BootstrapInput, LoginInput, Principal }
export { AuthFailure } from './auth-service.js'
export { ScryptPasswordHasher, type PasswordHasher } from './password-hasher.js'
export default AuthGateway
