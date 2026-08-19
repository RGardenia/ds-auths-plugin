import { AsyncLocalStorage } from 'node:async_hooks'
import type { Principal } from './auth-service.js'

class PrincipalContext {
  private readonly storage = new AsyncLocalStorage<Principal>()

  run<T>(principal: Principal, operation: () => T): T {
    return this.storage.run(principal, operation)
  }

  current(): Principal | undefined {
    return this.storage.getStore()
  }

  require(): Principal {
    const principal = this.current()
    if (principal === undefined) throw new Error('authenticated principal context is unavailable')
    return principal
  }
}

export const principalContext = new PrincipalContext()
