import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { AuthService } from '../src/auth-service.js'
import { ScryptPasswordHasher } from '../src/password-hasher.js'

const hasher = new ScryptPasswordHasher({ cost: 1024, blockSize: 8, parallelization: 1, keyLength: 32 })
const roots: string[] = []

async function createFixture(options: { now?: () => number; databasePath?: string } = {}) {
  const service = await AuthService.open({
    databasePath: options.databasePath ?? ':memory:',
    bootstrapToken: 'bootstrap-secret-with-enough-entropy',
    bootstrapTtlMs: 60_000,
    sessionIdleTtlMs: 10_000,
    sessionAbsoluteTtlMs: 30_000,
    passwordHasher: hasher,
    ...(options.now === undefined ? {} : { now: options.now }),
  })
  return service
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })))
})

describe('AuthService', () => {
  it('stays locked until the one-time bootstrap creates the first administrator', async () => {
    const service = await createFixture()
    expect(service.getStatus()).toEqual({ state: 'uninitialized_locked' })

    const session = await service.bootstrap({
      bootstrapToken: 'bootstrap-secret-with-enough-entropy',
      username: 'Admin',
      displayName: 'Harness Owner',
      password: 'correct horse battery staple',
    })

    expect(service.getStatus()).toEqual({ state: 'ready' })
    expect(session.principal).toMatchObject({ username: 'admin', displayName: 'Harness Owner', roles: ['super_admin'] })
    expect(session.token).toHaveLength(43)
    expect(session.csrfToken).toHaveLength(43)
    await expect(service.authenticate(session.token)).resolves.toMatchObject({ username: 'admin' })
    await expect(service.bootstrap({
      bootstrapToken: 'bootstrap-secret-with-enough-entropy',
      username: 'other',
      displayName: 'Other',
      password: 'another sufficiently long password',
    })).rejects.toMatchObject({ code: 'AUTH_ALREADY_INITIALIZED' })
    service.close()
  })

  it('returns the same public failure for unknown users and wrong passwords', async () => {
    const service = await createFixture()
    await service.bootstrap({
      bootstrapToken: 'bootstrap-secret-with-enough-entropy',
      username: 'admin',
      displayName: 'Admin',
      password: 'correct horse battery staple',
    })

    const unknown = expect(service.login({ username: 'missing', password: 'not the right password' }))
      .rejects.toEqual(expect.objectContaining({ code: 'AUTH_INVALID_CREDENTIALS' }))
    const wrong = expect(service.login({ username: 'admin', password: 'not the right password' }))
      .rejects.toEqual(expect.objectContaining({ code: 'AUTH_INVALID_CREDENTIALS' }))

    await Promise.all([unknown, wrong])
    service.close()
  })

  it('persists revocable opaque sessions and enforces idle expiry', async () => {
    let now = 1_000_000
    const root = await mkdtemp(join(tmpdir(), 'dsh-auth-service-'))
    roots.push(root)
    const databasePath = join(root, 'auth.db')
    const service = await createFixture({ databasePath, now: () => now })
    await service.bootstrap({
      bootstrapToken: 'bootstrap-secret-with-enough-entropy',
      username: 'admin',
      displayName: 'Admin',
      password: 'correct horse battery staple',
    })
    const loggedIn = await service.login({ username: 'ADMIN', password: 'correct horse battery staple' })
    service.close()

    const reopened = await createFixture({ databasePath, now: () => now })
    await expect(reopened.authenticate(loggedIn.token)).resolves.toMatchObject({ username: 'admin' })

    now += 10_001
    await expect(reopened.authenticate(loggedIn.token)).resolves.toBeNull()

    const replacement = await reopened.login({ username: 'admin', password: 'correct horse battery staple' })
    await reopened.logout(replacement.token)
    await expect(reopened.authenticate(replacement.token)).resolves.toBeNull()
    reopened.close()
  })

  it('rejects weak bootstrap input without consuming the bootstrap token', async () => {
    const service = await createFixture()
    await expect(service.bootstrap({
      bootstrapToken: 'bootstrap-secret-with-enough-entropy',
      username: 'a',
      displayName: '',
      password: 'short',
    })).rejects.toMatchObject({ code: 'AUTH_INVALID_INPUT' })

    await expect(service.bootstrap({
      bootstrapToken: 'bootstrap-secret-with-enough-entropy',
      username: 'owner',
      displayName: 'Owner',
      password: 'a password that is finally long enough',
    })).resolves.toMatchObject({ principal: { username: 'owner' } })
    service.close()
  })

  it('allows only one winner when bootstrap requests race', async () => {
    const service = await createFixture()
    const results = await Promise.allSettled([
      service.bootstrap({
        bootstrapToken: 'bootstrap-secret-with-enough-entropy',
        username: 'first',
        displayName: 'First Owner',
        password: 'a sufficiently long first password',
      }),
      service.bootstrap({
        bootstrapToken: 'bootstrap-secret-with-enough-entropy',
        username: 'second',
        displayName: 'Second Owner',
        password: 'a sufficiently long second password',
      }),
    ])

    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1)
    expect(results.filter(result => result.status === 'rejected')).toHaveLength(1)
    expect(service.getStatus()).toEqual({ state: 'ready' })
    service.close()
  })
})
