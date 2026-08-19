import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import AuthGateway from '../src/index.js'
import AuthAwareWebServer from '../src/webserver.js'

const contexts: Context[] = []
const roots: string[] = []

afterEach(async () => {
  await Promise.allSettled(contexts.splice(0).map(context => context.fiber.dispose()))
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })))
})

describe('authentication HTTP surface', () => {
  it('boots locked, initializes once, then admits the authenticated Harness request', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-auth-http-'))
    roots.push(root)
    const context = new Context()
    contexts.push(context)
    await context.plugin(AuthGateway, {
      databasePath: join(root, 'auth.db'),
      bootstrapToken: 'integration-bootstrap-secret',
      bootstrapTtlMs: 60_000,
      sessionIdleTtlMs: 60_000,
      sessionAbsoluteTtlMs: 120_000,
      scryptCost: 1024,
    })
    await context.plugin(AuthAwareWebServer, {
      host: '127.0.0.1',
      port: 0,
      cookieSecure: 'development',
      trustedHosts: [],
    })
    context.webServer.registerFallback((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end('HARNESS PRIVATE SHELL')
    })

    const origin = `http://127.0.0.1:${String(context.webServer.port)}`
    const status = await fetch(`${origin}/auth/v1/bootstrap/status`)
    const statusBody = await status.json() as { state: string; csrfToken: string }
    expect(status.status).toBe(200)
    expect(statusBody.state).toBe('uninitialized_locked')
    expect(statusBody.csrfToken).toHaveLength(43)
    const preAuthCookie = status.headers.getSetCookie().map(value => value.split(';', 1)[0]).join('; ')

    const navigation = await fetch(`${origin}/workspace/demo`, {
      headers: { accept: 'text/html' },
      redirect: 'manual',
    })
    expect(navigation.status).toBe(302)
    expect(navigation.headers.get('location')).toBe('/auth/login?returnTo=%2Fworkspace%2Fdemo')

    const anonymousLoginPage = await fetch(`${origin}/auth/login`, { headers: { accept: 'text/html' } })
    expect(anonymousLoginPage.status).toBe(200)
    expect(await anonymousLoginPage.text()).toContain('安全访问')

    const denied = await fetch(`${origin}/api`, { method: 'POST' })
    expect(denied.status).toBe(401)
    await expect(denied.json()).resolves.toMatchObject({ ok: false, error: { code: 'AUTH_REQUIRED' } })

    const initialized = await fetch(`${origin}/auth/v1/bootstrap/complete`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: preAuthCookie,
        origin,
        'sec-fetch-site': 'same-origin',
        'x-dsh-csrf': statusBody.csrfToken,
      },
      body: JSON.stringify({
        bootstrapToken: 'integration-bootstrap-secret',
        username: 'admin',
        displayName: 'Harness Owner',
        password: 'correct horse battery staple',
      }),
    })
    expect(initialized.status).toBe(201)
    await expect(initialized.json()).resolves.toMatchObject({ ok: true, principal: { username: 'admin' } })
    const sessionCookies = initialized.headers.getSetCookie().map(value => value.split(';', 1)[0]).join('; ')
    expect(sessionCookies).toContain('dsh_auth_dev=')
    expect(sessionCookies).toContain('dsh_csrf_dev=')

    const admitted = await fetch(`${origin}/workspace/demo`, {
      headers: { cookie: sessionCookies, accept: 'text/html' },
    })
    expect(admitted.status).toBe(200)
    expect(await admitted.text()).toBe('HARNESS PRIVATE SHELL')

    const loginRedirect = await fetch(`${origin}/auth/login?returnTo=%2Fworkspace%2Fdemo`, {
      headers: { cookie: sessionCookies, accept: 'text/html' },
      redirect: 'manual',
    })
    expect(loginRedirect.status).toBe(302)
    expect(loginRedirect.headers.get('location')).toBe('/workspace/demo')

    const loginRedirectDefault = await fetch(`${origin}/auth/login`, {
      headers: { cookie: sessionCookies, accept: 'text/html' },
      redirect: 'manual',
    })
    expect(loginRedirectDefault.status).toBe(302)
    expect(loginRedirectDefault.headers.get('location')).toBe('/')

    const loginRedirectUnsafe = await fetch(`${origin}/auth/login?returnTo=${encodeURIComponent('https://evil.example/phish')}`, {
      headers: { cookie: sessionCookies, accept: 'text/html' },
      redirect: 'manual',
    })
    expect(loginRedirectUnsafe.status).toBe(302)
    expect(loginRedirectUnsafe.headers.get('location')).toBe('/')

    const loginRedirectSelf = await fetch(`${origin}/auth/login?returnTo=%2Fauth%2Flogin`, {
      headers: { cookie: sessionCookies, accept: 'text/html' },
      redirect: 'manual',
    })
    expect(loginRedirectSelf.status).toBe(302)
    expect(loginRedirectSelf.headers.get('location')).toBe('/')

    const unknownAuthRoute = await fetch(`${origin}/auth/not-a-real-route`, {
      headers: { cookie: sessionCookies, accept: 'application/json' },
    })
    expect(unknownAuthRoute.status).toBe(404)
    await expect(unknownAuthRoute.json()).resolves.toMatchObject({ error: { code: 'NOT_FOUND' } })
  })

  it('rejects cross-origin bootstrap requests before consuming the token', async () => {
    const context = new Context()
    contexts.push(context)
    await context.plugin(AuthGateway, {
      databasePath: ':memory:',
      bootstrapToken: 'integration-bootstrap-secret',
      bootstrapTtlMs: 60_000,
      sessionIdleTtlMs: 60_000,
      sessionAbsoluteTtlMs: 120_000,
      scryptCost: 1024,
    })
    await context.plugin(AuthAwareWebServer, {
      host: '127.0.0.1',
      port: 0,
      cookieSecure: 'development',
      trustedHosts: [],
    })
    const origin = `http://127.0.0.1:${String(context.webServer.port)}`
    const status = await fetch(`${origin}/auth/v1/bootstrap/status`)
    const body = await status.json() as { csrfToken: string }
    const cookie = status.headers.getSetCookie().map(value => value.split(';', 1)[0]).join('; ')

    const response = await fetch(`${origin}/auth/v1/bootstrap/complete`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie,
        origin: 'https://evil.example',
        'sec-fetch-site': 'cross-site',
        'x-dsh-csrf': body.csrfToken,
      },
      body: JSON.stringify({
        bootstrapToken: 'integration-bootstrap-secret',
        username: 'admin',
        displayName: 'Admin',
        password: 'correct horse battery staple',
      }),
    })
    expect(response.status).toBe(403)
    expect(context.authGateway.getStatus()).toEqual({ state: 'uninitialized_locked' })
  })
})
