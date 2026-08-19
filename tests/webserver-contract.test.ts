import { once } from 'node:events'
import { connect } from 'node:net'
import type { Socket } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import AuthGateway from '../src/index.js'
import AuthAwareWebServer from '../src/webserver.js'

const contexts: Context[] = []

interface Fixture {
  context: Context
  origin: string
  cookie: string
}

afterEach(async () => {
  await Promise.allSettled(contexts.splice(0).map(context => context.fiber.dispose()))
})

async function fixture(): Promise<Fixture> {
  const context = new Context()
  contexts.push(context)
  await context.plugin(AuthGateway, {
    databasePath: ':memory:',
    bootstrapToken: 'contract-bootstrap-token',
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
  const session = await context.authGateway.bootstrap({
    bootstrapToken: 'contract-bootstrap-token',
    username: 'admin',
    displayName: 'Admin',
    password: 'correct horse battery staple',
  })
  return {
    context,
    origin: `http://127.0.0.1:${String(context.webServer.port)}`,
    cookie: `dsh_auth_dev=${session.token}; dsh_csrf_dev=${session.csrfToken}`,
  }
}

describe('AuthAwareWebServer official contract', () => {
  it('preserves exact, longest-prefix, fallback, index-tap and disposer semantics behind auth', async () => {
    const { context, origin, cookie } = await fixture()
    const server = context.webServer
    server.register({ kind: 'exact', path: '/probe', handler: (_request, response) => { response.end('EXACT') } })
    server.register({ kind: 'prefix', path: '/api', handler: (_request, response) => { response.end('API') } })
    server.register({ kind: 'prefix', path: '/api/deep', handler: (_request, response) => { response.end('DEEP') } })
    server.register({ kind: 'prefix', path: '', handler: (_request, response) => { response.end('EMPTY') } })

    const get = async (path: string, init: RequestInit = {}) => {
      const response = await fetch(`${origin}${path}`, { ...init, headers: { cookie, ...init.headers } })
      return { status: response.status, body: await response.text() }
    }
    await expect(get('/probe')).resolves.toMatchObject({ status: 200, body: 'EXACT' })
    await expect(get('/api/item')).resolves.toMatchObject({ status: 200, body: 'API' })
    await expect(get('/api/deep/item')).resolves.toMatchObject({ status: 200, body: 'DEEP' })
    await expect(get('/unclaimed')).resolves.toMatchObject({ status: 200, body: 'EMPTY' })

    expect(() => server.register({ kind: 'exact', path: '/probe', handler: () => {} })).toThrow(/duplicate exact route/)
    expect(() => server.register({ kind: 'exact', path: '/auth/shadow', handler: () => {} })).toThrow(/reserved authentication route/)
    const release = server.register({ kind: 'exact', path: '/once', handler: (_request, response) => { response.end('ONCE') } })
    await expect(get('/once')).resolves.toMatchObject({ body: 'ONCE' })
    release()
    await expect(get('/once')).resolves.toMatchObject({ body: 'EMPTY' })

    const releaseEmpty = server.registerFallback((_request, response) => {
      response.end(server.applyIndexTaps('<head></head><body>fallback</body>'))
    })
    expect(() => server.registerFallback(() => {})).toThrow(/fallback already registered/)
    const untap = server.tapIndex(html => html.replace('<head>', '<head><meta name="probe">'))
    expect(server.applyIndexTaps('<head></head>')).toContain('name="probe"')
    untap()
    expect(server.applyIndexTaps('<head></head>')).not.toContain('name="probe"')
    releaseEmpty()
  })

  it('authenticates upgrade before route disclosure and closes session sockets on logout', async () => {
    const { context, cookie } = await fixture()
    let serverObservedClose = false
    context.webServer.registerUpgrade({
      path: '/events',
      handler: (_request, socket) => {
        socket.once('close', () => { serverObservedClose = true })
        socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: dsh-test\r\n\r\n')
      },
    })
    const unauthenticated = await rawUpgrade(context.webServer.port, '/private-unknown', '')
    expect(unauthenticated.response).toContain('401 Unauthorized')
    unauthenticated.socket.destroy()

    const accepted = await rawUpgrade(context.webServer.port, '/events', cookie)
    expect(accepted.response).toContain('101 Switching Protocols')
    const sessionToken = /dsh_auth_dev=([^;]+)/.exec(cookie)?.[1]
    expect(sessionToken).toBeDefined()
    await context.authGateway.logout(sessionToken ?? '')
    await once(accepted.socket, 'close')
    expect(serverObservedClose).toBe(true)
  })
})

async function rawUpgrade(port: number, path: string, cookie: string): Promise<{ socket: Socket; response: string }> {
  const socket = connect(port, '127.0.0.1')
  await once(socket, 'connect')
  const response = once(socket, 'data')
  socket.write([
    `GET ${path} HTTP/1.1`,
    `Host: 127.0.0.1:${String(port)}`,
    `Origin: http://127.0.0.1:${String(port)}`,
    'Connection: Upgrade',
    'Upgrade: dsh-test',
    ...(cookie.length === 0 ? [] : [`Cookie: ${cookie}`]),
    '',
    '',
  ].join('\r\n'))
  const [data] = await response as [Buffer]
  return { socket, response: String(data) }
}
