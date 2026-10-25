import { execFileSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { request } from 'node:https'
import { connect } from 'node:net'
import { once } from 'node:events'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import AuthGateway from '../src/index.js'
import AuthAwareWebServer, { type Config } from '../src/webserver.js'

const contexts: Context[] = []
const roots: string[] = []
afterEach(async () => {
  await Promise.all(contexts.splice(0).map(context => context.fiber.dispose()))
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })))
})

async function start(config: Partial<Config>) {
  const context = new Context()
  contexts.push(context)
  await context.plugin(AuthGateway, {
    databasePath: ':memory:', bootstrapToken: 'tls-test-bootstrap', scryptCost: 1024,
    bootstrapTtlMs: 60_000, sessionIdleTtlMs: 60_000, sessionAbsoluteTtlMs: 120_000,
  })
  await context.plugin(AuthAwareWebServer, { host: '127.0.0.1', port: 0, cookieSecure: 'auto', trustedHosts: [], ...config })
  return context
}

describe('listener transport', () => {
  it('issues usable HTTP cookies on wildcard listeners with explicitly trusted remote authorities', async () => {
    const context = await start({ host: '0.0.0.0', trustedHosts: ['harness.internal'] })
    const response = await fetch(`${context.webServer.getOrigin()}/auth/v1/bootstrap/status`)
    expect(response.status).toBe(200)
    expect(response.headers.get('set-cookie')).toContain('dsh_pre_csrf_dev=')
    expect(response.headers.get('set-cookie')).not.toContain('Secure')
    expect(context.webServer.protocol).toBe('http:')
  })

  it('serves native TLS with Secure cookies and closes incomplete handshakes on disposal', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ds-auth-tls-'))
    roots.push(root)
    const certFile = join(root, 'cert.pem')
    const keyFile = join(root, 'key.pem')
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' })
    const context = await start({ tls: { certFile, keyFile } })
    expect(context.webServer.protocol).toBe('https:')
    const headers = await new Promise<import('node:http').IncomingHttpHeaders>((resolve, reject) => {
      const req = request(`${context.webServer.getOrigin()}/auth/v1/bootstrap/status`, { rejectUnauthorized: false }, response => {
        expect(response.statusCode).toBe(200)
        response.resume()
        response.on('end', () => resolve(response.headers))
      })
      req.on('error', reject)
      req.end()
    })
    expect(headers['set-cookie']?.[0]).toContain('__Host-dsh_pre_csrf=')
    expect(headers['set-cookie']?.[0]).toContain('; Secure')
    const stalled = connect(context.webServer.port, '127.0.0.1')
    await once(stalled, 'connect')
    // Closing a TLS socket before ClientHello may produce a reset on macOS.
    stalled.on('error', error => { expect((error as NodeJS.ErrnoException).code).toBe('ECONNRESET') })
    const closed = new Promise<void>(resolve => { stalled.once('close', () => resolve()) })
    await context.fiber.dispose()
    await closed
  })
})
