import type { IncomingHttpHeaders, IncomingMessage } from 'node:http'
import { describe, expect, it, vi } from 'vitest'
import { AccessGate } from '../src/access-gate.js'
import type { Principal } from '../src/auth-service.js'

const principal: Principal = {
  userId: 'user-1',
  sessionId: 'session-1',
  username: 'admin',
  displayName: 'Admin',
  roles: ['super_admin'],
  permissions: new Set(['*']),
  authVersion: 1,
  policyVersion: 1,
}

function request(url: string, headers: IncomingHttpHeaders = {}, method = 'GET'): IncomingMessage {
  return { url, method, headers } as IncomingMessage
}

describe('AccessGate', () => {
  it('keeps only explicit auth routes public and distinguishes navigation from API denial', async () => {
    const authenticate = vi.fn(async (token: string) => token === 'valid-token' ? principal : null)
    const gate = new AccessGate({ authenticate }, { sessionCookieName: 'dsh_auth_dev' })

    await expect(gate.evaluateHttp(request('/auth/v1/bootstrap/status'))).resolves.toEqual({ kind: 'public' })
    await expect(gate.evaluateHttp(request('/workspace/demo', { accept: 'text/html' }))).resolves.toEqual({
      kind: 'redirect',
      location: '/auth/login?returnTo=%2Fworkspace%2Fdemo',
    })
    await expect(gate.evaluateHttp(request('/api/session.list', { accept: 'application/json' }, 'POST'))).resolves.toEqual({
      kind: 'deny',
      status: 401,
      code: 'AUTH_REQUIRED',
    })
    await expect(gate.evaluateHttp(request('/api/session.list', {
      cookie: 'dsh_auth_dev=valid-token',
      host: 'harness.example',
      origin: 'https://evil.example',
      'sec-fetch-site': 'cross-site',
    }, 'POST'))).resolves.toEqual({ kind: 'deny', status: 403, code: 'AUTH_ORIGIN_REJECTED' })
    await expect(gate.evaluateHttp(request('/api/session.list', {
      cookie: 'dsh_auth_dev=valid-token',
      host: 'harness.example',
    }, 'POST'))).resolves.toEqual({ kind: 'deny', status: 403, code: 'AUTH_ORIGIN_REJECTED' })
    await expect(gate.evaluateHttp(request('/api/session.list', {
      cookie: 'dsh_auth_dev=valid-token',
      host: 'harness.example',
      origin: 'https://harness.example',
      'sec-fetch-site': 'same-origin',
    }, 'POST'))).resolves.toMatchObject({ kind: 'allow', principal })
  })

  it('rejects duplicate session cookies and requires an authenticated same-origin WebSocket handshake', async () => {
    const authenticate = vi.fn(async (token: string) => token === 'valid-token' ? principal : null)
    const gate = new AccessGate({ authenticate }, { sessionCookieName: 'dsh_auth_dev' })

    await expect(gate.evaluateUpgrade(request('/api/events.mux', {
      cookie: 'dsh_auth_dev=valid-token; dsh_auth_dev=shadow',
      host: 'harness.example',
      origin: 'https://harness.example',
    }))).resolves.toEqual({ kind: 'deny', status: 401, code: 'AUTH_REQUIRED' })
    await expect(gate.evaluateUpgrade(request('/api/events.mux', {
      cookie: 'dsh_auth_dev=valid-token',
      host: 'harness.example',
      origin: 'https://harness.example',
    }))).resolves.toMatchObject({ kind: 'allow', principal })
    await expect(gate.evaluateUpgrade(request('/api/events.mux', {
      cookie: 'dsh_auth_dev=valid-token',
      host: 'harness.example',
    }))).resolves.toEqual({ kind: 'deny', status: 403, code: 'AUTH_ORIGIN_REJECTED' })
  })
})
