import type { IncomingMessage } from 'node:http'
import { describe, expect, it, vi } from 'vitest'
import { bridgeBrowserAuthentication, type BrowserConnection } from '../src/browser-bridge.js'

describe('native browser authentication bridge', () => {
  it('exchanges only through public APIs and replaces native credentials on the request', () => {
    const authorizeIndex: BrowserConnection['authorizeIndex'] = (request, response) => {
      expect(request.headers.host).toBe('harness.example')
      expect(request.url).toBe('http://dsh.invalid/?token=host-only')
      response.writeHead(303, { 'set-cookie': 'dsh-auth-native=signed; Path=/; HttpOnly' })
      response.end()
      return false
    }
    const request = { url: '/?token=old&workspace=one', headers: { host: 'harness.example', cookie: 'dsh_auth_dev=ours; dsh-auth-old=stale; other=value' } } as IncomingMessage
    bridgeBrowserAuthentication({ authenticatedUrl: url => `${url}?token=host-only`, authorizeIndex }, request)
    expect(request.headers.cookie).toBe('dsh_auth_dev=ours;  other=value; dsh-auth-native=signed')
    expect(request.url).toBe('/?workspace=one')
    const combo = '/plugins/??@deepseek-ai/dsh-client-modules/client.js&rev=abc'
    request.url = combo
    bridgeBrowserAuthentication({ authenticatedUrl: url => `${url}?token=host-only`, authorizeIndex }, request)
    expect(request.url).toBe(combo)
  })

  it('fails closed when upstream no longer honors the token exchange', () => {
    expect(() => bridgeBrowserAuthentication({ authenticatedUrl: url => url, authorizeIndex: vi.fn(() => false) }, { headers: {} } as IncomingMessage)).toThrow(/exchange failed/)
  })
})
