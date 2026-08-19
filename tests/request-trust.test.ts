import { describe, expect, it } from 'vitest'
import { assertTrustedAuthority, hasTrustedOrigin, isTrustedRequest } from '../src/request-trust.js'

function request(headers: Record<string, string | undefined>) {
  return { headers }
}

describe('request trust fence', () => {
  it('accepts loopback and declared authorities while rejecting rebound hosts', () => {
    expect(isTrustedRequest(request({ host: '127.0.0.1:3080' }), [])).toBe(true)
    expect(isTrustedRequest(request({ host: '127.9.2.1:3080', origin: 'http://127.9.2.1:3080' }), [])).toBe(true)
    expect(isTrustedRequest(request({ host: 'harness.internal:3080', origin: 'http://harness.internal:3080' }), ['harness.internal'])).toBe(true)
    expect(isTrustedRequest(request({ host: 'evil.example:3080', origin: 'http://evil.example:3080' }), [])).toBe(false)
    expect(isTrustedRequest(request({ host: '127.0.0.1:3080', origin: 'https://evil.example' }), [])).toBe(false)
    expect(isTrustedRequest(request({ host: '127.0.0.1:3080', 'sec-fetch-site': 'cross-site' }), [])).toBe(false)
  })

  it('allows an explicit external-origin to internal-host proxy mapping without trusting arbitrary origins', () => {
    const trusted = ['25.1.83.16:34753', 'harness.preview.example']
    const proxied = request({
      host: '25.1.83.16:34753',
      origin: 'https://harness.preview.example',
      'sec-fetch-site': 'same-origin',
    })
    expect(isTrustedRequest(proxied, trusted)).toBe(true)
    expect(hasTrustedOrigin(proxied, trusted)).toBe(true)
    expect(isTrustedRequest(request({
      host: '25.1.83.16:34753',
      origin: 'https://evil.example',
      'sec-fetch-site': 'same-origin',
    }), trusted)).toBe(false)
    expect(hasTrustedOrigin(request({ host: '25.1.83.16:34753' }), trusted)).toBe(false)
  })

  it('rejects malformed configured authorities instead of broadening trust', () => {
    for (const value of ['harness.internal', 'harness.internal:3080', '10.0.0.8', '[::1]:3080']) {
      expect(() => { assertTrustedAuthority(value) }).not.toThrow()
    }
    for (const value of ['harness.internal/path', 'user@harness.internal', ' harness.internal', 'harness.internal:0080', '']) {
      expect(() => { assertTrustedAuthority(value) }).toThrow(/bare host\[:port\] authority/)
    }
  })
})
