import { Context } from '@deepseek-ai/cordis'
import { provideCmdline } from '@deepseek-ai/dsh-cmdline'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { apply, validateHost } from '../src/startup.js'

afterEach(() => { vi.unstubAllEnvs() })

function parse(args: string[]) {
  const context = new Context()
  const exit = vi.fn()
  provideCmdline(context, { args, exit })
  apply(context)
  return { startup: context.get('webStartup'), exit }
}

describe('authenticated Web startup', () => {
  it('passes TLS, public URL, no-open and trusted authorities without dropping remote binds', () => {
    const { startup, exit } = parse(['--host', '::', '--port', '0', '--no-open', '--tls-cert', 'cert.pem', '--tls-key', 'key.pem', '--trusted-host', 'harness.example', '--public-url', 'https://harness.example/'])
    expect(exit).not.toHaveBeenCalled()
    expect(startup).toMatchObject({ host: '::', port: 0, openBrowser: false, tls: { certFile: 'cert.pem', keyFile: 'key.pem' }, publicUrl: 'https://harness.example/', trustedHosts: ['harness.example'] })
  })

  it('uses environment overrides consistently for the listener and upstream trust fence', () => {
    vi.stubEnv('DSH_AUTH_HOST', '192.168.1.20')
    vi.stubEnv('DSH_AUTH_PORT', '8443')
    vi.stubEnv('DSH_AUTH_TRUSTED_HOSTS', 'proxy.example')
    expect(parse(['--host', '127.0.0.1']).startup).toMatchObject({ host: '192.168.1.20', port: 8443, trustedHosts: ['proxy.example', '192.168.1.20'] })
  })

  it.each([
    ['--host', 'example.com'], ['--port', '65536'], ['--port', '-1'],
    ['--tls-cert', 'cert.pem'], ['--tls-key', 'key.pem'],
    ['--public-url', 'https://example.com/prefix/'], ['--trusted-host', 'user@example.com'],
  ])('rejects invalid startup arguments %j before providing a service', (...args) => {
    const { startup, exit } = parse(args)
    expect(startup).toBeUndefined()
    expect(exit).toHaveBeenCalledWith(1)
  })

  it('normalizes IPv6 and rejects zone IDs', () => {
    expect(validateHost('0:0:0:0:0:0:0:1')).toBe('::1')
    expect(() => validateHost('fe80::1%en0')).toThrow()
  })
})
