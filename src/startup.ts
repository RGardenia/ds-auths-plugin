import { isIP } from 'node:net'
import { Command } from 'commander'
import type { Context } from '@deepseek-ai/cordis'
import { parseCmdline } from '@deepseek-ai/dsh-cmdline'
import { assertTrustedAuthority } from './request-trust.js'

export const name = 'auth-web-startup'
export const inject = ['cmdlineArgs']

/** Validate a listener address without resolving an untrusted hostname. */
export function validateHost(host: string): string {
  if (isIP(host) === 0 || host.includes('%')) throw new Error('host must be an IPv4 or IPv6 literal without a zone id')
  return host.includes(':') ? new URL(`http://[${host}]`).hostname.slice(1, -1) : host
}

/** Parse the Web flags while allowing wildcard listeners behind the authentication gateway. */
export function apply(ctx: Context): void {
  const program = new Command()
    .name('dsh web')
    .description('Serve DeepSeek Harness behind ds-auths-plugin authentication.')
    .option('--host <host>', 'IPv4 or IPv6 bind address, including 0.0.0.0 and ::')
    .option('--port <port>', 'listen port (0 selects an available port)')
    .option('--no-open', 'do not open the browser')
    .option('--trusted-host <authority...>', 'additional host or host:port authorities; authentication remains required')
    .option('--public-url <url>', 'public HTTP(S) origin (root deployment only)')
    .option('--tls-cert <file>', 'PEM certificate chain; requires --tls-key')
    .option('--tls-key <file>', 'PEM private key; requires --tls-cert')
  program.action(() => {
    const options = program.opts<{
      host?: string; port?: string; open: boolean; trustedHost?: string[]
      publicUrl?: string; tlsCert?: string; tlsKey?: string
    }>()
    try {
      const host = validateHost(process.env.DSH_AUTH_HOST ?? options.host ?? '127.0.0.1')
      const portText = process.env.DSH_AUTH_PORT ?? options.port ?? '3080'
      if (!/^\d+$/.test(portText) || Number(portText) > 65535) throw new Error('port must be an integer between 0 and 65535')
      if ((options.tlsCert === undefined) !== (options.tlsKey === undefined)) throw new Error('--tls-cert and --tls-key must be supplied together')
      if (options.publicUrl !== undefined) {
        const url = new URL(options.publicUrl)
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
          throw new Error('--public-url must be an HTTP(S) root URL without credentials, query or fragment')
        }
      }
      const trustedHosts = [...options.trustedHost ?? [], ...(process.env.DSH_AUTH_TRUSTED_HOSTS ?? '').split(',').map(value => value.trim()).filter(Boolean)]
      // A concrete bind address is a served authority. Wildcard listeners still
      // need explicit LAN/proxy authorities, protecting against DNS rebinding.
      if (host !== '0.0.0.0' && host !== '::') trustedHosts.push(host.includes(':') ? `[${host}]` : host)
      for (const authority of trustedHosts) assertTrustedAuthority(authority)
      ctx.provide('webStartup', {
        host, port: Number(portText), openBrowser: options.open, trustedHosts: [...new Set(trustedHosts)],
        ...(options.publicUrl === undefined ? {} : { publicUrl: options.publicUrl }),
        ...(options.tlsCert === undefined ? {} : { tls: { certFile: options.tlsCert, keyFile: options.tlsKey } }),
      })
    } catch (error) {
      program.error(error instanceof Error ? error.message : String(error))
    }
  })
  parseCmdline(ctx, program)
}
