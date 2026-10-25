import type { IncomingMessage } from 'node:http'

/** The public Connection methods shared by Harness 0.2.1 and current master. */
export interface BrowserConnection {
  authenticatedUrl(baseUrl: string): string
  authorizeIndex(request: { url: string; method: string; headers: IncomingMessage['headers'] }, response: {
    writeHead(status: number, headers?: Record<string, string>): void
    end(body?: string): void
  }): boolean
}

/**
 * Exchange the host's launch token only after our revocable session is admitted.
 * The native cookie stays on this server-side request; it is never issued to
 * the browser or accepted as a replacement for the gateway session.
 */
export function bridgeBrowserAuthentication(connection: BrowserConnection, request: IncomingMessage): void {
  let nativeCookie: string | undefined
  connection.authorizeIndex({
    method: 'GET',
    url: connection.authenticatedUrl('http://dsh.invalid/'),
    headers: request.headers,
  }, {
    writeHead(status, headers) {
      if (status === 303) nativeCookie = headers?.['set-cookie']?.split(';', 1)[0]
    },
    end() {},
  })
  if (nativeCookie === undefined || !nativeCookie.startsWith('dsh-auth-')) {
    throw new Error('ds-auths-plugin: Harness browser authentication exchange failed')
  }
  const existing = (request.headers.cookie ?? '').split(';')
    .filter(value => value.trim() !== '' && !value.trim().startsWith('dsh-auth-'))
  request.headers.cookie = [...existing, nativeCookie].join('; ')
  // A launch URL must not make upstream issue a native cookie or redirect again.
  const url = new URL(request.url ?? '/', 'http://dsh.invalid')
  if ((url.pathname === '/' || url.pathname === '/index.html') && url.searchParams.has('token')) {
    url.searchParams.delete('token')
    request.url = `${url.pathname}${url.search}`
  }
}
