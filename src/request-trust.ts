import type { IncomingHttpHeaders } from 'node:http'

interface TrustRequest {
  headers: IncomingHttpHeaders | Headers
}

export function assertTrustedAuthority(entry: string): void {
  const parsed = parseAuthority(entry)
  if (parsed !== undefined && canonicalAuthority(entry, parsed) === entry.toLowerCase()) return
  throw new Error(`ds-auths-plugin: trustedHosts entry ${JSON.stringify(entry)} is not a bare host[:port] authority`)
}

export function isTrustedRequest(request: TrustRequest, trustedHosts: readonly string[]): boolean {
  const host = header(request.headers, 'host')
  if (host === undefined) return false
  const hostUrl = parseAuthority(host)
  if (hostUrl === undefined) return false
  if (!isLoopbackHostname(hostUrl.hostname) && !matchesTrustedAuthority(hostUrl, trustedHosts)) return false
  if (header(request.headers, 'sec-fetch-site') === 'cross-site') return false
  const origin = header(request.headers, 'origin')
  if (origin === undefined) return true
  const originUrl = parseOrigin(origin)
  return originUrl !== undefined
    && (originUrl.host === hostUrl.host || matchesTrustedAuthority(originUrl, trustedHosts))
}

export function hasTrustedOrigin(request: TrustRequest, trustedHosts: readonly string[]): boolean {
  if (header(request.headers, 'sec-fetch-site') === 'cross-site') return false
  const host = header(request.headers, 'host')
  const origin = header(request.headers, 'origin')
  if (host === undefined || origin === undefined) return false
  const hostUrl = parseAuthority(host)
  const originUrl = parseOrigin(origin)
  if (hostUrl === undefined || originUrl === undefined) return false
  return originUrl.host === hostUrl.host || matchesTrustedAuthority(originUrl, trustedHosts)
}

function parseOrigin(origin: string): URL | undefined {
  try {
    const parsed = new URL(origin)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed : undefined
  } catch {
    return undefined
  }
}

function header(headers: IncomingHttpHeaders | Headers, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const value = headers[name]
  return typeof value === 'string' ? value : undefined
}

function parseAuthority(authority: string): URL | undefined {
  try {
    return new URL(`http://${authority}`)
  } catch {
    return undefined
  }
}

function canonicalAuthority(entry: string, parsed: URL): string {
  const port = parsed.port !== '' ? parsed.port : new URL(`https://${entry}`).port
  return port === '' ? parsed.hostname : `${parsed.hostname}:${port}`
}

function matchesTrustedAuthority(host: URL, trustedHosts: readonly string[]): boolean {
  return trustedHosts.some((entry) => {
    const parsed = parseAuthority(entry)
    if (parsed === undefined) return false
    return canonicalAuthority(entry, parsed) === parsed.hostname
      ? parsed.hostname === host.hostname
      : parsed.host === host.host
  })
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '[::1]') return true
  const parts = hostname.split('.')
  return parts.length === 4
    && parts[0] === '127'
    && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}
