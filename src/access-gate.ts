import type { IncomingMessage } from 'node:http'
import type { Principal } from './auth-service.js'

export interface SessionAuthenticator {
  authenticate(token: string): Promise<Principal | null>
}

export interface AccessGateOptions {
  sessionCookieName: string
  isTrustedOrigin?: (request: IncomingMessage) => boolean
}

export type AccessDecision =
  | { kind: 'public' }
  | { kind: 'redirect'; location: string }
  | { kind: 'deny'; status: 401 | 403; code: 'AUTH_REQUIRED' | 'AUTH_ORIGIN_REJECTED' }
  | { kind: 'allow'; principal: Principal; token: string }

const PUBLIC_ROUTES = new Set([
  '/auth/login',
  '/auth/v1/bootstrap/status',
  '/auth/v1/bootstrap/complete',
  '/auth/v1/login',
  '/auth/v1/health/live',
])

export class AccessGate {
  constructor(
    private readonly authenticator: SessionAuthenticator,
    private readonly options: AccessGateOptions,
  ) {}

  async evaluateHttp(request: IncomingMessage): Promise<AccessDecision> {
    const pathname = readPathname(request)
    if (PUBLIC_ROUTES.has(pathname)) return { kind: 'public' }
    const authenticated = await this.readPrincipal(request)
    if (authenticated === null) {
      if (isNavigation(request)) {
        const returnTo = `${pathname}${readSearch(request)}`
        return { kind: 'redirect', location: `/auth/login?returnTo=${encodeURIComponent(returnTo)}` }
      }
      return { kind: 'deny', status: 401, code: 'AUTH_REQUIRED' }
    }
    if (isStateChanging(request) && !this.originAllowed(request)) {
      return { kind: 'deny', status: 403, code: 'AUTH_ORIGIN_REJECTED' }
    }
    return { kind: 'allow', ...authenticated }
  }

  async evaluateUpgrade(request: IncomingMessage): Promise<AccessDecision> {
    const authenticated = await this.readPrincipal(request)
    if (authenticated === null) return { kind: 'deny', status: 401, code: 'AUTH_REQUIRED' }
    if (!this.originAllowed(request)) return { kind: 'deny', status: 403, code: 'AUTH_ORIGIN_REJECTED' }
    return { kind: 'allow', ...authenticated }
  }

  async authenticateRequest(request: IncomingMessage): Promise<{ principal: Principal; token: string } | null> {
    return this.readPrincipal(request)
  }

  private originAllowed(request: IncomingMessage): boolean {
    return this.options.isTrustedOrigin?.(request) ?? isSameOrigin(request, true)
  }

  private async readPrincipal(request: IncomingMessage): Promise<{ principal: Principal; token: string } | null> {
    const token = readUniqueCookie(request, this.options.sessionCookieName)
    if (token === null) return null
    const principal = await this.authenticator.authenticate(token)
    return principal === null ? null : { principal, token }
  }
}

export function readUniqueCookie(request: IncomingMessage, name: string): string | null {
  const raw = request.headers.cookie
  if (raw === undefined || raw.length > 8192) return null
  const values: string[] = []
  for (const part of raw.split(';')) {
    const separator = part.indexOf('=')
    if (separator < 0) continue
    if (part.slice(0, separator).trim() !== name) continue
    const value = part.slice(separator + 1).trim()
    if (value.length < 1 || value.length > 256) return null
    values.push(value)
  }
  return values.length === 1 ? values[0] ?? null : null
}

function readPathname(request: IncomingMessage): string {
  return new URL(request.url ?? '/', 'http://dsh.local').pathname
}

function readSearch(request: IncomingMessage): string {
  return new URL(request.url ?? '/', 'http://dsh.local').search
}

function isNavigation(request: IncomingMessage): boolean {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false
  const destination = request.headers['sec-fetch-dest']
  if (destination === 'document') return true
  return (request.headers.accept ?? '').split(',').some(value => value.trim().startsWith('text/html'))
}

function isStateChanging(request: IncomingMessage): boolean {
  return request.method !== 'GET' && request.method !== 'HEAD' && request.method !== 'OPTIONS'
}

function isSameOrigin(request: IncomingMessage, originRequired = false): boolean {
  const site = request.headers['sec-fetch-site']
  if (site === 'cross-site') return false
  const origin = request.headers.origin
  if (origin === undefined) return !originRequired
  const host = request.headers.host
  if (host === undefined) return false
  try {
    const parsed = new URL(origin)
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.host === host
  } catch {
    return false
  }
}
