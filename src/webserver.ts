import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { createServer as createSecureServer } from 'node:https'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { isIP, type AddressInfo } from 'node:net'
import type { Duplex } from 'node:stream'
import { Context, Service } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { AccessGate, readUniqueCookie } from './access-gate.js'
import type { AuthGateway } from './index.js'
import { renderAuthPage } from './auth-page.js'
import { renderAccountPage } from './account-page.js'
import { principalContext } from './principal-context.js'
import { FailureRateLimiter, type LoginAttemptKey } from './rate-limiter.js'
import { assertTrustedAuthority, hasTrustedOrigin, isTrustedRequest } from './request-trust.js'
import { bridgeBrowserAuthentication, type BrowserConnection } from './browser-bridge.js'
import { renderIndexInjections, type IndexInjection } from './index-injections.js'
import { serveResource, type WebResource } from './web-resource.js'
import { RANDOM_UUID_POLYFILL } from './browser-compat.js'

declare module '@deepseek-ai/cordis' {
  interface Context {
    authGateway: AuthGateway
    webServer: AuthAwareWebServer
  }
  interface Events {
    'webserver/index-inject'(table: IndexInjection[], peer?: object): void
  }
}

export type WebRouteKind = 'exact' | 'prefix'

export interface WebRoute {
  kind: WebRouteKind
  path: string
  handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>
}

export interface WebUpgradeRoute {
  path: string
  handler: (request: IncomingMessage, socket: Duplex, head: Buffer) => void | Promise<void>
}

export interface WebResourceRoute {
  kind: WebRouteKind
  path: string
  resource: WebResource
}

export interface Config {
  host: string
  port: number
  tls?: { certFile: string; keyFile: string }
  cookieSecure: 'auto' | 'required' | 'development'
  trustedHosts: string[]
}

interface CookiePolicy {
  sessionName: string
  csrfName: string
  preAuthCsrfName: string
  secure: boolean
}

class HttpProblem extends Error {
  readonly retryAfterSeconds: number | undefined

  constructor(status: number, code: string, message: string, retryAfterSeconds?: number) {
    super(message)
    this.status = status
    this.code = code
    this.retryAfterSeconds = retryAfterSeconds
  }

  readonly status: number
  readonly code: string
}

const MAX_AUTH_BODY_BYTES = 64 * 1024

export class AuthAwareWebServer extends Service {
  static inject = ['authGateway']
  static Config: z<Config> = z.object({
    host: z.transform(z.string(), value => {
      if (isIP(value) === 0 || value.includes('%')) throw new Error('host must be an IPv4 or IPv6 literal without a zone id')
      return value
    }).required(),
    port: z.natural().max(65_535).required(),
    tls: z.object({ certFile: z.string().required(), keyFile: z.string().required() }).default(undefined as never),
    cookieSecure: z.union([z.const('auto'), z.const('required'), z.const('development')]).default('auto'),
    trustedHosts: z.array(z.string()).default([]),
  })

  private readonly exact = new Map<string, WebRoute | WebResourceRoute>()
  private readonly prefixes = new Map<string, WebRoute | WebResourceRoute>()
  private readonly upgrades = new Map<string, WebUpgradeRoute>()
  private readonly upgradedSockets = new Set<Duplex>()
  private readonly tlsSockets = new Set<Duplex>()
  private readonly socketsBySession = new Map<string, Set<Duplex>>()
  private readonly indexTaps: ((html: string) => string)[] = []
  private readonly cookiePolicy: CookiePolicy
  private readonly gate: AccessGate
  private readonly loginLimiter = new FailureRateLimiter({
    windowMs: 15 * 60_000,
    account: { freeAttempts: 5, hardLimit: 12 },
    source: { freeAttempts: 20, hardLimit: 60 },
    pair: { freeAttempts: 5, hardLimit: 10 },
    baseDelayMs: 1_000,
    maxDelayMs: 5 * 60_000,
    maxBuckets: 10_000,
  })
  private readonly bootstrapLimiter = new FailureRateLimiter({
    windowMs: 15 * 60_000,
    account: { freeAttempts: 3, hardLimit: 8 },
    source: { freeAttempts: 8, hardLimit: 20 },
    pair: { freeAttempts: 3, hardLimit: 6 },
    baseDelayMs: 2_000,
    maxDelayMs: 10 * 60_000,
    maxBuckets: 2_000,
  })
  private fallback: WebRoute['handler'] | Pick<WebResourceRoute, 'resource'> | undefined
  private server!: Server
  private listenedPort!: number

  constructor(ctx: Context, private readonly config: Config) {
    super(ctx, 'webServer')
    for (const authority of config.trustedHosts) assertTrustedAuthority(authority)
    this.cookiePolicy = createCookiePolicy(config)
    this.gate = new AccessGate(ctx.authGateway, {
      sessionCookieName: this.cookiePolicy.sessionName,
      isTrustedOrigin: request => hasTrustedOrigin(request, this.config.trustedHosts),
    })
  }

  get port(): number {
    return this.listenedPort
  }

  get host(): Config['host'] {
    return this.config.host
  }

  get protocol(): 'http:' | 'https:' {
    return this.config.tls == null ? 'http:' : 'https:'
  }

  getOrigin(): string {
    const host = this.host === '0.0.0.0' ? '127.0.0.1' : this.host === '::' ? '::1' : this.host
    return `${this.protocol}//${isIP(host) === 6 ? `[${host}]` : host}:${this.port}`
  }

  register(route: WebRoute | WebResourceRoute): () => void {
    assertRoutePath(route.path, route.kind === 'prefix')
    const table = route.kind === 'exact' ? this.exact : this.prefixes
    if (table.has(route.path)) throw new Error(`webserver: duplicate ${route.kind} route "${route.path}"`)
    table.set(route.path, route)
    return () => { table.delete(route.path) }
  }

  registerUpgrade(route: WebUpgradeRoute): () => void {
    assertRoutePath(route.path, false)
    if (this.upgrades.has(route.path)) throw new Error(`webserver: duplicate upgrade route "${route.path}"`)
    this.upgrades.set(route.path, route)
    return () => { this.upgrades.delete(route.path) }
  }

  registerFallback(handler: WebRoute['handler'] | Pick<WebResourceRoute, 'resource'>): () => void {
    if (this.fallback !== undefined) throw new Error('webserver: fallback already registered')
    this.fallback = handler
    return () => { this.fallback = undefined }
  }

  tapIndex(transform: (html: string) => string): () => void {
    this.indexTaps.push(transform)
    return () => {
      const index = this.indexTaps.indexOf(transform)
      if (index !== -1) this.indexTaps.splice(index, 1)
    }
  }

  applyIndexTaps(html: string): string {
    const transformed = this.indexTaps.reduce((output, transform) => transform(output), html)
    return transformed.replace('</body>', '<a href="/auth/account" aria-label="账号与安全" style="position:fixed;right:16px;bottom:16px;z-index:1000;padding:8px 12px;border-radius:8px;background:Canvas;color:CanvasText;border:1px solid GrayText;font:13px system-ui;text-decoration:none">账号与安全</a></body>')
  }

  collectIndexInjections(peer?: object): IndexInjection[] {
    const table: IndexInjection[] = [{ kind: 'script', placement: 'head', text: RANDOM_UUID_POLYFILL }]
    this.ctx.emit('webserver/index-inject', table, peer)
    return table
  }

  renderIndex(html: string, peer?: object): string {
    return this.applyIndexTaps(renderIndexInjections(html, this.collectIndexInjections(peer)))
  }

  /** In-process callers admit their own Peer; HTTP always passes the session gate. */
  async readResource(request: Request, peer: object): Promise<Response> {
    if (request.method !== 'GET' && request.method !== 'HEAD') return new Response(null, { status: 405, headers: { allow: 'GET, HEAD' } })
    const route = this.match(new URL(request.url).pathname) ?? this.fallback
    if (typeof route !== 'object' || !('resource' in route)) return new Response(null, { status: 404 })
    const response = await route.resource(request, peer)
    if (request.method !== 'HEAD') return response
    await response.body?.cancel()
    return new Response(null, { status: response.status, statusText: response.statusText, headers: response.headers })
  }

  protected async [Service.init](): Promise<void> {
    this.ctx.effect(() => this.ctx.authGateway.onSessionRevoked((sessionId) => {
      const sockets = this.socketsBySession.get(sessionId)
      if (sockets === undefined) return
      for (const socket of sockets) socket.destroy()
      this.socketsBySession.delete(sessionId)
    }), 'authAwareWebServer.sessionRevocation')
    const listener = (request: IncomingMessage, response: ServerResponse): void => {
      this.handle(request, response).catch((error: unknown) => {
        this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)))
        if (response.headersSent) {
          response.destroy()
          return
        }
        this.sendProblem(response, error)
      })
    }
    await this.ctx.effect(async () => {
      const tls = this.config.tls
      if (tls == null) {
        this.server = createServer(listener)
      } else {
        const [cert, key] = await Promise.all([readFile(tls.certFile, 'utf8'), readFile(tls.keyFile, 'utf8')])
        if (!cert.trim() || !key.trim()) throw new Error('TLS certificate and key must not be empty')
        this.server = createSecureServer({ cert, key }, listener)
        this.server.on('connection', socket => {
          this.tlsSockets.add(socket)
          socket.once('close', () => { this.tlsSockets.delete(socket) })
        })
      }
      this.server.on('upgrade', (request, socket, head) => {
        void this.handleUpgrade(request, socket, head)
      })
      await new Promise<void>((resolve, reject) => {
        this.server.once('error', reject)
        this.server.listen(this.config.port, this.config.host, () => {
          this.server.off('error', reject)
          this.server.on('error', error => { this.ctx.logger.error(error) })
          this.listenedPort = (this.server.address() as AddressInfo).port
          resolve()
        })
      })
      return async () => {
        const serverClosed = new Promise<void>((resolve) => {
          this.server.close(() => { resolve() })
        })
        this.server.closeAllConnections()
        const upgradedClosed = [...this.upgradedSockets, ...this.tlsSockets].map(socket => new Promise<void>((resolve) => {
          socket.once('close', () => { resolve() })
          socket.destroy()
        }))
        await Promise.all([serverClosed, ...upgradedClosed])
      }
    }, 'authAwareWebServer.listen')
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const requestId = randomUUID()
    response.setHeader('x-request-id', requestId)
    if (!isTrustedRequest(request, this.config.trustedHosts)) {
      sendJson(response, 403, failureBody('AUTH_AUTHORITY_REJECTED', requestId, '请求地址或来源不受信任'))
      return
    }
    const decision = await this.gate.evaluateHttp(request)
    if (decision.kind === 'redirect') {
      applySecurityHeaders(response)
      response.writeHead(302, { location: decision.location, 'cache-control': 'no-store' })
      response.end()
      return
    }
    if (decision.kind === 'deny') {
      sendJson(response, decision.status, failureBody(decision.code, requestId))
      return
    }
    if (decision.kind === 'public') {
      if (await this.handleAuthRoute(request, response, null)) return
      sendJson(response, 404, failureBody('NOT_FOUND', requestId))
      return
    }
    await principalContext.run(decision.principal, async () => {
      if (await this.handleAuthRoute(request, response, decision.token)) return
      this.bridgeAuthentication(request)
      const pathname = readPathname(request)
      if (pathname === '/auth' || pathname.startsWith('/auth/')) {
        sendJson(response, 404, failureBody('NOT_FOUND', requestId))
        return
      }
      const route = this.match(pathname)
      if (route !== undefined) {
        if ('resource' in route) await serveResource(request, response, route.resource)
        else await route.handler(request, response)
        return
      }
      if (this.fallback === undefined) {
        response.writeHead(404)
        response.end()
        return
      }
      if (typeof this.fallback === 'function') await this.fallback(request, response)
      else await serveResource(request, response, this.fallback.resource)
    })
  }

  private bridgeAuthentication(request: IncomingMessage): void {
    const connection = this.ctx.get('connection') as BrowserConnection | undefined
    if (connection !== undefined) bridgeBrowserAuthentication(connection, request)
  }

  private async handleAuthRoute(
    request: IncomingMessage,
    response: ServerResponse,
    sessionToken: string | null,
  ): Promise<boolean> {
    const pathname = readPathname(request)
    if (pathname === '/auth/account') {
      requireMethod(request, ['GET', 'HEAD'])
      const nonce = randomBytes(18).toString('base64url')
      applySecurityHeaders(response, nonce)
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      response.end(request.method === 'HEAD' ? undefined : renderAccountPage(nonce))
      return true
    }
    if (pathname === '/auth/login') {
      if (request.method !== 'GET' && request.method !== 'HEAD') throw new HttpProblem(405, 'METHOD_NOT_ALLOWED', '仅支持 GET')
      const authenticated = sessionToken !== null || (await this.gate.authenticateRequest(request)) !== null
      if (authenticated) {
        applySecurityHeaders(response)
        response.writeHead(302, { location: safeReturnTo(request), 'cache-control': 'no-store' })
        response.end()
        return true
      }
      const nonce = randomBytes(18).toString('base64')
      applySecurityHeaders(response, nonce)
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      response.end(request.method === 'HEAD' ? undefined : renderAuthPage(nonce))
      return true
    }
    if (pathname === '/auth/v1/health/live') {
      requireMethod(request, ['GET', 'HEAD'])
      sendJson(response, 200, { ok: true, status: 'live' }, request.method === 'HEAD')
      return true
    }
    if (pathname === '/auth/v1/bootstrap/status') {
      requireMethod(request, ['GET', 'HEAD'])
      const csrfToken = this.readOrIssuePreAuthCsrf(request)
      response.setHeader('set-cookie', serializeCookie(this.cookiePolicy.preAuthCsrfName, csrfToken, this.cookiePolicy, { httpOnly: true }))
      sendJson(response, 200, { ...this.ctx.authGateway.getStatus(), csrfToken }, request.method === 'HEAD')
      return true
    }
    if (pathname === '/auth/v1/bootstrap/complete') {
      requireMethod(request, ['POST'])
      this.requirePublicWriteProtection(request)
      const body = await readJsonBody(request)
      const key = authAttemptKey(request, readString(body, 'username'))
      this.requireRateLimit(this.bootstrapLimiter, key)
      try {
        const session = await this.ctx.authGateway.bootstrap({
          bootstrapToken: readString(body, 'bootstrapToken'),
          username: readString(body, 'username'),
          displayName: readString(body, 'displayName'),
          password: readString(body, 'password'),
        })
        this.bootstrapLimiter.recordSuccess(key)
        this.setSessionCookies(response, session.token, session.csrfToken, session.absoluteExpiresAt)
        sendJson(response, 201, { ok: true, principal: publicPrincipal(session.principal) })
      } catch (error) {
        if (shouldCountAuthFailure(error)) this.bootstrapLimiter.recordFailure(key)
        throw error
      }
      return true
    }
    if (pathname === '/auth/v1/login') {
      requireMethod(request, ['POST'])
      this.requirePublicWriteProtection(request)
      const body = await readJsonBody(request)
      const key = authAttemptKey(request, readString(body, 'username'))
      this.requireRateLimit(this.loginLimiter, key)
      try {
        const session = await this.ctx.authGateway.login({
          username: readString(body, 'username'),
          password: readString(body, 'password'),
        })
        this.loginLimiter.recordSuccess(key)
        this.setSessionCookies(response, session.token, session.csrfToken, session.absoluteExpiresAt)
        sendJson(response, 200, { ok: true, principal: publicPrincipal(session.principal) })
      } catch (error) {
        if (shouldCountAuthFailure(error)) this.loginLimiter.recordFailure(key)
        throw error
      }
      return true
    }
    if (pathname === '/auth/v1/session') {
      requireMethod(request, ['GET', 'HEAD'])
      if (sessionToken === null) throw new HttpProblem(401, 'AUTH_REQUIRED', '需要登录')
      const principal = principalContext.require()
      const csrfToken = readUniqueCookie(request, this.cookiePolicy.csrfName)
      sendJson(response, 200, {
        ok: true,
        principal: publicPrincipal(principal),
        csrfToken,
      }, request.method === 'HEAD')
      return true
    }
    if (pathname === '/auth/v1/logout' || pathname === '/auth/v1/account') {
      requireMethod(request, ['POST'])
      if (sessionToken === null) throw new HttpProblem(401, 'AUTH_REQUIRED', '需要登录')
      const csrf = request.headers['x-dsh-csrf']
      const cookieCsrf = readUniqueCookie(request, this.cookiePolicy.csrfName)
      if (
        typeof csrf !== 'string'
        || cookieCsrf === null
        || !safeEqual(csrf, cookieCsrf)
        || !this.ctx.authGateway.verifyCsrf(sessionToken, csrf)
      ) {
        throw new HttpProblem(403, 'AUTH_CSRF_REJECTED', '安全校验失败')
      }
      if (pathname === '/auth/v1/account') {
        const body = await readJsonBody(request)
        const key = authAttemptKey(request, principalContext.require().username)
        this.requireRateLimit(this.loginLimiter, key)
        try {
          const session = await this.ctx.authGateway.updateAccount(sessionToken, {
            currentPassword: readString(body, 'currentPassword'),
            username: readString(body, 'username'),
            displayName: readString(body, 'displayName'),
            ...(body.password === undefined ? {} : { password: readString(body, 'password') }),
          })
          this.loginLimiter.recordSuccess(key)
          this.setSessionCookies(response, session.token, session.csrfToken, session.absoluteExpiresAt)
          sendJson(response, 200, { ok: true, principal: publicPrincipal(session.principal) })
        } catch (error) {
          if (shouldCountAuthFailure(error)) this.loginLimiter.recordFailure(key)
          throw error
        }
        return true
      }
      await this.ctx.authGateway.logout(sessionToken)
      this.clearSessionCookies(response)
      sendJson(response, 200, { ok: true })
      return true
    }
    return false
  }

  private requireRateLimit(limiter: FailureRateLimiter, key: LoginAttemptKey): void {
    const decision = limiter.check(key)
    if (decision.allowed) return
    const retryAfterSeconds = Math.ceil(decision.retryAfterMs / 1000)
    throw new HttpProblem(429, 'AUTH_RATE_LIMITED', `尝试次数过多，请在 ${String(retryAfterSeconds)} 秒后重试`, retryAfterSeconds)
  }

  private requirePublicWriteProtection(request: IncomingMessage): void {
    if (!hasTrustedOrigin(request, this.config.trustedHosts)) {
      throw new HttpProblem(403, 'AUTH_ORIGIN_REJECTED', '请求来源不受信任')
    }
    const headerToken = request.headers['x-dsh-csrf']
    const cookieToken = readUniqueCookie(request, this.cookiePolicy.preAuthCsrfName)
    if (typeof headerToken !== 'string' || cookieToken === null || !safeEqual(headerToken, cookieToken)) {
      throw new HttpProblem(403, 'AUTH_CSRF_REJECTED', '安全校验失败')
    }
  }

  private readOrIssuePreAuthCsrf(request: IncomingMessage): string {
    const existing = readUniqueCookie(request, this.cookiePolicy.preAuthCsrfName)
    return existing !== null && existing.length === 43 ? existing : randomBytes(32).toString('base64url')
  }

  private setSessionCookies(response: ServerResponse, token: string, csrfToken: string, absoluteExpiresAt: number): void {
    const maxAge = Math.max(1, Math.floor((absoluteExpiresAt - Date.now()) / 1000))
    response.setHeader('set-cookie', [
      serializeCookie(this.cookiePolicy.sessionName, token, this.cookiePolicy, { httpOnly: true, maxAge }),
      serializeCookie(this.cookiePolicy.csrfName, csrfToken, this.cookiePolicy, { httpOnly: true, maxAge }),
      serializeCookie(this.cookiePolicy.preAuthCsrfName, '', this.cookiePolicy, { httpOnly: true, maxAge: 0 }),
    ])
  }

  private clearSessionCookies(response: ServerResponse): void {
    response.setHeader('set-cookie', [
      serializeCookie(this.cookiePolicy.sessionName, '', this.cookiePolicy, { httpOnly: true, maxAge: 0 }),
      serializeCookie(this.cookiePolicy.csrfName, '', this.cookiePolicy, { httpOnly: true, maxAge: 0 }),
    ])
  }

  private async handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
    const onError = (error: Error): void => {
      this.ctx.logger.warn(error)
      socket.destroy()
    }
    socket.on('error', onError)
    socket.once('close', () => {
      socket.off('error', onError)
      this.upgradedSockets.delete(socket)
    })
    try {
      if (!isTrustedRequest(request, this.config.trustedHosts)) {
        rejectUpgrade(socket, 403)
        return
      }
      const decision = await this.gate.evaluateUpgrade(request)
      if (decision.kind !== 'allow') {
        rejectUpgrade(socket, decision.kind === 'deny' ? decision.status : 401)
        return
      }
      const route = this.upgrades.get(readPathname(request))
      if (route === undefined) {
        rejectUpgrade(socket, 404)
        return
      }
      this.bridgeAuthentication(request)
      this.upgradedSockets.add(socket)
      let sessionSockets = this.socketsBySession.get(decision.principal.sessionId)
      if (sessionSockets === undefined) {
        sessionSockets = new Set()
        this.socketsBySession.set(decision.principal.sessionId, sessionSockets)
      }
      sessionSockets.add(socket)
      socket.once('close', () => {
        sessionSockets.delete(socket)
        if (sessionSockets.size === 0) this.socketsBySession.delete(decision.principal.sessionId)
      })
      await principalContext.run(decision.principal, () => route.handler(request, socket, head))
    } catch (error) {
      this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)))
      socket.destroy()
    }
  }

  private match(pathname: string): WebRoute | WebResourceRoute | undefined {
    const exact = this.exact.get(pathname)
    if (exact !== undefined) return exact
    let best: WebRoute | WebResourceRoute | undefined
    for (const [prefix, route] of this.prefixes) {
      if (pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue
      if (best === undefined || prefix.length > best.path.length) best = route
    }
    return best
  }

  private sendProblem(response: ServerResponse, error: unknown): void {
    const requestId = String(response.getHeader('x-request-id') ?? randomUUID())
    if (isAuthFailure(error)) {
      sendJson(response, error.status, failureBody(error.code, requestId, error.message))
      return
    }
    if (error instanceof HttpProblem) {
      if (error.retryAfterSeconds !== undefined) response.setHeader('retry-after', String(error.retryAfterSeconds))
      sendJson(response, error.status, failureBody(error.code, requestId, error.message))
      return
    }
    sendJson(response, 500, failureBody('AUTH_INTERNAL_ERROR', requestId, '认证服务暂不可用'))
  }
}

function isAuthFailure(error: unknown): error is Error & { code: string; status: number } {
  if (!(error instanceof Error)) return false
  const candidate = error as Error & { code?: unknown; status?: unknown }
  return typeof candidate.code === 'string' && typeof candidate.status === 'number'
}

function createCookiePolicy(config: Config): CookiePolicy {
  const secure = config.cookieSecure === 'required'
    || config.tls != null
  return secure
    ? { sessionName: '__Host-dsh_auth', csrfName: '__Host-dsh_csrf', preAuthCsrfName: '__Host-dsh_pre_csrf', secure }
    : { sessionName: 'dsh_auth_dev', csrfName: 'dsh_csrf_dev', preAuthCsrfName: 'dsh_pre_csrf_dev', secure }
}

function serializeCookie(
  name: string,
  value: string,
  policy: CookiePolicy,
  options: { httpOnly: boolean; maxAge?: number },
): string {
  const attributes = [`${name}=${value}`, 'Path=/', 'SameSite=Lax']
  if (options.httpOnly) attributes.push('HttpOnly')
  if (policy.secure) attributes.push('Secure')
  if (options.maxAge !== undefined) attributes.push(`Max-Age=${String(options.maxAge)}`)
  return attributes.join('; ')
}

function applySecurityHeaders(response: ServerResponse, nonce?: string): void {
  response.setHeader('x-content-type-options', 'nosniff')
  response.setHeader('x-frame-options', 'DENY')
  response.setHeader('referrer-policy', 'no-referrer')
  response.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()')
  response.setHeader('x-robots-tag', 'noindex, nofollow')
  if (nonce !== undefined) {
    response.setHeader('content-security-policy', `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`)
  }
}

function sendJson(response: ServerResponse, status: number, body: unknown, head = false): void {
  applySecurityHeaders(response)
  response.setHeader('cache-control', 'no-store')
  response.setHeader('content-type', 'application/json; charset=utf-8')
  response.writeHead(status)
  response.end(head ? undefined : JSON.stringify(body))
}

function failureBody(code: string, requestId: string, message?: string): object {
  return { ok: false, error: { code, message: message ?? '需要登录后继续', requestId } }
}

function publicPrincipal(principal: import('./auth-service.js').Principal): object {
  return {
    userId: principal.userId,
    username: principal.username,
    displayName: principal.displayName,
    roles: principal.roles,
    permissions: [...principal.permissions],
  }
}

function requireMethod(request: IncomingMessage, allowed: readonly string[]): void {
  if (!allowed.includes(request.method ?? 'GET')) throw new HttpProblem(405, 'METHOD_NOT_ALLOWED', '请求方法不受支持')
}

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const mediaType = (request.headers['content-type'] ?? '').split(';', 1)[0]?.trim().toLowerCase()
  if (mediaType !== 'application/json') throw new HttpProblem(415, 'AUTH_MEDIA_TYPE_REQUIRED', '请求必须使用 application/json')
  const declared = Number(request.headers['content-length'] ?? 0)
  if (Number.isFinite(declared) && declared > MAX_AUTH_BODY_BYTES) {
    throw new HttpProblem(413, 'AUTH_BODY_TOO_LARGE', '请求内容过大')
  }
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
    size += buffer.length
    if (size > MAX_AUTH_BODY_BYTES) throw new HttpProblem(413, 'AUTH_BODY_TOO_LARGE', '请求内容过大')
    chunks.push(buffer)
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('object required')
    return parsed as Record<string, unknown>
  } catch {
    throw new HttpProblem(400, 'AUTH_INVALID_JSON', '请求内容不是有效 JSON')
  }
}

function readString(body: Record<string, unknown>, name: string): string {
  const value = body[name]
  if (typeof value !== 'string') throw new HttpProblem(400, 'AUTH_INVALID_INPUT', '提交的信息不完整')
  return value
}

function authAttemptKey(request: IncomingMessage, username: string): LoginAttemptKey {
  return {
    account: username.normalize('NFKC').trim().toLowerCase().slice(0, 128) || '<blank>',
    source: request.socket.remoteAddress ?? '<unknown>',
  }
}

function shouldCountAuthFailure(error: unknown): boolean {
  if (!isAuthFailure(error)) return false
  return error.code === 'AUTH_INVALID_CREDENTIALS'
    || error.code === 'AUTH_BOOTSTRAP_INVALID'
    || error.code === 'AUTH_INVALID_INPUT'
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}

function readPathname(request: IncomingMessage): string {
  return new URL(request.url ?? '/', 'http://dsh.local').pathname
}

function safeReturnTo(request: IncomingMessage): string {
  const requested = new URL(request.url ?? '/', 'http://dsh.local').searchParams.get('returnTo')
  if (requested === null || !requested.startsWith('/') || requested.startsWith('//')) return '/'
  const parsed = new URL(requested, 'http://dsh.local')
  if (parsed.origin !== 'http://dsh.local' || parsed.pathname === '/auth/login') return '/'
  return `${parsed.pathname}${parsed.search}${parsed.hash}`
}

function assertRoutePath(path: string, allowEmptyPrefix: boolean): void {
  if ((path === '' && !allowEmptyPrefix) || (path !== '' && !path.startsWith('/')) || (path.length > 1 && path.endsWith('/'))) {
    throw new Error(`webserver: invalid route path "${path}"`)
  }
  if (path === '/auth' || path.startsWith('/auth/')) {
    throw new Error(`webserver: reserved authentication route path "${path}"`)
  }
}

function rejectUpgrade(socket: Duplex, status: number): void {
  const reason = status === 403 ? 'Forbidden' : status === 404 ? 'Not Found' : 'Unauthorized'
  socket.end(`HTTP/1.1 ${String(status)} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`)
}

export default AuthAwareWebServer
