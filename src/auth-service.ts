import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { chmod, mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import type { PasswordHasher } from './password-hasher.js'

export type AuthState = 'uninitialized_locked' | 'ready'

export interface Principal {
  userId: string
  sessionId: string
  username: string
  displayName: string
  roles: readonly string[]
  permissions: ReadonlySet<string>
  authVersion: number
  policyVersion: number
}

export interface AuthSession {
  token: string
  csrfToken: string
  principal: Principal
  idleExpiresAt: number
  absoluteExpiresAt: number
}

export interface AuthServiceOptions {
  databasePath: string
  bootstrapToken?: string
  bootstrapTtlMs: number
  sessionIdleTtlMs: number
  sessionAbsoluteTtlMs: number
  passwordHasher: PasswordHasher
  now?: () => number
}

export interface BootstrapInput {
  bootstrapToken: string
  username: string
  displayName: string
  password: string
}

export interface LoginInput {
  username: string
  password: string
}

export type AuthFailureCode =
  | 'AUTH_ALREADY_INITIALIZED'
  | 'AUTH_BOOTSTRAP_INVALID'
  | 'AUTH_INVALID_CREDENTIALS'
  | 'AUTH_INVALID_INPUT'
  | 'AUTH_NOT_INITIALIZED'

const FAILURE_STATUS: Record<AuthFailureCode, number> = {
  AUTH_ALREADY_INITIALIZED: 409,
  AUTH_BOOTSTRAP_INVALID: 403,
  AUTH_INVALID_CREDENTIALS: 401,
  AUTH_INVALID_INPUT: 400,
  AUTH_NOT_INITIALIZED: 423,
}

const FAILURE_MESSAGE: Record<AuthFailureCode, string> = {
  AUTH_ALREADY_INITIALIZED: '系统已经完成初始化',
  AUTH_BOOTSTRAP_INVALID: '初始化凭据无效或已过期',
  AUTH_INVALID_CREDENTIALS: '用户名或密码错误',
  AUTH_INVALID_INPUT: '提交的信息不符合安全要求',
  AUTH_NOT_INITIALIZED: '系统尚未完成安全初始化',
}

const APPLICATION_ID = 0x44534841
const SCHEMA_VERSION = 1
const SUPER_ADMIN_PERMISSIONS = new Set(['*'])

interface UserRow {
  id: string
  username_norm: string
  display_name: string
  password_hash: string
  status: string
  auth_version: number
}

interface SessionRow extends UserRow {
  session_id_hash: string
  idle_expires_at: number
  absolute_expires_at: number
  session_auth_version: number
}

export class AuthFailure extends Error {
  readonly code: AuthFailureCode
  readonly status: number

  constructor(code: AuthFailureCode) {
    super(FAILURE_MESSAGE[code])
    this.name = 'AuthFailure'
    this.code = code
    this.status = FAILURE_STATUS[code]
  }
}

export class AuthService {
  readonly issuedBootstrapToken: string | undefined
  private readonly db: DatabaseSync
  private readonly passwordHasher: PasswordHasher
  private readonly dummyHash: string
  private readonly now: () => number
  private readonly sessionIdleTtlMs: number
  private readonly sessionAbsoluteTtlMs: number
  private closed = false

  private constructor(
    options: AuthServiceOptions,
    db: DatabaseSync,
    dummyHash: string,
    issuedBootstrapToken: string | undefined,
  ) {
    this.db = db
    this.passwordHasher = options.passwordHasher
    this.dummyHash = dummyHash
    this.now = options.now ?? Date.now
    this.sessionIdleTtlMs = options.sessionIdleTtlMs
    this.sessionAbsoluteTtlMs = options.sessionAbsoluteTtlMs
    this.issuedBootstrapToken = issuedBootstrapToken
  }

  static async open(options: AuthServiceOptions): Promise<AuthService> {
    assertPositiveDuration(options.bootstrapTtlMs, 'bootstrapTtlMs')
    assertPositiveDuration(options.sessionIdleTtlMs, 'sessionIdleTtlMs')
    assertPositiveDuration(options.sessionAbsoluteTtlMs, 'sessionAbsoluteTtlMs')
    if (options.sessionIdleTtlMs > options.sessionAbsoluteTtlMs) {
      throw new Error('sessionIdleTtlMs cannot exceed sessionAbsoluteTtlMs')
    }
    if (options.databasePath !== ':memory:') {
      const directory = dirname(options.databasePath)
      await mkdir(directory, { recursive: true, mode: 0o700 })
      await chmod(directory, 0o700)
    }
    const db = new DatabaseSync(options.databasePath)
    try {
      configureDatabase(db, options.databasePath)
      if (options.databasePath !== ':memory:') await chmod(options.databasePath, 0o600)
      const now = (options.now ?? Date.now)()
      const users = readCount(db, 'users')
      let issuedBootstrapToken: string | undefined
      if (users === 0) {
        issuedBootstrapToken = options.bootstrapToken ?? randomBytes(32).toString('base64url')
        db.prepare(`
          INSERT INTO bootstrap_tokens (singleton, token_hash, expires_at, used_at)
          VALUES (1, ?, ?, NULL)
          ON CONFLICT(singleton) DO UPDATE SET
            token_hash = excluded.token_hash,
            expires_at = excluded.expires_at,
            used_at = NULL
        `).run(hashToken(issuedBootstrapToken), now + options.bootstrapTtlMs)
      }
      const dummyHash = await options.passwordHasher.hash(randomBytes(32).toString('base64url'))
      return new AuthService(options, db, dummyHash, issuedBootstrapToken)
    } catch (error) {
      db.close()
      throw error
    }
  }

  getStatus(): { state: AuthState } {
    this.requireOpen()
    return { state: readCount(this.db, 'users') === 0 ? 'uninitialized_locked' : 'ready' }
  }

  async bootstrap(input: BootstrapInput): Promise<AuthSession> {
    this.requireOpen()
    const normalized = validateIdentityInput(input.username, input.displayName, input.password)
    if (this.getStatus().state !== 'uninitialized_locked') throw new AuthFailure('AUTH_ALREADY_INITIALIZED')
    const now = this.now()
    const bootstrap = this.db.prepare(
      'SELECT token_hash, expires_at, used_at FROM bootstrap_tokens WHERE singleton = 1',
    ).get() as { token_hash: string; expires_at: number; used_at: number | null } | undefined
    if (
      bootstrap === undefined
      || bootstrap.used_at !== null
      || bootstrap.expires_at <= now
      || !safeTokenEqual(hashToken(input.bootstrapToken), bootstrap.token_hash)
    ) {
      throw new AuthFailure('AUTH_BOOTSTRAP_INVALID')
    }

    const passwordHash = await this.passwordHasher.hash(input.password)
    const userId = randomUUID()
    const session = newSessionMaterial(now, this.sessionIdleTtlMs, this.sessionAbsoluteTtlMs)
    this.db.exec('BEGIN IMMEDIATE')
    let committed = false
    try {
      if (readCount(this.db, 'users') !== 0) throw new AuthFailure('AUTH_ALREADY_INITIALIZED')
      const current = this.db.prepare(
        'SELECT token_hash, expires_at, used_at FROM bootstrap_tokens WHERE singleton = 1',
      ).get() as { token_hash: string; expires_at: number; used_at: number | null } | undefined
      if (
        current === undefined
        || current.used_at !== null
        || current.expires_at <= now
        || !safeTokenEqual(hashToken(input.bootstrapToken), current.token_hash)
      ) {
        throw new AuthFailure('AUTH_BOOTSTRAP_INVALID')
      }
      this.db.prepare(`
        INSERT INTO users (id, username_norm, display_name, password_hash, status, auth_version, created_at)
        VALUES (?, ?, ?, ?, 'active', 1, ?)
      `).run(userId, normalized.username, normalized.displayName, passwordHash, now)
      this.db.prepare('INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)').run(userId, 'super_admin')
      insertSession(this.db, session, userId, 1)
      this.db.prepare('UPDATE bootstrap_tokens SET used_at = ? WHERE singleton = 1').run(now)
      insertAudit(this.db, userId, 'auth.bootstrap.completed', 'allow', now)
      this.db.exec('COMMIT')
      committed = true
    } finally {
      if (!committed) this.db.exec('ROLLBACK')
    }
    return this.materializeSession(session, {
      id: userId,
      username_norm: normalized.username,
      display_name: normalized.displayName,
      password_hash: passwordHash,
      status: 'active',
      auth_version: 1,
    })
  }

  async login(input: LoginInput): Promise<AuthSession> {
    this.requireOpen()
    if (this.getStatus().state !== 'ready') throw new AuthFailure('AUTH_NOT_INITIALIZED')
    const username = normalizeUsername(input.username)
    const user = this.db.prepare(`
      SELECT id, username_norm, display_name, password_hash, status, auth_version
      FROM users WHERE username_norm = ?
    `).get(username) as UserRow | undefined
    const valid = await this.passwordHasher.verify(input.password, user?.password_hash ?? this.dummyHash)
    if (user === undefined || user.status !== 'active' || !valid) {
      insertAudit(this.db, user?.id ?? null, 'auth.login.failed', 'deny', this.now())
      throw new AuthFailure('AUTH_INVALID_CREDENTIALS')
    }
    if (this.passwordHasher.needsRehash(user.password_hash)) {
      const upgraded = await this.passwordHasher.hash(input.password)
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(upgraded, user.id)
    }
    const now = this.now()
    const material = newSessionMaterial(now, this.sessionIdleTtlMs, this.sessionAbsoluteTtlMs)
    insertSession(this.db, material, user.id, user.auth_version)
    insertAudit(this.db, user.id, 'auth.login.succeeded', 'allow', now)
    return this.materializeSession(material, user)
  }

  async authenticate(token: string): Promise<Principal | null> {
    this.requireOpen()
    if (token.length < 32 || token.length > 256) return null
    const now = this.now()
    const tokenHash = hashToken(token)
    const row = this.db.prepare(`
      SELECT
        s.id_hash AS session_id_hash,
        s.idle_expires_at,
        s.absolute_expires_at,
        s.auth_version AS session_auth_version,
        u.id,
        u.username_norm,
        u.display_name,
        u.password_hash,
        u.status,
        u.auth_version
      FROM auth_sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.id_hash = ? AND s.revoked_at IS NULL
    `).get(tokenHash) as SessionRow | undefined
    if (
      row === undefined
      || row.status !== 'active'
      || row.session_auth_version !== row.auth_version
      || row.idle_expires_at <= now
      || row.absolute_expires_at <= now
    ) {
      if (row !== undefined) this.db.prepare('UPDATE auth_sessions SET revoked_at = ? WHERE id_hash = ?').run(now, tokenHash)
      return null
    }
    const idleExpiresAt = Math.min(now + this.sessionIdleTtlMs, row.absolute_expires_at)
    this.db.prepare('UPDATE auth_sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id_hash = ?')
      .run(now, idleExpiresAt, tokenHash)
    return this.toPrincipal(row, tokenHash)
  }

  verifyCsrf(token: string, csrfToken: string): boolean {
    this.requireOpen()
    if (token.length < 32 || csrfToken.length < 32 || csrfToken.length > 256) return false
    const row = this.db.prepare(
      'SELECT csrf_hash FROM auth_sessions WHERE id_hash = ? AND revoked_at IS NULL',
    ).get(hashToken(token)) as { csrf_hash: string } | undefined
    return row !== undefined && safeTokenEqual(hashToken(csrfToken), row.csrf_hash)
  }

  async logout(token: string): Promise<void> {
    this.requireOpen()
    const now = this.now()
    const tokenHash = hashToken(token)
    const row = this.db.prepare('SELECT user_id FROM auth_sessions WHERE id_hash = ?').get(tokenHash) as { user_id: string } | undefined
    this.db.prepare('UPDATE auth_sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL').run(now, tokenHash)
    if (row !== undefined) insertAudit(this.db, row.user_id, 'auth.logout', 'allow', now)
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    this.db.close()
  }

  private materializeSession(material: SessionMaterial, user: UserRow): AuthSession {
    return {
      token: material.token,
      csrfToken: material.csrfToken,
      principal: this.toPrincipal(user, material.idHash),
      idleExpiresAt: material.idleExpiresAt,
      absoluteExpiresAt: material.absoluteExpiresAt,
    }
  }

  private toPrincipal(user: UserRow, sessionId: string): Principal {
    const roles = this.db.prepare('SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name')
      .all(user.id) as unknown as { role_name: string }[]
    return {
      userId: user.id,
      sessionId,
      username: user.username_norm,
      displayName: user.display_name,
      roles: roles.map(role => role.role_name),
      permissions: new Set(SUPER_ADMIN_PERMISSIONS),
      authVersion: user.auth_version,
      policyVersion: 1,
    }
  }

  private requireOpen(): void {
    if (this.closed) throw new Error('AuthService is closed')
  }
}

interface SessionMaterial {
  token: string
  csrfToken: string
  idHash: string
  csrfHash: string
  createdAt: number
  idleExpiresAt: number
  absoluteExpiresAt: number
}

function newSessionMaterial(now: number, idleTtl: number, absoluteTtl: number): SessionMaterial {
  const token = randomBytes(32).toString('base64url')
  const csrfToken = randomBytes(32).toString('base64url')
  return {
    token,
    csrfToken,
    idHash: hashToken(token),
    csrfHash: hashToken(csrfToken),
    createdAt: now,
    idleExpiresAt: now + idleTtl,
    absoluteExpiresAt: now + absoluteTtl,
  }
}

function insertSession(db: DatabaseSync, material: SessionMaterial, userId: string, authVersion: number): void {
  db.prepare(`
    INSERT INTO auth_sessions (
      id_hash, csrf_hash, user_id, created_at, last_seen_at,
      idle_expires_at, absolute_expires_at, auth_version, revoked_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
  `).run(
    material.idHash,
    material.csrfHash,
    userId,
    material.createdAt,
    material.createdAt,
    material.idleExpiresAt,
    material.absoluteExpiresAt,
    authVersion,
  )
}

function validateIdentityInput(username: string, displayName: string, password: string): { username: string; displayName: string } {
  const normalizedUsername = normalizeUsername(username)
  const normalizedDisplayName = displayName.normalize('NFKC').trim()
  const passwordLength = [...password].length
  if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(normalizedUsername)) throw new AuthFailure('AUTH_INVALID_INPUT')
  if (normalizedDisplayName.length < 1 || normalizedDisplayName.length > 100) throw new AuthFailure('AUTH_INVALID_INPUT')
  if (passwordLength < 12 || passwordLength > 128) throw new AuthFailure('AUTH_INVALID_INPUT')
  return { username: normalizedUsername, displayName: normalizedDisplayName }
}

function normalizeUsername(username: string): string {
  return username.normalize('NFKC').trim().toLowerCase()
}

function hashToken(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('base64url')
}

function safeTokenEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual)
  const expectedBuffer = Buffer.from(expected)
  return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer)
}

function assertPositiveDuration(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${field} must be a positive safe integer`)
}

function readCount(db: DatabaseSync, table: 'users'): number {
  return Number((db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count)
}

function insertAudit(db: DatabaseSync, actorId: string | null, action: string, decision: string, createdAt: number): void {
  db.prepare('INSERT INTO audit_log (id, actor_user_id, action, decision, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(randomUUID(), actorId, action, decision, createdAt)
}

function configureDatabase(db: DatabaseSync, path: string): void {
  db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000')
  let transaction = false
  try {
    db.exec('BEGIN IMMEDIATE')
    transaction = true
    const { user_version: version } = db.prepare('PRAGMA user_version').get() as { user_version: number }
    const { application_id: applicationId } = db.prepare('PRAGMA application_id').get() as { application_id: number }
    const { count } = db.prepare("SELECT COUNT(*) AS count FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'").get() as { count: number }
    if (version === 0 && (applicationId !== 0 || count > 0)) {
      throw new Error(`authentication database at "${path}" is not an empty dsh-auth database`)
    }
    if (version !== 0 && version !== SCHEMA_VERSION) {
      throw new Error(`authentication database at "${path}" has unsupported schema version ${version}`)
    }
    if (version === SCHEMA_VERSION && applicationId !== APPLICATION_ID) {
      throw new Error(`authentication database at "${path}" has a foreign application id`)
    }
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username_norm TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
        auth_version INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS user_roles (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role_name TEXT NOT NULL,
        PRIMARY KEY (user_id, role_name)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id_hash TEXT PRIMARY KEY,
        csrf_hash TEXT NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        idle_expires_at INTEGER NOT NULL,
        absolute_expires_at INTEGER NOT NULL,
        auth_version INTEGER NOT NULL,
        revoked_at INTEGER
      ) STRICT;
      CREATE INDEX IF NOT EXISTS auth_sessions_user_id ON auth_sessions(user_id);
      CREATE TABLE IF NOT EXISTS bootstrap_tokens (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        token_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
      ) STRICT;
      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        actor_user_id TEXT,
        action TEXT NOT NULL,
        decision TEXT NOT NULL,
        created_at INTEGER NOT NULL
      ) STRICT;
    `)
    if (version === 0) {
      db.exec(`PRAGMA application_id = ${APPLICATION_ID}; PRAGMA user_version = ${SCHEMA_VERSION}`)
    }
    db.exec('COMMIT')
    transaction = false
  } catch (error) {
    if (transaction) db.exec('ROLLBACK')
    throw error
  }
  if (path !== ':memory:') db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL')
}
