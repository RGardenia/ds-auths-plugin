// src/index.ts
import { Service } from "@deepseek-ai/cordis";
import z from "@deepseek-ai/schemastery";

// src/auth-service.ts
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { chmod, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
var FAILURE_STATUS = {
  AUTH_ALREADY_INITIALIZED: 409,
  AUTH_BOOTSTRAP_INVALID: 403,
  AUTH_INVALID_CREDENTIALS: 401,
  AUTH_INVALID_INPUT: 400,
  AUTH_NOT_INITIALIZED: 423
};
var FAILURE_MESSAGE = {
  AUTH_ALREADY_INITIALIZED: "\u7CFB\u7EDF\u5DF2\u7ECF\u5B8C\u6210\u521D\u59CB\u5316",
  AUTH_BOOTSTRAP_INVALID: "\u521D\u59CB\u5316\u51ED\u636E\u65E0\u6548\u6216\u5DF2\u8FC7\u671F",
  AUTH_INVALID_CREDENTIALS: "\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF",
  AUTH_INVALID_INPUT: "\u63D0\u4EA4\u7684\u4FE1\u606F\u4E0D\u7B26\u5408\u5B89\u5168\u8981\u6C42",
  AUTH_NOT_INITIALIZED: "\u7CFB\u7EDF\u5C1A\u672A\u5B8C\u6210\u5B89\u5168\u521D\u59CB\u5316"
};
var APPLICATION_ID = 1146308673;
var SCHEMA_VERSION = 1;
var SUPER_ADMIN_PERMISSIONS = /* @__PURE__ */ new Set(["*"]);
var AuthFailure = class extends Error {
  code;
  status;
  constructor(code) {
    super(FAILURE_MESSAGE[code]);
    this.name = "AuthFailure";
    this.code = code;
    this.status = FAILURE_STATUS[code];
  }
};
var AuthService = class _AuthService {
  issuedBootstrapToken;
  db;
  passwordHasher;
  dummyHash;
  now;
  sessionIdleTtlMs;
  sessionAbsoluteTtlMs;
  closed = false;
  constructor(options, db, dummyHash, issuedBootstrapToken) {
    this.db = db;
    this.passwordHasher = options.passwordHasher;
    this.dummyHash = dummyHash;
    this.now = options.now ?? Date.now;
    this.sessionIdleTtlMs = options.sessionIdleTtlMs;
    this.sessionAbsoluteTtlMs = options.sessionAbsoluteTtlMs;
    this.issuedBootstrapToken = issuedBootstrapToken;
  }
  static async open(options) {
    assertPositiveDuration(options.bootstrapTtlMs, "bootstrapTtlMs");
    assertPositiveDuration(options.sessionIdleTtlMs, "sessionIdleTtlMs");
    assertPositiveDuration(options.sessionAbsoluteTtlMs, "sessionAbsoluteTtlMs");
    if (options.sessionIdleTtlMs > options.sessionAbsoluteTtlMs) {
      throw new Error("sessionIdleTtlMs cannot exceed sessionAbsoluteTtlMs");
    }
    if (options.databasePath !== ":memory:") {
      const directory = dirname(options.databasePath);
      await mkdir(directory, { recursive: true, mode: 448 });
      await chmod(directory, 448);
    }
    const db = new DatabaseSync(options.databasePath);
    try {
      configureDatabase(db, options.databasePath);
      if (options.databasePath !== ":memory:") await chmod(options.databasePath, 384);
      const now = (options.now ?? Date.now)();
      const users = readCount(db, "users");
      let issuedBootstrapToken;
      if (users === 0) {
        issuedBootstrapToken = options.bootstrapToken ?? randomBytes(32).toString("base64url");
        db.prepare(`
          INSERT INTO bootstrap_tokens (singleton, token_hash, expires_at, used_at)
          VALUES (1, ?, ?, NULL)
          ON CONFLICT(singleton) DO UPDATE SET
            token_hash = excluded.token_hash,
            expires_at = excluded.expires_at,
            used_at = NULL
        `).run(hashToken(issuedBootstrapToken), now + options.bootstrapTtlMs);
      }
      const dummyHash = await options.passwordHasher.hash(randomBytes(32).toString("base64url"));
      return new _AuthService(options, db, dummyHash, issuedBootstrapToken);
    } catch (error) {
      db.close();
      throw error;
    }
  }
  getStatus() {
    this.requireOpen();
    return { state: readCount(this.db, "users") === 0 ? "uninitialized_locked" : "ready" };
  }
  async bootstrap(input) {
    this.requireOpen();
    const normalized = validateIdentityInput(input.username, input.displayName, input.password);
    if (this.getStatus().state !== "uninitialized_locked") throw new AuthFailure("AUTH_ALREADY_INITIALIZED");
    const now = this.now();
    const bootstrap = this.db.prepare(
      "SELECT token_hash, expires_at, used_at FROM bootstrap_tokens WHERE singleton = 1"
    ).get();
    if (bootstrap === void 0 || bootstrap.used_at !== null || bootstrap.expires_at <= now || !safeTokenEqual(hashToken(input.bootstrapToken), bootstrap.token_hash)) {
      throw new AuthFailure("AUTH_BOOTSTRAP_INVALID");
    }
    const passwordHash = await this.passwordHasher.hash(input.password);
    const userId = randomUUID();
    const session = newSessionMaterial(now, this.sessionIdleTtlMs, this.sessionAbsoluteTtlMs);
    this.db.exec("BEGIN IMMEDIATE");
    let committed = false;
    try {
      if (readCount(this.db, "users") !== 0) throw new AuthFailure("AUTH_ALREADY_INITIALIZED");
      const current = this.db.prepare(
        "SELECT token_hash, expires_at, used_at FROM bootstrap_tokens WHERE singleton = 1"
      ).get();
      if (current === void 0 || current.used_at !== null || current.expires_at <= now || !safeTokenEqual(hashToken(input.bootstrapToken), current.token_hash)) {
        throw new AuthFailure("AUTH_BOOTSTRAP_INVALID");
      }
      this.db.prepare(`
        INSERT INTO users (id, username_norm, display_name, password_hash, status, auth_version, created_at)
        VALUES (?, ?, ?, ?, 'active', 1, ?)
      `).run(userId, normalized.username, normalized.displayName, passwordHash, now);
      this.db.prepare("INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)").run(userId, "super_admin");
      insertSession(this.db, session, userId, 1);
      this.db.prepare("UPDATE bootstrap_tokens SET used_at = ? WHERE singleton = 1").run(now);
      insertAudit(this.db, userId, "auth.bootstrap.completed", "allow", now);
      this.db.exec("COMMIT");
      committed = true;
    } finally {
      if (!committed) this.db.exec("ROLLBACK");
    }
    return this.materializeSession(session, {
      id: userId,
      username_norm: normalized.username,
      display_name: normalized.displayName,
      password_hash: passwordHash,
      status: "active",
      auth_version: 1
    });
  }
  async login(input) {
    this.requireOpen();
    if (this.getStatus().state !== "ready") throw new AuthFailure("AUTH_NOT_INITIALIZED");
    const username = normalizeUsername(input.username);
    const user = this.db.prepare(`
      SELECT id, username_norm, display_name, password_hash, status, auth_version
      FROM users WHERE username_norm = ?
    `).get(username);
    const valid = await this.passwordHasher.verify(input.password, user?.password_hash ?? this.dummyHash);
    if (user === void 0 || user.status !== "active" || !valid) {
      insertAudit(this.db, user?.id ?? null, "auth.login.failed", "deny", this.now());
      throw new AuthFailure("AUTH_INVALID_CREDENTIALS");
    }
    if (this.passwordHasher.needsRehash(user.password_hash)) {
      const upgraded = await this.passwordHasher.hash(input.password);
      this.db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(upgraded, user.id);
    }
    const now = this.now();
    const material = newSessionMaterial(now, this.sessionIdleTtlMs, this.sessionAbsoluteTtlMs);
    insertSession(this.db, material, user.id, user.auth_version);
    insertAudit(this.db, user.id, "auth.login.succeeded", "allow", now);
    return this.materializeSession(material, user);
  }
  async authenticate(token) {
    this.requireOpen();
    if (token.length < 32 || token.length > 256) return null;
    const now = this.now();
    const tokenHash = hashToken(token);
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
    `).get(tokenHash);
    if (row === void 0 || row.status !== "active" || row.session_auth_version !== row.auth_version || row.idle_expires_at <= now || row.absolute_expires_at <= now) {
      if (row !== void 0) this.db.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE id_hash = ?").run(now, tokenHash);
      return null;
    }
    const idleExpiresAt = Math.min(now + this.sessionIdleTtlMs, row.absolute_expires_at);
    this.db.prepare("UPDATE auth_sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id_hash = ?").run(now, idleExpiresAt, tokenHash);
    return this.toPrincipal(row, tokenHash);
  }
  verifyCsrf(token, csrfToken) {
    this.requireOpen();
    if (token.length < 32 || csrfToken.length < 32 || csrfToken.length > 256) return false;
    const row = this.db.prepare(
      "SELECT csrf_hash FROM auth_sessions WHERE id_hash = ? AND revoked_at IS NULL"
    ).get(hashToken(token));
    return row !== void 0 && safeTokenEqual(hashToken(csrfToken), row.csrf_hash);
  }
  async logout(token) {
    this.requireOpen();
    const now = this.now();
    const tokenHash = hashToken(token);
    const row = this.db.prepare("SELECT user_id FROM auth_sessions WHERE id_hash = ?").get(tokenHash);
    this.db.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL").run(now, tokenHash);
    if (row !== void 0) insertAudit(this.db, row.user_id, "auth.logout", "allow", now);
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.db.close();
  }
  materializeSession(material, user) {
    return {
      token: material.token,
      csrfToken: material.csrfToken,
      principal: this.toPrincipal(user, material.idHash),
      idleExpiresAt: material.idleExpiresAt,
      absoluteExpiresAt: material.absoluteExpiresAt
    };
  }
  toPrincipal(user, sessionId) {
    const roles = this.db.prepare("SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name").all(user.id);
    return {
      userId: user.id,
      sessionId,
      username: user.username_norm,
      displayName: user.display_name,
      roles: roles.map((role) => role.role_name),
      permissions: new Set(SUPER_ADMIN_PERMISSIONS),
      authVersion: user.auth_version,
      policyVersion: 1
    };
  }
  requireOpen() {
    if (this.closed) throw new Error("AuthService is closed");
  }
};
function newSessionMaterial(now, idleTtl, absoluteTtl) {
  const token = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(32).toString("base64url");
  return {
    token,
    csrfToken,
    idHash: hashToken(token),
    csrfHash: hashToken(csrfToken),
    createdAt: now,
    idleExpiresAt: now + idleTtl,
    absoluteExpiresAt: now + absoluteTtl
  };
}
function insertSession(db, material, userId, authVersion) {
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
    authVersion
  );
}
function validateIdentityInput(username, displayName, password) {
  const normalizedUsername = normalizeUsername(username);
  const normalizedDisplayName = displayName.normalize("NFKC").trim();
  const passwordLength = [...password].length;
  if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(normalizedUsername)) throw new AuthFailure("AUTH_INVALID_INPUT");
  if (normalizedDisplayName.length < 1 || normalizedDisplayName.length > 100) throw new AuthFailure("AUTH_INVALID_INPUT");
  if (passwordLength < 12 || passwordLength > 128) throw new AuthFailure("AUTH_INVALID_INPUT");
  return { username: normalizedUsername, displayName: normalizedDisplayName };
}
function normalizeUsername(username) {
  return username.normalize("NFKC").trim().toLowerCase();
}
function hashToken(value) {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}
function safeTokenEqual(actual, expected) {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer);
}
function assertPositiveDuration(value, field) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${field} must be a positive safe integer`);
}
function readCount(db, table) {
  return Number(db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count);
}
function insertAudit(db, actorId, action, decision, createdAt) {
  db.prepare("INSERT INTO audit_log (id, actor_user_id, action, decision, created_at) VALUES (?, ?, ?, ?, ?)").run(randomUUID(), actorId, action, decision, createdAt);
}
function configureDatabase(db, path) {
  db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000");
  let transaction = false;
  try {
    db.exec("BEGIN IMMEDIATE");
    transaction = true;
    const { user_version: version } = db.prepare("PRAGMA user_version").get();
    const { application_id: applicationId } = db.prepare("PRAGMA application_id").get();
    const { count } = db.prepare("SELECT COUNT(*) AS count FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'").get();
    if (version === 0 && (applicationId !== 0 || count > 0)) {
      throw new Error(`authentication database at "${path}" is not an empty dsh-auth database`);
    }
    if (version !== 0 && version !== SCHEMA_VERSION) {
      throw new Error(`authentication database at "${path}" has unsupported schema version ${version}`);
    }
    if (version === SCHEMA_VERSION && applicationId !== APPLICATION_ID) {
      throw new Error(`authentication database at "${path}" has a foreign application id`);
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
    `);
    if (version === 0) {
      db.exec(`PRAGMA application_id = ${APPLICATION_ID}; PRAGMA user_version = ${SCHEMA_VERSION}`);
    }
    db.exec("COMMIT");
    transaction = false;
  } catch (error) {
    if (transaction) db.exec("ROLLBACK");
    throw error;
  }
  if (path !== ":memory:") db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL");
}

// src/password-hasher.ts
import { randomBytes as randomBytes2, scrypt, timingSafeEqual as timingSafeEqual2 } from "node:crypto";
var DEFAULT_PARAMETERS = {
  cost: 32768,
  blockSize: 8,
  parallelization: 1,
  keyLength: 32
};
var HASH_PATTERN = /^\$dsh\$scrypt-v1\$N=(\d+),r=(\d+),p=(\d+),k=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/;
var ScryptPasswordHasher = class {
  parameters;
  constructor(parameters = {}) {
    this.parameters = { ...DEFAULT_PARAMETERS, ...parameters };
    assertSafeParameters(this.parameters);
  }
  async hash(password) {
    const salt = randomBytes2(16);
    const digest = await derive(password, salt, this.parameters);
    const { cost, blockSize, parallelization, keyLength } = this.parameters;
    return `$dsh$scrypt-v1$N=${cost},r=${blockSize},p=${parallelization},k=${keyLength}$${salt.toString("base64url")}$${digest.toString("base64url")}`;
  }
  async verify(password, encoded) {
    const parsed = parseHash(encoded);
    if (parsed === void 0) return false;
    try {
      const actual = await derive(password, parsed.salt, parsed.parameters);
      return actual.length === parsed.digest.length && timingSafeEqual2(actual, parsed.digest);
    } catch {
      return false;
    }
  }
  needsRehash(encoded) {
    const parsed = parseHash(encoded);
    if (parsed === void 0) return true;
    return Object.entries(this.parameters).some(([key, value]) => parsed.parameters[key] !== value);
  }
};
function parseHash(encoded) {
  const match = HASH_PATTERN.exec(encoded);
  if (match === null) return void 0;
  const parameters = {
    cost: Number(match[1]),
    blockSize: Number(match[2]),
    parallelization: Number(match[3]),
    keyLength: Number(match[4])
  };
  try {
    assertSafeParameters(parameters);
    const salt = Buffer.from(match[5] ?? "", "base64url");
    const digest = Buffer.from(match[6] ?? "", "base64url");
    if (salt.length < 16 || salt.length > 64 || digest.length !== parameters.keyLength) return void 0;
    return { parameters, salt, digest };
  } catch {
    return void 0;
  }
}
function assertSafeParameters(parameters) {
  const { cost, blockSize, parallelization, keyLength } = parameters;
  if (!Number.isSafeInteger(cost) || cost < 2 || cost > 1048576 || (cost & cost - 1) !== 0) {
    throw new Error("scrypt cost must be a power of two between 2 and 1048576");
  }
  if (!Number.isSafeInteger(blockSize) || blockSize < 1 || blockSize > 32) {
    throw new Error("scrypt blockSize must be between 1 and 32");
  }
  if (!Number.isSafeInteger(parallelization) || parallelization < 1 || parallelization > 16) {
    throw new Error("scrypt parallelization must be between 1 and 16");
  }
  if (!Number.isSafeInteger(keyLength) || keyLength < 16 || keyLength > 64) {
    throw new Error("scrypt keyLength must be between 16 and 64");
  }
}
async function derive(password, salt, parameters) {
  const { cost, blockSize, parallelization, keyLength } = parameters;
  const maxmem = Math.max(32 * 1024 * 1024, 128 * cost * blockSize + 2 * 1024 * 1024);
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, { cost, blockSize, parallelization, maxmem }, (error, result) => {
      if (error !== null) reject(error);
      else resolve(result);
    });
  });
}

// src/index.ts
var AuthGateway = class extends Service {
  constructor(ctx, config) {
    super(ctx, "authGateway");
    this.config = config;
  }
  config;
  static Config = z.object({
    databasePath: z.string().default("auth.db"),
    bootstrapToken: z.string().default(""),
    bootstrapTtlMs: z.natural().min(6e4).default(9e5),
    sessionIdleTtlMs: z.natural().min(6e4).default(288e5),
    sessionAbsoluteTtlMs: z.natural().min(6e4).default(864e5),
    scryptCost: z.natural().min(1024).max(1048576).default(32768)
  });
  service;
  revocationListeners = /* @__PURE__ */ new Set();
  async [Service.init]() {
    const options = {
      databasePath: this.config.databasePath,
      bootstrapTtlMs: this.config.bootstrapTtlMs,
      sessionIdleTtlMs: this.config.sessionIdleTtlMs,
      sessionAbsoluteTtlMs: this.config.sessionAbsoluteTtlMs,
      passwordHasher: new ScryptPasswordHasher({ cost: this.config.scryptCost }),
      ...this.config.bootstrapToken.length === 0 ? {} : { bootstrapToken: this.config.bootstrapToken }
    };
    const service = await AuthService.open(options);
    this.service = service;
    if (service.issuedBootstrapToken !== void 0) {
      console.warn(
        `ds-auths-plugin is locked. Complete bootstrap with this one-time token: ${service.issuedBootstrapToken}`
      );
    }
    this.ctx.effect(() => () => {
      service.close();
      this.service = void 0;
    }, "authGateway.database");
  }
  getStatus() {
    return this.requireService().getStatus();
  }
  bootstrap(input) {
    return this.requireService().bootstrap(input);
  }
  login(input) {
    return this.requireService().login(input);
  }
  authenticate(token) {
    return this.requireService().authenticate(token);
  }
  verifyCsrf(token, csrfToken) {
    return this.requireService().verifyCsrf(token, csrfToken);
  }
  async logout(token) {
    const principal = await this.requireService().authenticate(token);
    await this.requireService().logout(token);
    if (principal !== null) {
      for (const listener of this.revocationListeners) listener(principal.sessionId);
    }
  }
  onSessionRevoked(listener) {
    this.revocationListeners.add(listener);
    return () => {
      this.revocationListeners.delete(listener);
    };
  }
  requireService() {
    if (this.service === void 0) throw new Error("authGateway is not ready");
    return this.service;
  }
};
var src_default = AuthGateway;
export {
  AuthFailure,
  AuthGateway,
  ScryptPasswordHasher,
  src_default as default
};
//# sourceMappingURL=index.js.map
