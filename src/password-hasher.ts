import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'

export interface PasswordHasher {
  hash(password: string): Promise<string>
  verify(password: string, encoded: string): Promise<boolean>
  needsRehash(encoded: string): boolean
}

export interface ScryptParameters {
  cost: number
  blockSize: number
  parallelization: number
  keyLength: number
}

const DEFAULT_PARAMETERS: ScryptParameters = {
  cost: 32768,
  blockSize: 8,
  parallelization: 1,
  keyLength: 32,
}

const HASH_PATTERN = /^\$dsh\$scrypt-v1\$N=(\d+),r=(\d+),p=(\d+),k=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/

interface ParsedHash {
  parameters: ScryptParameters
  salt: Buffer
  digest: Buffer
}

export class ScryptPasswordHasher implements PasswordHasher {
  readonly parameters: ScryptParameters

  constructor(parameters: Partial<ScryptParameters> = {}) {
    this.parameters = { ...DEFAULT_PARAMETERS, ...parameters }
    assertSafeParameters(this.parameters)
  }

  async hash(password: string): Promise<string> {
    const salt = randomBytes(16)
    const digest = await derive(password, salt, this.parameters)
    const { cost, blockSize, parallelization, keyLength } = this.parameters
    return `$dsh$scrypt-v1$N=${cost},r=${blockSize},p=${parallelization},k=${keyLength}$${salt.toString('base64url')}$${digest.toString('base64url')}`
  }

  async verify(password: string, encoded: string): Promise<boolean> {
    const parsed = parseHash(encoded)
    if (parsed === undefined) return false
    try {
      const actual = await derive(password, parsed.salt, parsed.parameters)
      return actual.length === parsed.digest.length && timingSafeEqual(actual, parsed.digest)
    } catch {
      return false
    }
  }

  needsRehash(encoded: string): boolean {
    const parsed = parseHash(encoded)
    if (parsed === undefined) return true
    return Object.entries(this.parameters).some(([key, value]) => (
      parsed.parameters[key as keyof ScryptParameters] !== value
    ))
  }
}

function parseHash(encoded: string): ParsedHash | undefined {
  const match = HASH_PATTERN.exec(encoded)
  if (match === null) return undefined
  const parameters: ScryptParameters = {
    cost: Number(match[1]),
    blockSize: Number(match[2]),
    parallelization: Number(match[3]),
    keyLength: Number(match[4]),
  }
  try {
    assertSafeParameters(parameters)
    const salt = Buffer.from(match[5] ?? '', 'base64url')
    const digest = Buffer.from(match[6] ?? '', 'base64url')
    if (salt.length < 16 || salt.length > 64 || digest.length !== parameters.keyLength) return undefined
    return { parameters, salt, digest }
  } catch {
    return undefined
  }
}

function assertSafeParameters(parameters: ScryptParameters): void {
  const { cost, blockSize, parallelization, keyLength } = parameters
  if (!Number.isSafeInteger(cost) || cost < 2 || cost > 1_048_576 || (cost & (cost - 1)) !== 0) {
    throw new Error('scrypt cost must be a power of two between 2 and 1048576')
  }
  if (!Number.isSafeInteger(blockSize) || blockSize < 1 || blockSize > 32) {
    throw new Error('scrypt blockSize must be between 1 and 32')
  }
  if (!Number.isSafeInteger(parallelization) || parallelization < 1 || parallelization > 16) {
    throw new Error('scrypt parallelization must be between 1 and 16')
  }
  if (!Number.isSafeInteger(keyLength) || keyLength < 16 || keyLength > 64) {
    throw new Error('scrypt keyLength must be between 16 and 64')
  }
}

async function derive(password: string, salt: Buffer, parameters: ScryptParameters): Promise<Buffer> {
  const { cost, blockSize, parallelization, keyLength } = parameters
  const maxmem = Math.max(32 * 1024 * 1024, 128 * cost * blockSize + 2 * 1024 * 1024)
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, { cost, blockSize, parallelization, maxmem }, (error, result) => {
      if (error !== null) reject(error)
      else resolve(result)
    })
  })
}
