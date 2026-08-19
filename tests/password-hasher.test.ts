import { describe, expect, it } from 'vitest'
import { ScryptPasswordHasher } from '../src/password-hasher.js'

describe('ScryptPasswordHasher', () => {
  it('round-trips Unicode passwords without storing the plaintext', async () => {
    const hasher = new ScryptPasswordHasher({ cost: 1024, blockSize: 8, parallelization: 1, keyLength: 32 })
    const password = 'Correct horse 电池 staple 2026!'

    const encoded = await hasher.hash(password)

    expect(encoded).toMatch(/^\$dsh\$scrypt-v1\$N=1024,r=8,p=1,k=32\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/)
    expect(encoded).not.toContain(password)
    await expect(hasher.verify(password, encoded)).resolves.toBe(true)
    await expect(hasher.verify('not the password', encoded)).resolves.toBe(false)
    await expect(hasher.verify(password, 'not-a-password-hash')).resolves.toBe(false)
  })

  it('marks hashes with obsolete parameters for upgrade', async () => {
    const oldHasher = new ScryptPasswordHasher({ cost: 1024, blockSize: 8, parallelization: 1, keyLength: 32 })
    const currentHasher = new ScryptPasswordHasher({ cost: 2048, blockSize: 8, parallelization: 1, keyLength: 32 })
    const encoded = await oldHasher.hash('a sufficiently long password')

    expect(oldHasher.needsRehash(encoded)).toBe(false)
    expect(currentHasher.needsRehash(encoded)).toBe(true)
    expect(currentHasher.needsRehash('broken')).toBe(true)
  })
})
