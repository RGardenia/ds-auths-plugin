import { runInNewContext } from 'node:vm'
import { webcrypto } from 'node:crypto'
import { expect, it } from 'vitest'
import { RANDOM_UUID_POLYFILL } from '../src/browser-compat.js'

it('provides cryptographic UUIDs for LAN HTTP without replacing native implementations', () => {
  const crypto = { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) } as { getRandomValues: typeof webcrypto.getRandomValues; randomUUID?: () => string }
  runInNewContext(RANDOM_UUID_POLYFILL, { crypto })
  expect(crypto.randomUUID?.()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  expect(crypto.randomUUID?.()).not.toBe(crypto.randomUUID?.())
  const original = crypto.randomUUID
  runInNewContext(RANDOM_UUID_POLYFILL, { crypto })
  expect(crypto.randomUUID).toBe(original)
})
