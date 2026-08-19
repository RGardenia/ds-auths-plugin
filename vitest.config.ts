import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['references/**', 'node_modules/**', 'lib/**'],
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
    restoreMocks: true,
  },
})
