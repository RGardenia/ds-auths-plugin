import { build } from 'esbuild'
import { execFile } from 'node:child_process'
import { mkdir, rm } from 'node:fs/promises'
import { promisify } from 'node:util'

const external = ['@deepseek-ai/cordis', '@deepseek-ai/schemastery']
const exec = promisify(execFile)

await rm('lib', { recursive: true, force: true })
await mkdir('lib', { recursive: true })

await build({
  entryPoints: {
    index: 'src/index.ts',
    webserver: 'src/webserver.ts',
  },
  bundle: true,
  splitting: false,
  format: 'esm',
  platform: 'node',
  target: 'node22.19',
  outdir: 'lib',
  sourcemap: true,
  external,
  logLevel: 'info',
})

await exec(process.execPath, ['./node_modules/typescript/bin/tsc', '-p', 'tsconfig.build.json'])

console.log('Built lib/index.js, lib/webserver.js and TypeScript declarations')
