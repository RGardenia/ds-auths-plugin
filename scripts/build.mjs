import { build } from 'esbuild'
import { execFile } from 'node:child_process'
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { promisify } from 'node:util'

const external = ['@deepseek-ai/cordis', '@deepseek-ai/schemastery', '@deepseek-ai/dsh-cmdline', 'commander']
const exec = promisify(execFile)

await rm('lib', { recursive: true, force: true })
await mkdir('lib', { recursive: true })

await build({
  entryPoints: {
    index: 'src/index.ts',
    webserver: 'src/webserver.ts',
    startup: 'src/startup.ts',
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
for (const name of await readdir('lib')) {
  if (!name.endsWith('.d.ts')) continue
  const path = `lib/${name}`
  await writeFile(path, (await readFile(path, 'utf8')).replace(/[\t ]+$/gm, ''))
}

console.log('Built authentication, webserver, startup entries and TypeScript declarations')
