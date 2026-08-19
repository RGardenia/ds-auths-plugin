import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { delimiter, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const host = process.env.HOST ?? '0.0.0.0'
const port = Number(process.env.PORT ?? 34753)
const dshHome = process.env.DSH_HOME ?? join(root, '.local', 'dsh')
const dshEntry = process.env.DSH_ENTRY
  ?? join(root, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const runtimeNode = process.env.DSH_NODE ?? process.execPath
const profileManifest = join(dshHome, 'profiles', 'web', 'package.json')
const trustedHosts = (process.env.DSH_AUTH_TRUSTED_HOSTS ?? process.env.DSH_AUTH_PREVIEW_HOSTS ?? '')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean)

if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  throw new Error('PORT must be an integer between 1 and 65535')
}
if (host !== '127.0.0.1' && host !== '0.0.0.0') {
  throw new Error('HOST must be 127.0.0.1 or 0.0.0.0')
}
if (!existsSync(join(root, 'lib', 'index.js')) || !existsSync(join(root, 'lib', 'webserver.js'))) {
  throw new Error('Plugin is not built. Run pnpm build before previewing.')
}
if (!existsSync(dshEntry)) {
  throw new Error('DeepSeek Harness is not installed. Run pnpm install first.')
}
if (!existsSync(runtimeNode)) {
  throw new Error(`DSH_NODE does not exist: ${runtimeNode}`)
}
const runtimeVersion = spawnSync(runtimeNode, ['-p', 'process.versions.node'], { encoding: 'utf8' })
if (runtimeVersion.error) throw runtimeVersion.error
const [runtimeMajor = 0, runtimeMinor = 0] = runtimeVersion.stdout.trim().split('.').map(Number)
if (!((runtimeMajor === 22 && runtimeMinor >= 19) || runtimeMajor >= 24)) {
  throw new Error(`DeepSeek Harness requires Node 22.19+ or 24+; DSH_NODE is ${runtimeVersion.stdout.trim()}`)
}

mkdirSync(dshHome, { recursive: true })
const bootstrapToken = process.env.DSH_AUTH_BOOTSTRAP_TOKEN
  ?? process.env.DSH_AUTH_PREVIEW_TOKEN
  ?? (process.env.NODE_ENV === 'production' ? '' : 'preview-bootstrap-token-2026')
const env = {
  ...process.env,
  PATH: `${dirname(runtimeNode)}${delimiter}${process.env.PATH ?? ''}`,
  DSH_HOME: dshHome,
  DSH_AUTH_HOST: host,
  DSH_AUTH_PORT: String(port),
  DSH_AUTH_BOOTSTRAP_TOKEN: bootstrapToken,
  DSH_AUTH_DATABASE_PATH: process.env.DSH_AUTH_DATABASE_PATH
    ?? process.env.DSH_AUTH_PREVIEW_DB
    ?? join(dshHome, 'auth', 'v1', 'auth.db'),
  DSH_AUTH_COOKIE_SECURE: process.env.DSH_AUTH_COOKIE_SECURE ?? 'auto',
  DSH_AUTH_TRUSTED_HOSTS: trustedHosts.join(','),
}

let pluginInstalled = false
if (existsSync(profileManifest)) {
  const manifest = JSON.parse(readFileSync(profileManifest, 'utf8'))
  pluginInstalled = Boolean(
    manifest.dependencies?.['ds-auths-plugin']
    && manifest.dsh?.profile?.bundles?.includes('ds-auths-plugin'),
  )
}
if (!pluginInstalled) {
  const install = spawnSync(runtimeNode, [dshEntry, 'plugin', '--profile', 'web', 'add', root], {
    cwd: root,
    env,
    stdio: 'inherit',
  })
  if (install.error) throw install.error
  if (install.status !== 0) process.exit(install.status ?? 1)
}

const args = [dshEntry, 'web', '--port', String(port)]
if (trustedHosts.length > 0) args.push('--trusted-host', ...trustedHosts)
const harness = spawn(runtimeNode, args, {
  cwd: root,
  env,
  stdio: 'inherit',
})

const forward = signal => {
  if (!harness.killed) harness.kill(signal)
}
process.once('SIGINT', () => { forward('SIGINT') })
process.once('SIGTERM', () => { forward('SIGTERM') })
harness.once('error', error => { throw error })
harness.once('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal)
  else process.exit(code ?? 1)
})
