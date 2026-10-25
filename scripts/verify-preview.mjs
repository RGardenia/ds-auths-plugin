const origin = (process.env.ORIGIN ?? 'http://127.0.0.1:34753').replace(/\/$/, '')
const bootstrapToken = process.env.DSH_AUTH_PREVIEW_TOKEN ?? 'preview-bootstrap-token-2026'
const username = process.env.DSH_AUTH_PREVIEW_USERNAME ?? 'preview-admin'
const displayName = process.env.DSH_AUTH_PREVIEW_DISPLAY_NAME ?? 'Preview Admin'
const password = process.env.DSH_AUTH_PREVIEW_PASSWORD ?? 'preview-password-2026'

const cookieHeader = response => response.headers
  .getSetCookie()
  .map(value => value.split(';', 1)[0])
  .join('; ')

const unauthenticated = await fetch(`${origin}/`, {
  headers: { accept: 'text/html' },
  redirect: 'manual',
})
if (unauthenticated.status !== 302 || !unauthenticated.headers.get('location')?.startsWith('/auth/login')) {
  throw new Error(`expected unauthenticated Harness navigation to redirect to login, got ${unauthenticated.status}`)
}

const statusResponse = await fetch(`${origin}/auth/v1/bootstrap/status`, {
  headers: { accept: 'application/json' },
})
if (!statusResponse.ok) throw new Error(`bootstrap status failed with ${statusResponse.status}`)
const status = await statusResponse.json()
const preAuthCookie = cookieHeader(statusResponse)

const endpoint = status.state === 'uninitialized_locked'
  ? '/auth/v1/bootstrap/complete'
  : '/auth/v1/login'
const payload = status.state === 'uninitialized_locked'
  ? { bootstrapToken, username, displayName, password }
  : { username, password }
const sessionResponse = await fetch(`${origin}${endpoint}`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    cookie: preAuthCookie,
    origin,
    'sec-fetch-site': 'same-origin',
    'x-dsh-csrf': status.csrfToken,
  },
  body: JSON.stringify(payload),
})
if (!sessionResponse.ok) {
  throw new Error(`authentication failed with ${sessionResponse.status}: ${await sessionResponse.text()}`)
}
const sessionCookie = cookieHeader(sessionResponse)
if (sessionResponse.headers.getSetCookie().some(value => value.startsWith('dsh-auth-'))) {
  throw new Error('native Harness authentication cookies must stay server-side')
}

const harnessResponse = await fetch(`${origin}/`, {
  headers: { accept: 'text/html', cookie: sessionCookie },
})
const html = await harnessResponse.text()
const result = {
  status: harnessResponse.status,
  hasHarnessBoot: html.includes('__DSH_BOOT__'),
  hasHarnessTitle: html.includes('<title>DeepSeek Harness</title>'),
  hasPlaceholder: html.includes('认证成功'),
}
console.log(JSON.stringify(result))
if (
  result.status !== 200
  || !result.hasHarnessBoot
  || !result.hasHarnessTitle
  || result.hasPlaceholder
) {
  throw new Error('authenticated root did not render the real DeepSeek Harness shell')
}

const scripts = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map(match => match[1].replaceAll('&amp;', '&'))
const combo = scripts.find(src => src.startsWith('plugins/??'))
if (!combo) throw new Error('Harness did not inject its plugin bootstrap script')
for (const src of scripts) {
  const url = new URL(src, `${origin}/`)
  if (url.origin !== origin) continue
  const response = await fetch(url, { headers: { cookie: sessionCookie } })
  if (!response.ok || !response.headers.get('content-type')?.includes('javascript')) {
    throw new Error(`Harness script ${url.pathname} failed: ${response.status}`)
  }
}
const deniedBundle = await fetch(new URL(combo, `${origin}/`))
if (deniedBundle.status !== 401) throw new Error(`anonymous plugin request returned ${deniedBundle.status}`)
// This exact unknown channel returns 404 only after Connection admits the request.
const admittedApi = await fetch(`${origin}/api/ds-auths-plugin-probe`, { headers: { cookie: sessionCookie } })
if (admittedApi.status !== 404) throw new Error(`authenticated API probe returned ${admittedApi.status}`)
const account = await fetch(`${origin}/auth/account`, { headers: { cookie: sessionCookie } })
if (!account.ok || !(await account.text()).includes('账号与安全')) throw new Error('account page unavailable')
const session = await (await fetch(`${origin}/auth/v1/session`, { headers: { cookie: sessionCookie } })).json()
const logout = await fetch(`${origin}/auth/v1/logout`, {
  method: 'POST', headers: { cookie: sessionCookie, origin, 'x-dsh-csrf': session.csrfToken },
})
if (!logout.ok) throw new Error('logout failed')
const revoked = await fetch(`${origin}/api/ds-auths-plugin-probe`, { headers: { cookie: sessionCookie } })
if (revoked.status !== 401) throw new Error('revoked session still reached the API')
console.log('Verified: private plugin scripts, authenticated API, account page, server-only native bridge, logout revocation')
