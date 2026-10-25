# Harness compatibility — ds-auths-plugin 0.2.0

## Baselines

- Runtime integration: `@deepseek-ai/dsh@0.2.1-rc.3` (npm `next`, checked 2026-10-25).
- Source inspection: `deepseek-ai/deepseek-harness` master `22ddee3792`.
- Reference: `GDWhisper/dsh-web-startup-auth` 0.1.13. The implementation keeps this plugin's SQLite sessions, bootstrap token and mandatory local authentication.
- Declared host range: `>=0.2.1-rc.3 <0.3.0-0`. The full master application was not built; its new resource and Peer interfaces are covered by contract tests. Each new Harness minor line needs a compatibility review before widening the range.

## Composition

The bundle disables the built-in `webserver`, replaces `web-startup`, installs `authGateway` and `AuthAwareWebServer`, and configures Connection from `webStartup.trustedHosts`. It does not reference the removed `webRuntime` service. A concrete bind IP joins the trusted authorities; wildcard binds require explicit remote authorities. All authorities still require authentication.

The replacement startup accepts the current flag family and passes TLS, public root URL, browser-open preference and trusted hosts to their owners. Root-path deployment is supported; subpath public URLs and zone-qualified IPv6 listeners fail explicitly.

## Native browser authentication

After the gateway admits its own session, it calls Connection's `authenticatedUrl()` and `authorizeIndex()` to exchange the process token using the real request Host. It captures the native cookie into the server-side request header only. Connection retains its own Host/Origin fence and verifies that native credential normally. There is no copy of upstream's cookie-signing format, no secret-file access, and no native authentication cookie sent to the browser.

A failed native exchange rejects the request. Anonymous requests, startup token URLs and native cookies alone never reach this bridge. Query strings remain byte-for-byte intact except for removing a root index's launch token; this preserves the revisioned `plugins/??...` bundle addresses. Logout and credential updates invalidate gateway sessions before later requests can receive a native credential.

## WebServer methods

The adapter supports exact/prefix handler routes, exact upgrade routes, a single handler/resource fallback, HTML taps, `protocol`, `getOrigin()`, `collectIndexInjections(peer?)`, `renderIndex(html, peer?)`, and master's `readResource(request, peer)` / resource routes. In-process resource reads rely on their caller to admit the Peer, as upstream does. Network resource requests always pass the session gate, preserve individual Set-Cookie headers, support HEAD and reject non-read methods, propagate disconnect cancellation and respect response backpressure.

The structured index renderer is copied under MIT from the inspected master (also present in rc.3). TLS listener teardown closes unfinished handshakes as well as upgraded connections. The adapter currently does not implement upstream's optional gzip compression; proxy compression can be configured separately.

## Verification

`pnpm check` covers bootstrap, persistence, password hashing, login limits, Host/Origin parsing, HTTP authentication, account changes, CSRF, revocation, WebSocket teardown, resource routes, Peer injection, CLI flags, HTTP cookies, TLS cookies and incomplete TLS handshake teardown. `pnpm verify:preview` exercises an actual installed Harness in an isolated DSH_HOME: bootstrap/login, real boot HTML, JavaScript assets and combo scripts, anonymous bundle rejection, admitted API route lookup, account page and logout/replay rejection.

A browser smoke test additionally checks that the actual Harness shell loads and the account page displays the authenticated principal. No external model API call is needed. Existing schema-v1 databases remain compatible; changing account credentials increments the existing auth_version field atomically and revokes previous sessions.
