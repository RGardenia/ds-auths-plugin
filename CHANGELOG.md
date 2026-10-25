# Changelog

## 0.2.0 — 2026-10-25

- Adapt to Harness 0.2.1-rc.3 and current master WebServer resource/index interfaces.
- Replace the stale webRuntime trust dependency with webStartup configuration.
- Bridge native browser authentication server-side after revocable session admission; preserve combo-script query strings.
- Add remote IPv4/IPv6 startup, TLS, public-root URL and no-open flags.
- Add account management and logout, current-password/CSRF verification, atomic credential changes and revocation of old sessions and WebSockets.
- Fix Secure Cookie selection for HTTP LAN and TLS deployments; add a cryptographic randomUUID fallback for LAN HTTP browsers.
- Reject malformed Host/Origin authorities and retain explicit HTTPS port matching.
- Update the real Harness verification script, add compatibility/TLS/account tests and validate artifacts during prepack.

Upgrade the host first: this release requires Harness >=0.2.1-rc.3 and excludes 0.3.x. Existing authentication databases remain intact.
