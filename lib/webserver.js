// src/webserver.ts
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { Service } from "@deepseek-ai/cordis";
import z from "@deepseek-ai/schemastery";

// src/access-gate.ts
var PUBLIC_ROUTES = /* @__PURE__ */ new Set([
  "/auth/login",
  "/auth/v1/bootstrap/status",
  "/auth/v1/bootstrap/complete",
  "/auth/v1/login",
  "/auth/v1/health/live"
]);
var AccessGate = class {
  constructor(authenticator, options) {
    this.authenticator = authenticator;
    this.options = options;
  }
  authenticator;
  options;
  async evaluateHttp(request) {
    const pathname = readPathname(request);
    if (PUBLIC_ROUTES.has(pathname)) return { kind: "public" };
    const authenticated = await this.readPrincipal(request);
    if (authenticated === null) {
      if (isNavigation(request)) {
        const returnTo = `${pathname}${readSearch(request)}`;
        return { kind: "redirect", location: `/auth/login?returnTo=${encodeURIComponent(returnTo)}` };
      }
      return { kind: "deny", status: 401, code: "AUTH_REQUIRED" };
    }
    if (isStateChanging(request) && !this.originAllowed(request)) {
      return { kind: "deny", status: 403, code: "AUTH_ORIGIN_REJECTED" };
    }
    return { kind: "allow", ...authenticated };
  }
  async evaluateUpgrade(request) {
    const authenticated = await this.readPrincipal(request);
    if (authenticated === null) return { kind: "deny", status: 401, code: "AUTH_REQUIRED" };
    if (!this.originAllowed(request)) return { kind: "deny", status: 403, code: "AUTH_ORIGIN_REJECTED" };
    return { kind: "allow", ...authenticated };
  }
  async authenticateRequest(request) {
    return this.readPrincipal(request);
  }
  originAllowed(request) {
    return this.options.isTrustedOrigin?.(request) ?? isSameOrigin(request, true);
  }
  async readPrincipal(request) {
    const token = readUniqueCookie(request, this.options.sessionCookieName);
    if (token === null) return null;
    const principal = await this.authenticator.authenticate(token);
    return principal === null ? null : { principal, token };
  }
};
function readUniqueCookie(request, name) {
  const raw = request.headers.cookie;
  if (raw === void 0 || raw.length > 8192) return null;
  const values = [];
  for (const part of raw.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    const value = part.slice(separator + 1).trim();
    if (value.length < 1 || value.length > 256) return null;
    values.push(value);
  }
  return values.length === 1 ? values[0] ?? null : null;
}
function readPathname(request) {
  return new URL(request.url ?? "/", "http://dsh.local").pathname;
}
function readSearch(request) {
  return new URL(request.url ?? "/", "http://dsh.local").search;
}
function isNavigation(request) {
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  const destination = request.headers["sec-fetch-dest"];
  if (destination === "document") return true;
  return (request.headers.accept ?? "").split(",").some((value) => value.trim().startsWith("text/html"));
}
function isStateChanging(request) {
  return request.method !== "GET" && request.method !== "HEAD" && request.method !== "OPTIONS";
}
function isSameOrigin(request, originRequired = false) {
  const site = request.headers["sec-fetch-site"];
  if (site === "cross-site") return false;
  const origin = request.headers.origin;
  if (origin === void 0) return !originRequired;
  const host = request.headers.host;
  if (host === void 0) return false;
  try {
    const parsed = new URL(origin);
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.host === host;
  } catch {
    return false;
  }
}

// src/auth-page.ts
function renderAuthPage(nonce) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <title>DeepSeek Harness \xB7 \u5B89\u5168\u8BBF\u95EE</title>
  <style nonce="${nonce}">
    :root{--bg:#07111f;--bg2:#0b1c30;--card:rgba(12,25,43,.82);--card2:rgba(18,36,59,.72);--line:rgba(148,180,219,.18);--text:#f2f7ff;--muted:#9eb1c9;--brand:#4c8dff;--brand2:#6ed7ff;--success:#43d39e;--danger:#ff758c;--shadow:0 32px 90px rgba(0,0,0,.38);--input:rgba(6,17,31,.7)}
    [data-theme="light"]{--bg:#edf5ff;--bg2:#dceaff;--card:rgba(255,255,255,.9);--card2:rgba(245,249,255,.86);--line:rgba(49,91,145,.16);--text:#10233d;--muted:#60738c;--brand:#1769e0;--brand2:#0aa4d6;--success:#138b65;--danger:#d84260;--shadow:0 32px 90px rgba(38,74,123,.18);--input:rgba(240,246,255,.9)}
    *{box-sizing:border-box}[hidden]{display:none!important}html,body{min-height:100%;margin:0}body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(135deg,var(--bg),var(--bg2));color:var(--text);overflow-x:hidden}
    body:before,body:after{content:"";position:fixed;border-radius:50%;filter:blur(4px);pointer-events:none;opacity:.55;animation:float 12s ease-in-out infinite alternate}body:before{width:520px;height:520px;right:-160px;top:-210px;background:radial-gradient(circle,rgba(76,141,255,.42),transparent 68%)}body:after{width:460px;height:460px;left:-180px;bottom:-200px;background:radial-gradient(circle,rgba(52,215,196,.26),transparent 68%);animation-delay:-5s}
    .grid{position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);background-size:52px 52px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.6),transparent 86%);opacity:.25}
    .page{position:relative;z-index:1;min-height:100vh;display:grid;place-items:center;padding:32px}.shell{width:min(1160px,100%);min-height:690px;display:grid;grid-template-columns:1.06fr .94fr;border:1px solid var(--line);border-radius:30px;background:var(--card);box-shadow:var(--shadow);backdrop-filter:blur(22px);overflow:hidden;animation:enter .65s cubic-bezier(.2,.8,.2,1)}
    .story{position:relative;padding:54px;display:flex;flex-direction:column;justify-content:space-between;background:linear-gradient(155deg,rgba(69,128,244,.16),transparent 58%),var(--card2);border-right:1px solid var(--line)}.story:after{content:"";position:absolute;width:260px;height:260px;right:-70px;bottom:80px;border:1px solid rgba(102,187,255,.16);border-radius:42% 58% 52% 48%;animation:spin 26s linear infinite}
    .brand{display:flex;align-items:center;gap:13px;font-weight:750;letter-spacing:-.02em}.logo{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(145deg,var(--brand),var(--brand2));box-shadow:0 12px 30px rgba(48,132,245,.34)}.logo svg{width:24px;color:white}.eyebrow{display:inline-flex;align-items:center;gap:8px;margin:70px 0 18px;color:var(--brand2);font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.13em}.eyebrow i{width:7px;height:7px;border-radius:50%;background:var(--success);box-shadow:0 0 0 6px rgba(67,211,158,.11)}
    h1{max-width:580px;margin:0;font-size:clamp(32px,3.6vw,52px);line-height:1.08;letter-spacing:-.045em}.gradient{background:linear-gradient(110deg,var(--brand2),var(--brand));-webkit-background-clip:text;background-clip:text;color:transparent}.lead{max-width:520px;margin:24px 0 36px;color:var(--muted);font-size:17px;line-height:1.7}.features{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.feature{padding:16px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.025);transition:.25s ease}.feature:hover{transform:translateY(-2px);border-color:rgba(93,169,255,.36)}.feature b{display:block;margin-bottom:5px;font-size:14px}.feature span{color:var(--muted);font-size:12px;line-height:1.5}.foot{display:flex;gap:10px;align-items:center;color:var(--muted);font-size:12px}.pulse{width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 0 rgba(67,211,158,.5);animation:pulse 2s infinite}
    .panel{padding:42px 48px;display:flex;flex-direction:column}.toolbar{display:flex;justify-content:flex-end}.icon-btn{width:40px;height:40px;border:1px solid var(--line);border-radius:12px;background:transparent;color:var(--text);cursor:pointer;display:grid;place-items:center;transition:.2s}.icon-btn:hover{background:var(--card2);transform:rotate(7deg)}.icon-btn svg{width:19px}.form-wrap{width:min(430px,100%);margin:auto}.status{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid var(--line);border-radius:999px;background:var(--card2);color:var(--muted);font-size:12px}.status-dot{width:7px;height:7px;border-radius:50%;background:var(--brand2)}h2{margin:22px 0 9px;font-size:31px;letter-spacing:-.035em}.subtitle{margin:0 0 28px;color:var(--muted);font-size:14px;line-height:1.6}
    .steps{display:none;grid-template-columns:repeat(3,1fr);gap:7px;margin:0 0 25px}.steps.active{display:grid}.step{height:4px;border-radius:10px;background:var(--line);overflow:hidden}.step.on:after{content:"";display:block;width:100%;height:100%;background:linear-gradient(90deg,var(--brand),var(--brand2));animation:grow .5s ease}
    .field{margin:0 0 16px}.label-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}.field label{font-size:13px;font-weight:650}.hint{font-size:11px;color:var(--muted)}.input-wrap{position:relative}.input{width:100%;height:50px;border:1px solid var(--line);border-radius:14px;background:var(--input);color:var(--text);padding:0 15px;font:inherit;outline:none;transition:.2s}.input:focus{border-color:var(--brand);box-shadow:0 0 0 4px rgba(76,141,255,.12)}.input::placeholder{color:color-mix(in srgb,var(--muted) 68%,transparent)}.input.has-action{padding-right:48px}.reveal{position:absolute;right:5px;top:5px;width:40px;height:40px;border:0;border-radius:10px;background:transparent;color:var(--muted);cursor:pointer}.reveal:hover{background:var(--card2);color:var(--text)}
    .notice{display:none;margin:4px 0 16px;padding:12px 13px;border-radius:13px;border:1px solid rgba(255,117,140,.25);background:rgba(255,117,140,.08);color:var(--danger);font-size:13px;line-height:1.45}.notice.show{display:block;animation:shake .25s ease}.submit{width:100%;height:52px;border:0;border-radius:15px;background:linear-gradient(110deg,var(--brand),#6c67f5 62%,var(--brand2));color:#fff;font:700 15px inherit;cursor:pointer;box-shadow:0 14px 32px rgba(52,115,232,.28);transition:.22s;position:relative;overflow:hidden}.submit:hover{transform:translateY(-2px);box-shadow:0 18px 38px rgba(52,115,232,.35)}.submit:disabled{opacity:.7;cursor:wait;transform:none}.submit:after{content:"";position:absolute;inset:0;transform:translateX(-110%);background:linear-gradient(90deg,transparent,rgba(255,255,255,.22),transparent)}.submit:not(:disabled):hover:after{animation:shine .7s ease}.meta{display:flex;justify-content:center;align-items:center;gap:18px;margin-top:22px;color:var(--muted);font-size:11px}.meta span{display:flex;align-items:center;gap:6px}.meta svg{width:14px}.skeleton{height:265px;display:grid;place-items:center;color:var(--muted)}.spinner{width:34px;height:34px;border:3px solid var(--line);border-top-color:var(--brand);border-radius:50%;animation:spin 1s linear infinite;margin:auto auto 12px}
    @keyframes enter{from{opacity:0;transform:translateY(16px) scale(.99)}to{opacity:1;transform:none}}@keyframes float{to{transform:translate3d(20px,30px,0) scale(1.08)}}@keyframes spin{to{transform:rotate(360deg)}}@keyframes pulse{70%{box-shadow:0 0 0 9px rgba(67,211,158,0)}}@keyframes grow{from{width:0}}@keyframes shine{to{transform:translateX(110%)}}@keyframes shake{25%{transform:translateX(-3px)}75%{transform:translateX(3px)}}
    @media(max-width:860px){.page{padding:16px}.shell{grid-template-columns:1fr;min-height:0}.story{padding:30px;border-right:0;border-bottom:1px solid var(--line)}.story-main{display:none}.features{display:none}.foot{margin-top:22px}.panel{padding:28px 24px 38px}.toolbar{position:absolute;right:30px;top:26px}.form-wrap{margin:42px auto 0}}@media(max-width:480px){.page{padding:0}.shell{min-height:100vh;border:0;border-radius:0}.story{padding:22px 20px}.panel{padding:22px 20px 32px}.toolbar{right:20px;top:18px}h2{font-size:27px}}
    @media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
  </style>
</head>
<body>
  <div class="grid"></div>
  <main class="page">
    <section class="shell" aria-labelledby="auth-title">
      <aside class="story">
        <div>
          <div class="brand"><span class="logo"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 8.2 12 3l8 5.2v7.6L12 21l-8-5.2V8.2Z" stroke="currentColor" stroke-width="1.8"/><path d="m8.5 12 2.1 2.1 5-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span><span>DeepSeek Harness</span></div>
          <div class="story-main"><div class="eyebrow"><i></i>Identity protection layer</div><h1>DSH WEB \u8BA4\u8BC1\u63D2\u4EF6<br><span class="gradient">\u7EDF\u4E00\u5B88\u62A4\u8BBF\u95EE\u5165\u53E3\u3002</span></h1><p class="lead">\u8BA4\u8BC1\u53D1\u751F\u5728 Harness\u3001\u63D2\u4EF6\u8D44\u6E90\u3001RPC \u4E0E WebSocket \u4E4B\u524D\u3002\u672A\u7ECF\u6388\u6743\u7684\u8BF7\u6C42\u4E0D\u4F1A\u89E6\u8FBE\u5DE5\u4F5C\u533A\u6216\u4F1A\u8BDD\u6570\u636E\u3002</p><div class="features"><div class="feature"><b>\u670D\u52A1\u5668\u7AEF\u4F1A\u8BDD</b><span>Opaque token \u53EF\u64A4\u9500\uFF0C\u4E0D\u5199\u5165\u6D4F\u89C8\u5668\u5B58\u50A8\u3002</span></div><div class="feature"><b>\u5168\u94FE\u8DEF\u95E8\u7981</b><span>HTTP\u3001RPC \u4E0E\u5B9E\u65F6\u8FDE\u63A5\u7EDF\u4E00\u6821\u9A8C\u3002</span></div><div class="feature"><b>\u9ED8\u8BA4\u9501\u5B9A</b><span>\u672A\u521D\u59CB\u5316\u4E0E\u6545\u969C\u72B6\u6001\u7EDD\u4E0D\u533F\u540D\u653E\u884C\u3002</span></div><div class="feature"><b>\u5B89\u5168\u5BA1\u8BA1</b><span>\u5173\u952E\u8BA4\u8BC1\u4E8B\u4EF6\u5F62\u6210\u53EF\u8FFD\u6EAF\u8BB0\u5F55\u3002</span></div></div></div>
        </div>
        <div class="foot"><i class="pulse"></i><span>Authentication gateway is active</span></div>
      </aside>
      <section class="panel">
        <div class="toolbar"><button class="icon-btn" id="theme" type="button" aria-label="\u5207\u6362\u4E3B\u9898"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6 7 7m10 10 1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.8"/></svg></button></div>
        <div class="form-wrap">
          <div id="loading" class="skeleton"><div><div class="spinner"></div><span>\u6B63\u5728\u786E\u8BA4\u5B89\u5168\u72B6\u6001\u2026</span></div></div>
          <div id="content" hidden>
            <span class="status"><i class="status-dot"></i><span id="status-text">\u5B89\u5168\u8FDE\u63A5</span></span>
            <h2 id="auth-title">\u6B22\u8FCE\u56DE\u6765</h2><p class="subtitle" id="subtitle">\u9A8C\u8BC1\u8EAB\u4EFD\u540E\u7EE7\u7EED\u8FDB\u5165 Harness \u5DE5\u4F5C\u533A\u3002</p>
            <div class="steps" id="steps"><i class="step on"></i><i class="step on"></i><i class="step on"></i></div>
            <form id="form" novalidate>
              <div class="field setup-only"><div class="label-row"><label for="bootstrap">\u521D\u59CB\u5316\u4EE4\u724C</label><span class="hint">\u5BBF\u4E3B\u7EC8\u7AEF\u751F\u6210</span></div><input class="input" id="bootstrap" name="bootstrapToken" autocomplete="one-time-code" placeholder="\u7C98\u8D34\u4E00\u6B21\u6027\u4EE4\u724C"></div>
              <div class="field setup-only"><div class="label-row"><label for="displayName">\u663E\u793A\u540D\u79F0</label><span class="hint">1\u2013100 \u5B57\u7B26</span></div><input class="input" id="displayName" name="displayName" autocomplete="name" placeholder="\u4F8B\u5982\uFF1AHarness Owner"></div>
              <div class="field"><div class="label-row"><label for="username">\u7528\u6237\u540D</label><span class="hint setup-only">3\u201364 \u4F4D</span></div><input class="input" id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="\u8F93\u5165\u7528\u6237\u540D"></div>
              <div class="field"><div class="label-row"><label for="password">\u5BC6\u7801</label><span class="hint" id="caps" hidden>Caps Lock \u5DF2\u5F00\u542F</span></div><div class="input-wrap"><input class="input has-action" id="password" name="password" type="password" autocomplete="current-password" placeholder="\u81F3\u5C11 12 \u4E2A\u5B57\u7B26"><button class="reveal" id="reveal" type="button" aria-label="\u663E\u793A\u5BC6\u7801">\u663E\u793A</button></div></div>
              <div class="notice" id="notice" role="alert" aria-live="polite"></div>
              <button class="submit" id="submit" type="submit"><span id="submit-label">\u5B89\u5168\u767B\u5F55</span></button>
            </form>
            <div class="meta"><span><svg viewBox="0 0 24 24" fill="none"><path d="M7 11V8a5 5 0 0 1 10 0v3m-9 0h8a2 2 0 0 1 2 2v6H6v-6a2 2 0 0 1 2-2Z" stroke="currentColor" stroke-width="1.8"/></svg>HttpOnly Session</span><span><svg viewBox="0 0 24 24" fill="none"><path d="m5 12 4 4L19 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>Same-origin Protected</span></div>
          </div>
        </div>
      </section>
    </section>
  </main>
  <script nonce="${nonce}">
    (()=>{const $=id=>document.getElementById(id);const root=document.documentElement;const saved=localStorage.getItem('ui-theme.preference');const system=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';root.dataset.theme=saved==='light'||saved==='dark'?saved:system;$('theme').onclick=()=>{const next=root.dataset.theme==='dark'?'light':'dark';root.dataset.theme=next;localStorage.setItem('ui-theme.preference',next)};let state='ready',csrf='';const showError=value=>{const n=$('notice');n.textContent=value;n.classList.add('show')};const clearError=()=>{$('notice').classList.remove('show')};const messages={AUTH_INVALID_CREDENTIALS:'\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF',AUTH_BOOTSTRAP_INVALID:'\u521D\u59CB\u5316\u4EE4\u724C\u65E0\u6548\u6216\u5DF2\u8FC7\u671F',AUTH_INVALID_INPUT:'\u8BF7\u68C0\u67E5\u7528\u6237\u540D\u3001\u663E\u793A\u540D\u79F0\u4E0E\u5BC6\u7801\u5F3A\u5EA6',AUTH_ALREADY_INITIALIZED:'\u7CFB\u7EDF\u5DF2\u521D\u59CB\u5316\uFF0C\u8BF7\u5237\u65B0\u540E\u767B\u5F55',AUTH_CSRF_REJECTED:'\u5B89\u5168\u6821\u9A8C\u5931\u8D25\uFF0C\u8BF7\u5237\u65B0\u9875\u9762\u91CD\u8BD5',AUTH_ORIGIN_REJECTED:'\u8BF7\u6C42\u6765\u6E90\u4E0D\u53D7\u4FE1\u4EFB'};async function status(){const response=await fetch('/auth/v1/bootstrap/status',{headers:{accept:'application/json'}});if(!response.ok)throw new Error('\u5B89\u5168\u72B6\u6001\u6682\u4E0D\u53EF\u7528');const body=await response.json();state=body.state;csrf=body.csrfToken;const setup=state==='uninitialized_locked';document.querySelectorAll('.setup-only').forEach(node=>node.hidden=!setup);$('steps').classList.toggle('active',setup);$('auth-title').textContent=setup?'\u521D\u59CB\u5316\u5B89\u5168\u7BA1\u7406\u5458':'\u6B22\u8FCE\u56DE\u6765';$('subtitle').textContent=setup?'\u4F7F\u7528\u5BBF\u4E3B\u7EC8\u7AEF\u4E2D\u7684\u4E00\u6B21\u6027\u4EE4\u724C\uFF0C\u521B\u5EFA\u9996\u4F4D\u8D85\u7EA7\u7BA1\u7406\u5458\u3002':'\u9A8C\u8BC1\u8EAB\u4EFD\u540E\u7EE7\u7EED\u8FDB\u5165 Harness \u5DE5\u4F5C\u533A\u3002';$('status-text').textContent=setup?'\u9996\u6B21\u5B89\u5168\u521D\u59CB\u5316':'\u8EAB\u4EFD\u7F51\u5173\u5DF2\u5C31\u7EEA';$('submit-label').textContent=setup?'\u5B8C\u6210\u521D\u59CB\u5316\u5E76\u8FDB\u5165':'\u5B89\u5168\u767B\u5F55';$('password').autocomplete=setup?'new-password':'current-password';$('loading').hidden=true;$('content').hidden=false;$('username').focus()}$('reveal').onclick=()=>{const input=$('password');const visible=input.type==='text';input.type=visible?'password':'text';$('reveal').textContent=visible?'\u663E\u793A':'\u9690\u85CF';$('reveal').setAttribute('aria-label',visible?'\u663E\u793A\u5BC6\u7801':'\u9690\u85CF\u5BC6\u7801')};$('password').addEventListener('keyup',event=>{$('caps').hidden=!event.getModifierState('CapsLock')});$('form').addEventListener('submit',async event=>{event.preventDefault();clearError();const submit=$('submit');submit.disabled=true;const original=$('submit-label').textContent;$('submit-label').textContent=state==='ready'?'\u6B63\u5728\u9A8C\u8BC1\u2026':'\u6B63\u5728\u5EFA\u7ACB\u5B89\u5168\u7A7A\u95F4\u2026';try{const form=new FormData(event.currentTarget);const payload={username:String(form.get('username')||''),password:String(form.get('password')||'')};if(state!=='ready'){payload.bootstrapToken=String(form.get('bootstrapToken')||'');payload.displayName=String(form.get('displayName')||'')}const endpoint=state==='ready'?'/auth/v1/login':'/auth/v1/bootstrap/complete';const response=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json','x-dsh-csrf':csrf},body:JSON.stringify(payload)});const body=await response.json();if(!response.ok||!body.ok)throw new Error(messages[body.error?.code]||body.error?.message||'\u64CD\u4F5C\u672A\u5B8C\u6210\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5');$('submit-label').textContent='\u9A8C\u8BC1\u6210\u529F\uFF0C\u6B63\u5728\u8FDB\u5165\u2026';const requested=new URLSearchParams(location.search).get('returnTo');let target='/';if(requested){const parsed=new URL(requested,location.origin);if(parsed.origin===location.origin&&requested.startsWith('/')&&!requested.startsWith('//'))target=parsed.pathname+parsed.search+parsed.hash}location.assign(target)}catch(error){showError(error instanceof Error?error.message:'\u64CD\u4F5C\u672A\u5B8C\u6210');$('submit-label').textContent=original;submit.disabled=false}});status().catch(error=>{const loading=$('loading');loading.textContent='';const title=document.createElement('strong');title.textContent='\u5B89\u5168\u670D\u52A1\u6682\u4E0D\u53EF\u7528';const detail=document.createElement('p');detail.textContent=String(error instanceof Error?error.message:error);loading.append(title,detail)})})();
  </script>
</body>
</html>`;
}

// src/principal-context.ts
import { AsyncLocalStorage } from "node:async_hooks";
var PrincipalContext = class {
  storage = new AsyncLocalStorage();
  run(principal, operation) {
    return this.storage.run(principal, operation);
  }
  current() {
    return this.storage.getStore();
  }
  require() {
    const principal = this.current();
    if (principal === void 0) throw new Error("authenticated principal context is unavailable");
    return principal;
  }
};
var principalContext = new PrincipalContext();

// src/rate-limiter.ts
var FailureRateLimiter = class {
  constructor(policy, now = Date.now) {
    this.policy = policy;
    this.now = now;
    assertPolicy(policy);
  }
  policy;
  now;
  buckets = /* @__PURE__ */ new Map();
  check(key) {
    const now = this.now();
    const candidates = this.keys(key).map(([bucketKey, policy]) => ({ bucketKey, policy, bucket: this.readBucket(bucketKey, now) }));
    const retryAfterMs = candidates.reduce((maximum, candidate) => candidate.bucket === void 0 ? maximum : Math.max(maximum, candidate.bucket.blockedUntil - now), 0);
    return retryAfterMs > 0 ? { allowed: false, retryAfterMs } : { allowed: true };
  }
  recordFailure(key) {
    const now = this.now();
    for (const [bucketKey, policy] of this.keys(key)) {
      const bucket = this.readBucket(bucketKey, now) ?? { failures: [], blockedUntil: 0, lastSeenAt: now };
      bucket.failures.push(now);
      bucket.lastSeenAt = now;
      const failures = bucket.failures.length;
      if (failures >= policy.freeAttempts) {
        const exponent = Math.max(0, failures - policy.freeAttempts);
        const delay = Math.min(this.policy.maxDelayMs, this.policy.baseDelayMs * 2 ** exponent);
        bucket.blockedUntil = Math.max(bucket.blockedUntil, now + delay);
      }
      if (failures >= policy.hardLimit) bucket.blockedUntil = Math.max(bucket.blockedUntil, now + this.policy.maxDelayMs);
      this.buckets.delete(bucketKey);
      this.buckets.set(bucketKey, bucket);
    }
    this.prune(now);
  }
  recordSuccess(key) {
    this.buckets.delete(`account:${key.account}`);
    this.buckets.delete(`pair:${key.account}\0${key.source}`);
  }
  keys(key) {
    return [
      [`account:${key.account}`, this.policy.account],
      [`source:${key.source}`, this.policy.source],
      [`pair:${key.account}\0${key.source}`, this.policy.pair]
    ];
  }
  readBucket(key, now) {
    const bucket = this.buckets.get(key);
    if (bucket === void 0) return void 0;
    bucket.failures = bucket.failures.filter((timestamp) => now - timestamp <= this.policy.windowMs);
    if (bucket.failures.length === 0 && bucket.blockedUntil <= now) {
      this.buckets.delete(key);
      return void 0;
    }
    return bucket;
  }
  prune(now) {
    for (const key of this.buckets.keys()) this.readBucket(key, now);
    while (this.buckets.size > this.policy.maxBuckets) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === void 0) break;
      this.buckets.delete(oldest);
    }
  }
};
function assertPolicy(policy) {
  for (const [name, value] of Object.entries({
    windowMs: policy.windowMs,
    baseDelayMs: policy.baseDelayMs,
    maxDelayMs: policy.maxDelayMs,
    maxBuckets: policy.maxBuckets
  })) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive safe integer`);
  }
  for (const [name, value] of Object.entries({ account: policy.account, source: policy.source, pair: policy.pair })) {
    if (!Number.isSafeInteger(value.freeAttempts) || value.freeAttempts < 1) throw new Error(`${name}.freeAttempts must be positive`);
    if (!Number.isSafeInteger(value.hardLimit) || value.hardLimit < value.freeAttempts) throw new Error(`${name}.hardLimit must be at least freeAttempts`);
  }
}

// src/request-trust.ts
function assertTrustedAuthority(entry) {
  const parsed = parseAuthority(entry);
  if (parsed !== void 0 && canonicalAuthority(entry, parsed) === entry.toLowerCase()) return;
  throw new Error(`ds-auths-plugin: trustedHosts entry ${JSON.stringify(entry)} is not a bare host[:port] authority`);
}
function isTrustedRequest(request, trustedHosts) {
  const host = header(request.headers, "host");
  if (host === void 0) return false;
  const hostUrl = parseAuthority(host);
  if (hostUrl === void 0) return false;
  if (!isLoopbackHostname(hostUrl.hostname) && !matchesTrustedAuthority(hostUrl, trustedHosts)) return false;
  if (header(request.headers, "sec-fetch-site") === "cross-site") return false;
  const origin = header(request.headers, "origin");
  if (origin === void 0) return true;
  const originUrl = parseOrigin(origin);
  return originUrl !== void 0 && (originUrl.host === hostUrl.host || matchesTrustedAuthority(originUrl, trustedHosts));
}
function hasTrustedOrigin(request, trustedHosts) {
  if (header(request.headers, "sec-fetch-site") === "cross-site") return false;
  const host = header(request.headers, "host");
  const origin = header(request.headers, "origin");
  if (host === void 0 || origin === void 0) return false;
  const hostUrl = parseAuthority(host);
  const originUrl = parseOrigin(origin);
  if (hostUrl === void 0 || originUrl === void 0) return false;
  return originUrl.host === hostUrl.host || matchesTrustedAuthority(originUrl, trustedHosts);
}
function parseOrigin(origin) {
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed : void 0;
  } catch {
    return void 0;
  }
}
function header(headers, name) {
  if (headers instanceof Headers) return headers.get(name) ?? void 0;
  const value = headers[name];
  return typeof value === "string" ? value : void 0;
}
function parseAuthority(authority) {
  try {
    return new URL(`http://${authority}`);
  } catch {
    return void 0;
  }
}
function canonicalAuthority(entry, parsed) {
  const port = parsed.port !== "" ? parsed.port : new URL(`https://${entry}`).port;
  return port === "" ? parsed.hostname : `${parsed.hostname}:${port}`;
}
function matchesTrustedAuthority(host, trustedHosts) {
  return trustedHosts.some((entry) => {
    const parsed = parseAuthority(entry);
    if (parsed === void 0) return false;
    return canonicalAuthority(entry, parsed) === parsed.hostname ? parsed.hostname === host.hostname : parsed.host === host.host;
  });
}
function isLoopbackHostname(hostname) {
  if (hostname === "localhost" || hostname === "[::1]") return true;
  const parts = hostname.split(".");
  return parts.length === 4 && parts[0] === "127" && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

// src/webserver.ts
var HttpProblem = class extends Error {
  retryAfterSeconds;
  constructor(status, code, message, retryAfterSeconds) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
  status;
  code;
};
var MAX_AUTH_BODY_BYTES = 64 * 1024;
var AuthAwareWebServer = class extends Service {
  constructor(ctx, config) {
    super(ctx, "webServer");
    this.config = config;
    for (const authority of config.trustedHosts) assertTrustedAuthority(authority);
    this.cookiePolicy = createCookiePolicy(config);
    this.gate = new AccessGate(ctx.authGateway, {
      sessionCookieName: this.cookiePolicy.sessionName,
      isTrustedOrigin: (request) => hasTrustedOrigin(request, this.config.trustedHosts)
    });
  }
  config;
  static inject = ["authGateway"];
  static Config = z.object({
    host: z.union([z.const("127.0.0.1"), z.const("0.0.0.0")]).required(),
    port: z.natural().max(65535).required(),
    cookieSecure: z.union([z.const("auto"), z.const("required"), z.const("development")]).default("auto"),
    trustedHosts: z.array(z.string()).default([])
  });
  exact = /* @__PURE__ */ new Map();
  prefixes = /* @__PURE__ */ new Map();
  upgrades = /* @__PURE__ */ new Map();
  upgradedSockets = /* @__PURE__ */ new Set();
  socketsBySession = /* @__PURE__ */ new Map();
  indexTaps = [];
  cookiePolicy;
  gate;
  loginLimiter = new FailureRateLimiter({
    windowMs: 15 * 6e4,
    account: { freeAttempts: 5, hardLimit: 12 },
    source: { freeAttempts: 20, hardLimit: 60 },
    pair: { freeAttempts: 5, hardLimit: 10 },
    baseDelayMs: 1e3,
    maxDelayMs: 5 * 6e4,
    maxBuckets: 1e4
  });
  bootstrapLimiter = new FailureRateLimiter({
    windowMs: 15 * 6e4,
    account: { freeAttempts: 3, hardLimit: 8 },
    source: { freeAttempts: 8, hardLimit: 20 },
    pair: { freeAttempts: 3, hardLimit: 6 },
    baseDelayMs: 2e3,
    maxDelayMs: 10 * 6e4,
    maxBuckets: 2e3
  });
  fallback;
  server;
  listenedPort;
  get port() {
    return this.listenedPort;
  }
  get host() {
    return this.config.host;
  }
  register(route) {
    assertRoutePath(route.path, route.kind === "prefix");
    const table = route.kind === "exact" ? this.exact : this.prefixes;
    if (table.has(route.path)) throw new Error(`webserver: duplicate ${route.kind} route "${route.path}"`);
    table.set(route.path, route);
    return () => {
      table.delete(route.path);
    };
  }
  registerUpgrade(route) {
    assertRoutePath(route.path, false);
    if (this.upgrades.has(route.path)) throw new Error(`webserver: duplicate upgrade route "${route.path}"`);
    this.upgrades.set(route.path, route);
    return () => {
      this.upgrades.delete(route.path);
    };
  }
  registerFallback(handler) {
    if (this.fallback !== void 0) throw new Error("webserver: fallback already registered");
    this.fallback = handler;
    return () => {
      this.fallback = void 0;
    };
  }
  tapIndex(transform) {
    this.indexTaps.push(transform);
    return () => {
      const index = this.indexTaps.indexOf(transform);
      if (index !== -1) this.indexTaps.splice(index, 1);
    };
  }
  applyIndexTaps(html) {
    return this.indexTaps.reduce((output, transform) => transform(output), html);
  }
  async [Service.init]() {
    this.ctx.effect(() => this.ctx.authGateway.onSessionRevoked((sessionId) => {
      const sockets = this.socketsBySession.get(sessionId);
      if (sockets === void 0) return;
      for (const socket of sockets) socket.destroy();
      this.socketsBySession.delete(sessionId);
    }), "authAwareWebServer.sessionRevocation");
    this.server = createServer((request, response) => {
      this.handle(request, response).catch((error) => {
        this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
        if (response.headersSent) {
          response.destroy();
          return;
        }
        this.sendProblem(response, error);
      });
    });
    this.server.on("upgrade", (request, socket, head) => {
      void this.handleUpgrade(request, socket, head);
    });
    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.config.port, this.config.host, () => {
        this.server.off("error", reject);
        this.server.on("error", (error) => {
          this.ctx.logger.error(error);
        });
        this.listenedPort = this.server.address().port;
        resolve();
      });
    });
    this.ctx.effect(() => async () => {
      const serverClosed = new Promise((resolve) => {
        this.server.close(() => {
          resolve();
        });
      });
      this.server.closeAllConnections();
      const upgradedClosed = [...this.upgradedSockets].map((socket) => new Promise((resolve) => {
        socket.once("close", () => {
          resolve();
        });
        socket.destroy();
      }));
      await Promise.all([serverClosed, ...upgradedClosed]);
    }, "authAwareWebServer.listen");
  }
  async handle(request, response) {
    const requestId = randomUUID();
    response.setHeader("x-request-id", requestId);
    if (!isTrustedRequest(request, this.config.trustedHosts)) {
      sendJson(response, 403, failureBody("AUTH_AUTHORITY_REJECTED", requestId, "\u8BF7\u6C42\u5730\u5740\u6216\u6765\u6E90\u4E0D\u53D7\u4FE1\u4EFB"));
      return;
    }
    const decision = await this.gate.evaluateHttp(request);
    if (decision.kind === "redirect") {
      applySecurityHeaders(response);
      response.writeHead(302, { location: decision.location, "cache-control": "no-store" });
      response.end();
      return;
    }
    if (decision.kind === "deny") {
      sendJson(response, decision.status, failureBody(decision.code, requestId));
      return;
    }
    if (decision.kind === "public") {
      if (await this.handleAuthRoute(request, response, null)) return;
      sendJson(response, 404, failureBody("NOT_FOUND", requestId));
      return;
    }
    await principalContext.run(decision.principal, async () => {
      if (await this.handleAuthRoute(request, response, decision.token)) return;
      const pathname = readPathname2(request);
      if (pathname === "/auth" || pathname.startsWith("/auth/")) {
        sendJson(response, 404, failureBody("NOT_FOUND", requestId));
        return;
      }
      const route = this.match(pathname);
      if (route !== void 0) {
        await route.handler(request, response);
        return;
      }
      if (this.fallback === void 0) {
        response.writeHead(404);
        response.end();
        return;
      }
      await this.fallback(request, response);
    });
  }
  async handleAuthRoute(request, response, sessionToken) {
    const pathname = readPathname2(request);
    if (pathname === "/auth/login") {
      if (request.method !== "GET" && request.method !== "HEAD") throw new HttpProblem(405, "METHOD_NOT_ALLOWED", "\u4EC5\u652F\u6301 GET");
      const authenticated = sessionToken !== null || await this.gate.authenticateRequest(request) !== null;
      if (authenticated) {
        applySecurityHeaders(response);
        response.writeHead(302, { location: safeReturnTo(request), "cache-control": "no-store" });
        response.end();
        return true;
      }
      const nonce = randomBytes(18).toString("base64");
      applySecurityHeaders(response, nonce);
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      response.end(request.method === "HEAD" ? void 0 : renderAuthPage(nonce));
      return true;
    }
    if (pathname === "/auth/v1/health/live") {
      requireMethod(request, ["GET", "HEAD"]);
      sendJson(response, 200, { ok: true, status: "live" }, request.method === "HEAD");
      return true;
    }
    if (pathname === "/auth/v1/bootstrap/status") {
      requireMethod(request, ["GET", "HEAD"]);
      const csrfToken = this.readOrIssuePreAuthCsrf(request);
      response.setHeader("set-cookie", serializeCookie(this.cookiePolicy.preAuthCsrfName, csrfToken, this.cookiePolicy, { httpOnly: true }));
      sendJson(response, 200, { ...this.ctx.authGateway.getStatus(), csrfToken }, request.method === "HEAD");
      return true;
    }
    if (pathname === "/auth/v1/bootstrap/complete") {
      requireMethod(request, ["POST"]);
      this.requirePublicWriteProtection(request);
      const body = await readJsonBody(request);
      const key = authAttemptKey(request, readString(body, "username"));
      this.requireRateLimit(this.bootstrapLimiter, key);
      try {
        const session = await this.ctx.authGateway.bootstrap({
          bootstrapToken: readString(body, "bootstrapToken"),
          username: readString(body, "username"),
          displayName: readString(body, "displayName"),
          password: readString(body, "password")
        });
        this.bootstrapLimiter.recordSuccess(key);
        this.setSessionCookies(response, session.token, session.csrfToken, session.absoluteExpiresAt);
        sendJson(response, 201, { ok: true, principal: publicPrincipal(session.principal) });
      } catch (error) {
        if (shouldCountAuthFailure(error)) this.bootstrapLimiter.recordFailure(key);
        throw error;
      }
      return true;
    }
    if (pathname === "/auth/v1/login") {
      requireMethod(request, ["POST"]);
      this.requirePublicWriteProtection(request);
      const body = await readJsonBody(request);
      const key = authAttemptKey(request, readString(body, "username"));
      this.requireRateLimit(this.loginLimiter, key);
      try {
        const session = await this.ctx.authGateway.login({
          username: readString(body, "username"),
          password: readString(body, "password")
        });
        this.loginLimiter.recordSuccess(key);
        this.setSessionCookies(response, session.token, session.csrfToken, session.absoluteExpiresAt);
        sendJson(response, 200, { ok: true, principal: publicPrincipal(session.principal) });
      } catch (error) {
        if (shouldCountAuthFailure(error)) this.loginLimiter.recordFailure(key);
        throw error;
      }
      return true;
    }
    if (pathname === "/auth/v1/session") {
      requireMethod(request, ["GET", "HEAD"]);
      if (sessionToken === null) throw new HttpProblem(401, "AUTH_REQUIRED", "\u9700\u8981\u767B\u5F55");
      const principal = principalContext.require();
      const csrfToken = readUniqueCookie(request, this.cookiePolicy.csrfName);
      sendJson(response, 200, {
        ok: true,
        principal: publicPrincipal(principal),
        csrfToken
      }, request.method === "HEAD");
      return true;
    }
    if (pathname === "/auth/v1/logout") {
      requireMethod(request, ["POST"]);
      if (sessionToken === null) throw new HttpProblem(401, "AUTH_REQUIRED", "\u9700\u8981\u767B\u5F55");
      const csrf = request.headers["x-dsh-csrf"];
      const cookieCsrf = readUniqueCookie(request, this.cookiePolicy.csrfName);
      if (typeof csrf !== "string" || cookieCsrf === null || !safeEqual(csrf, cookieCsrf) || !this.ctx.authGateway.verifyCsrf(sessionToken, csrf)) {
        throw new HttpProblem(403, "AUTH_CSRF_REJECTED", "\u5B89\u5168\u6821\u9A8C\u5931\u8D25");
      }
      await this.ctx.authGateway.logout(sessionToken);
      this.clearSessionCookies(response);
      sendJson(response, 200, { ok: true });
      return true;
    }
    return false;
  }
  requireRateLimit(limiter, key) {
    const decision = limiter.check(key);
    if (decision.allowed) return;
    const retryAfterSeconds = Math.ceil(decision.retryAfterMs / 1e3);
    throw new HttpProblem(429, "AUTH_RATE_LIMITED", `\u5C1D\u8BD5\u6B21\u6570\u8FC7\u591A\uFF0C\u8BF7\u5728 ${String(retryAfterSeconds)} \u79D2\u540E\u91CD\u8BD5`, retryAfterSeconds);
  }
  requirePublicWriteProtection(request) {
    if (!hasTrustedOrigin(request, this.config.trustedHosts)) {
      throw new HttpProblem(403, "AUTH_ORIGIN_REJECTED", "\u8BF7\u6C42\u6765\u6E90\u4E0D\u53D7\u4FE1\u4EFB");
    }
    const headerToken = request.headers["x-dsh-csrf"];
    const cookieToken = readUniqueCookie(request, this.cookiePolicy.preAuthCsrfName);
    if (typeof headerToken !== "string" || cookieToken === null || !safeEqual(headerToken, cookieToken)) {
      throw new HttpProblem(403, "AUTH_CSRF_REJECTED", "\u5B89\u5168\u6821\u9A8C\u5931\u8D25");
    }
  }
  readOrIssuePreAuthCsrf(request) {
    const existing = readUniqueCookie(request, this.cookiePolicy.preAuthCsrfName);
    return existing !== null && existing.length === 43 ? existing : randomBytes(32).toString("base64url");
  }
  setSessionCookies(response, token, csrfToken, absoluteExpiresAt) {
    const maxAge = Math.max(1, Math.floor((absoluteExpiresAt - Date.now()) / 1e3));
    response.setHeader("set-cookie", [
      serializeCookie(this.cookiePolicy.sessionName, token, this.cookiePolicy, { httpOnly: true, maxAge }),
      serializeCookie(this.cookiePolicy.csrfName, csrfToken, this.cookiePolicy, { httpOnly: true, maxAge }),
      serializeCookie(this.cookiePolicy.preAuthCsrfName, "", this.cookiePolicy, { httpOnly: true, maxAge: 0 })
    ]);
  }
  clearSessionCookies(response) {
    response.setHeader("set-cookie", [
      serializeCookie(this.cookiePolicy.sessionName, "", this.cookiePolicy, { httpOnly: true, maxAge: 0 }),
      serializeCookie(this.cookiePolicy.csrfName, "", this.cookiePolicy, { httpOnly: true, maxAge: 0 })
    ]);
  }
  async handleUpgrade(request, socket, head) {
    const onError = (error) => {
      this.ctx.logger.warn(error);
      socket.destroy();
    };
    socket.on("error", onError);
    socket.once("close", () => {
      socket.off("error", onError);
      this.upgradedSockets.delete(socket);
    });
    try {
      if (!isTrustedRequest(request, this.config.trustedHosts)) {
        rejectUpgrade(socket, 403);
        return;
      }
      const decision = await this.gate.evaluateUpgrade(request);
      if (decision.kind !== "allow") {
        rejectUpgrade(socket, decision.kind === "deny" ? decision.status : 401);
        return;
      }
      const route = this.upgrades.get(readPathname2(request));
      if (route === void 0) {
        rejectUpgrade(socket, 404);
        return;
      }
      this.upgradedSockets.add(socket);
      let sessionSockets = this.socketsBySession.get(decision.principal.sessionId);
      if (sessionSockets === void 0) {
        sessionSockets = /* @__PURE__ */ new Set();
        this.socketsBySession.set(decision.principal.sessionId, sessionSockets);
      }
      sessionSockets.add(socket);
      socket.once("close", () => {
        sessionSockets.delete(socket);
        if (sessionSockets.size === 0) this.socketsBySession.delete(decision.principal.sessionId);
      });
      await principalContext.run(decision.principal, () => route.handler(request, socket, head));
    } catch (error) {
      this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
      socket.destroy();
    }
  }
  match(pathname) {
    const exact = this.exact.get(pathname);
    if (exact !== void 0) return exact;
    let best;
    for (const [prefix, route] of this.prefixes) {
      if (pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue;
      if (best === void 0 || prefix.length > best.path.length) best = route;
    }
    return best;
  }
  sendProblem(response, error) {
    const requestId = String(response.getHeader("x-request-id") ?? randomUUID());
    if (isAuthFailure(error)) {
      sendJson(response, error.status, failureBody(error.code, requestId, error.message));
      return;
    }
    if (error instanceof HttpProblem) {
      if (error.retryAfterSeconds !== void 0) response.setHeader("retry-after", String(error.retryAfterSeconds));
      sendJson(response, error.status, failureBody(error.code, requestId, error.message));
      return;
    }
    sendJson(response, 500, failureBody("AUTH_INTERNAL_ERROR", requestId, "\u8BA4\u8BC1\u670D\u52A1\u6682\u4E0D\u53EF\u7528"));
  }
};
function isAuthFailure(error) {
  if (!(error instanceof Error)) return false;
  const candidate = error;
  return typeof candidate.code === "string" && typeof candidate.status === "number";
}
function createCookiePolicy(config) {
  const secure = config.cookieSecure === "required" || config.cookieSecure === "auto" && (config.host !== "127.0.0.1" || config.trustedHosts.length > 0);
  return secure ? { sessionName: "__Host-dsh_auth", csrfName: "__Host-dsh_csrf", preAuthCsrfName: "__Host-dsh_pre_csrf", secure } : { sessionName: "dsh_auth_dev", csrfName: "dsh_csrf_dev", preAuthCsrfName: "dsh_pre_csrf_dev", secure };
}
function serializeCookie(name, value, policy, options) {
  const attributes = [`${name}=${value}`, "Path=/", "SameSite=Lax"];
  if (options.httpOnly) attributes.push("HttpOnly");
  if (policy.secure) attributes.push("Secure");
  if (options.maxAge !== void 0) attributes.push(`Max-Age=${String(options.maxAge)}`);
  return attributes.join("; ");
}
function applySecurityHeaders(response, nonce) {
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader("x-robots-tag", "noindex, nofollow");
  if (nonce !== void 0) {
    response.setHeader("content-security-policy", `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
  }
}
function sendJson(response, status, body, head = false) {
  applySecurityHeaders(response);
  response.setHeader("cache-control", "no-store");
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.writeHead(status);
  response.end(head ? void 0 : JSON.stringify(body));
}
function failureBody(code, requestId, message) {
  return { ok: false, error: { code, message: message ?? "\u9700\u8981\u767B\u5F55\u540E\u7EE7\u7EED", requestId } };
}
function publicPrincipal(principal) {
  return {
    userId: principal.userId,
    username: principal.username,
    displayName: principal.displayName,
    roles: principal.roles,
    permissions: [...principal.permissions]
  };
}
function requireMethod(request, allowed) {
  if (!allowed.includes(request.method ?? "GET")) throw new HttpProblem(405, "METHOD_NOT_ALLOWED", "\u8BF7\u6C42\u65B9\u6CD5\u4E0D\u53D7\u652F\u6301");
}
async function readJsonBody(request) {
  const mediaType = (request.headers["content-type"] ?? "").split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") throw new HttpProblem(415, "AUTH_MEDIA_TYPE_REQUIRED", "\u8BF7\u6C42\u5FC5\u987B\u4F7F\u7528 application/json");
  const declared = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > MAX_AUTH_BODY_BYTES) {
    throw new HttpProblem(413, "AUTH_BODY_TOO_LARGE", "\u8BF7\u6C42\u5185\u5BB9\u8FC7\u5927");
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_AUTH_BODY_BYTES) throw new HttpProblem(413, "AUTH_BODY_TOO_LARGE", "\u8BF7\u6C42\u5185\u5BB9\u8FC7\u5927");
    chunks.push(buffer);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("object required");
    return parsed;
  } catch {
    throw new HttpProblem(400, "AUTH_INVALID_JSON", "\u8BF7\u6C42\u5185\u5BB9\u4E0D\u662F\u6709\u6548 JSON");
  }
}
function readString(body, name) {
  const value = body[name];
  if (typeof value !== "string") throw new HttpProblem(400, "AUTH_INVALID_INPUT", "\u63D0\u4EA4\u7684\u4FE1\u606F\u4E0D\u5B8C\u6574");
  return value;
}
function authAttemptKey(request, username) {
  return {
    account: username.normalize("NFKC").trim().toLowerCase().slice(0, 128) || "<blank>",
    source: request.socket.remoteAddress ?? "<unknown>"
  };
}
function shouldCountAuthFailure(error) {
  if (!isAuthFailure(error)) return false;
  return error.code === "AUTH_INVALID_CREDENTIALS" || error.code === "AUTH_BOOTSTRAP_INVALID" || error.code === "AUTH_INVALID_INPUT";
}
function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
function readPathname2(request) {
  return new URL(request.url ?? "/", "http://dsh.local").pathname;
}
function safeReturnTo(request) {
  const requested = new URL(request.url ?? "/", "http://dsh.local").searchParams.get("returnTo");
  if (requested === null || !requested.startsWith("/") || requested.startsWith("//")) return "/";
  const parsed = new URL(requested, "http://dsh.local");
  if (parsed.origin !== "http://dsh.local" || parsed.pathname === "/auth/login") return "/";
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}
function assertRoutePath(path, allowEmptyPrefix) {
  if (path === "" && !allowEmptyPrefix || path !== "" && !path.startsWith("/") || path.length > 1 && path.endsWith("/")) {
    throw new Error(`webserver: invalid route path "${path}"`);
  }
  if (path === "/auth" || path.startsWith("/auth/")) {
    throw new Error(`webserver: reserved authentication route path "${path}"`);
  }
}
function rejectUpgrade(socket, status) {
  const reason = status === 403 ? "Forbidden" : status === 404 ? "Not Found" : "Unauthorized";
  socket.end(`HTTP/1.1 ${String(status)} ${reason}\r
Connection: close\r
Content-Length: 0\r
\r
`);
}
var webserver_default = AuthAwareWebServer;
export {
  AuthAwareWebServer,
  webserver_default as default
};
//# sourceMappingURL=webserver.js.map
