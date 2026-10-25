/** A self-contained account page, behind the same gate as the Harness UI. */
export function renderAccountPage(nonce: string): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>账号与安全 · DeepSeek Harness</title><style nonce="${nonce}">
:root{font-family:system-ui,sans-serif;color-scheme:light dark;background:#f5f7fb;color:#182236}
*{box-sizing:border-box}body{margin:0;padding:32px 20px}main{max-width:560px;margin:24px auto;padding:32px;border:1px solid #dbe2ee;border-radius:20px;background:#fff}
h1{font-size:26px;margin:24px 0 10px}p{color:#64748b;line-height:1.7}a{color:#2563eb}label{display:block;font-size:14px;margin-top:20px}input,button{font:inherit;width:100%;padding:12px 14px;border-radius:10px;margin-top:8px;border:1px solid #cbd5e1}input{background:transparent;color:inherit}button{cursor:pointer;background:#2563eb;color:white;border-color:transparent;margin-top:24px}button:disabled{opacity:.6;cursor:wait}#logout{background:transparent;color:#c5304c;border-color:#cbd5e1}#notice{min-height:24px;color:#2563eb;line-height:1.6}[hidden]{display:none!important}
@media(prefers-color-scheme:dark){:root{background:#0f172a;color:#eef2ff}main{background:#172033;border-color:#334155}input,#logout{border-color:#475569}p{color:#a5b4cc}a,#notice{color:#7cb4ff}}
</style></head><body><main><a href="/">← 返回 Harness</a><h1>账号与安全</h1><p id="identity">正在读取账号…</p>
<form id="account" hidden><label for="username">用户名</label><input id="username" name="username" autocomplete="username" required minlength="3" maxlength="64">
<label for="displayName">显示名称</label><input id="displayName" name="displayName" autocomplete="name" required maxlength="100">
<label for="currentPassword">当前密码</label><input id="currentPassword" name="currentPassword" type="password" autocomplete="current-password" required>
<label for="password">新密码（不修改请留空）</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128">
<p>保存后，其他浏览器和现有实时连接会退出登录；当前浏览器保持登录。</p><button id="save">保存修改</button></form>
<button id="logout" type="button" hidden>退出登录</button><p id="notice" role="status" aria-live="polite"></p>
</main><script nonce="${nonce}">
(()=>{const $=id=>document.getElementById(id);let csrf='';const notice=text=>{$('notice').textContent=text};
async function send(path,body){const response=await fetch(path,{method:'POST',headers:{'content-type':'application/json','x-dsh-csrf':csrf},body:JSON.stringify(body)});const result=await response.json();if(!response.ok)throw new Error(result.error?.message||'操作失败');return result}
async function load(){const response=await fetch('/auth/v1/session');if(response.status===401){location.assign('/auth/login?returnTo=%2Fauth%2Faccount');return}if(!response.ok)throw new Error('账号暂不可用');const data=await response.json();csrf=data.csrfToken;$('identity').textContent='当前登录：'+data.principal.displayName;$('username').value=data.principal.username;$('displayName').value=data.principal.displayName;$('account').hidden=false;$('logout').hidden=false}
$('account').onsubmit=async event=>{event.preventDefault();$('save').disabled=true;notice('正在保存…');try{const body=Object.fromEntries(new FormData(event.currentTarget));if(body.password==='')delete body.password;await send('/auth/v1/account',body);$('currentPassword').value='';$('password').value='';await load();notice('已保存，其他会话已退出。')}catch(error){notice(error.message)}finally{$('save').disabled=false}};
$('logout').onclick=async()=>{$('logout').disabled=true;try{await send('/auth/v1/logout',{});location.assign('/auth/login')}catch(error){notice(error.message);$('logout').disabled=false}};load().catch(error=>notice(error.message))})();
</script></body></html>`
}
