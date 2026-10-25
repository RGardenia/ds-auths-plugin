# ds-auths-plugin

[![npm version](https://img.shields.io/npm/v/ds-auths-plugin)](https://www.npmjs.com/package/ds-auths-plugin)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

DeepSeek Harness Web 的身份认证网关。登录之前，浏览器无法加载 Harness 页面、插件脚本、工作区资源，也无法调用 RPC 或建立 WebSocket。首次启动需要一次性初始化令牌；认证服务故障时拒绝放行。

## 0.2.0 更新

- 适配 Harness `0.2.1-rc.3`，对照上游 `master` 的 `22ddee3792` 补齐资源路由、Peer 页面注入、`protocol` 与 `getOrigin()` 接口。
- 支持 IPv4、IPv6、`--host 0.0.0.0` / `::`、原生 TLS、`--public-url` 和 `--no-open`。
- 登录后通过 Harness 的公开认证接口在服务器内部完成原生认证衔接。原生 Cookie 不下发给浏览器，Harness 启动 token 也不能替代插件会话。
- 新增“账号与安全”页面：修改用户名、显示名称、密码，或退出登录。修改凭据要求当前密码和 CSRF 校验，会撤销全部旧会话、关闭其 WebSocket，并为当前浏览器签发新会话。
- 修复 HTTP 局域网的 Cookie 设置；为缺少 `crypto.randomUUID` 的浏览器补充基于 `crypto.getRandomValues` 的实现。
- 保留 SQLite 持久会话、服务端撤销、scrypt 密码哈希、登录限流和安全审计；本机访问同样要求登录。

## 安装与升级

需要 Node.js `^22.19.0 || >=24.0.0` 和 pnpm。此版本面向 Harness `>=0.2.1-rc.3 <0.3.0-0`，不再支持旧的 `0.1.x` 宿主。先升级 Harness，再安装插件；不要在仍运行旧宿主时直接替换认证插件。

```sh
# 全局安装的 Harness
npm install -g @deepseek-ai/dsh@next
dsh plugin --profile web add ds-auths-plugin@latest
dsh web --no-open
```

也可以始终通过 npx 使用对应宿主：

```sh
npx @deepseek-ai/dsh@next plugin --profile web add ds-auths-plugin@latest
npx @deepseek-ai/dsh@next web --no-open
```

升级插件请带 `@latest`，以更新 profile 中已固定的版本。插件通过 `dsh.bundle.patch` 自动挂载，无需重复传 `--patch`。更新后重启 Harness，检查启动日志，并在无痕窗口确认匿名访问会跳转到 `/auth/login`。超出兼容范围时 Harness 可能跳过 bundle，因此启动成功本身不代表认证已挂载。

现有 `auth/v1/auth.db` 会保留，账号和密码不用重建。旧版自动 Secure Cookie 的 HTTP 部署升级后需要重新登录；HTTPS 反向代理继续设置 `DSH_AUTH_COOKIE_SECURE=required`。

## 首次初始化

1. 启动时终端输出一次性令牌：`ds-auths-plugin is locked. Complete bootstrap with this one-time token: ...`。
2. 访问 Web 地址，进入初始化页。
3. 输入令牌、用户名、显示名称和密码，创建首位管理员。
4. 初始化成功后自动登录。其他浏览器使用该账号登录。

也可设置 `DSH_AUTH_BOOTSTRAP_TOKEN` 预设令牌。令牌默认有效期为 15 分钟，过期后重启可重新签发。用户名为 3–64 位，以小写字母或数字开头，允许字母、数字、点、下划线和连字符；密码为 12–128 个字符。

## 部署

### 指定局域网地址

```sh
dsh web --host 192.168.1.20 --port 3080 --no-open
```

具体绑定地址自动加入 Host 信任列表。使用通配监听时，显式声明浏览器访问的 IP 或域名：

```sh
dsh web --host 0.0.0.0 --trusted-host 192.168.1.20 --no-open
# IPv6 浏览器地址需方括号，例如 http://[fd00::20]:3080/
dsh web --host :: --trusted-host '[fd00::20]' --no-open
```

信任 Host 仅解决地址校验，不会绕过登录。支持规范 IPv4/IPv6 地址，不支持带 `%接口` 的 zone ID。

### 原生 HTTPS

```sh
dsh web --host 0.0.0.0 --trusted-host harness.example \
  --tls-cert ./cert.pem --tls-key ./key.pem \
  --public-url https://harness.example:3080/ --no-open
```

证书和私钥必须成对提供。证书不可读、为空或不匹配时启动失败，不会降级到 HTTP。TLS 监听始终使用 Secure Cookie。

### HTTPS 反向代理

```sh
DSH_AUTH_COOKIE_SECURE=required dsh web \
  --host 127.0.0.1 --trusted-host harness.example \
  --public-url https://harness.example/ --no-open
```

代理需保留浏览器的 `Host` / `Origin` 并支持 WebSocket。`--public-url` 只设置对外展示地址，不授予 Host 信任。目前支持站点根路径部署，不接受 `/harness/` 等路径前缀。HTTP 明文不提供传输加密；远程部署应使用 HTTPS 或受信网络。

## 账号管理

登录后的 Harness 页面右下角有“账号与安全”入口，也可以直接访问 `/auth/account`。保存修改时必须填写当前密码；新密码留空即保留原密码。旧会话全部被撤销，当前浏览器自动续签。

退出会在服务器端撤销当前会话并关闭其 WebSocket，不只是删除浏览器 Cookie。默认空闲超时 8 小时，绝对超时 24 小时。已经发起的普通 HTTP 请求不会因之后退出而回滚。

忘记密码时，可在停止 Harness 后备份并移走认证数据库，再重启重新初始化。这会清空插件账号、认证会话和认证审计，不删除 Harness 的工作区或对话数据。

## 配置

| 环境变量 | 默认值 | 作用 |
|---|---|---|
| `DSH_AUTH_DATABASE_PATH` | `$DSH_HOME/auth/v1/auth.db` | SQLite 数据库；未设 DSH_HOME 时使用 Harness 默认目录 |
| `DSH_AUTH_BOOTSTRAP_TOKEN` | 自动生成 | 首次初始化令牌 |
| `DSH_AUTH_HOST` | `--host` 或 `127.0.0.1` | 覆盖绑定地址，并同步到宿主启动配置 |
| `DSH_AUTH_PORT` | `--port` 或 `3080` | 覆盖监听端口，0 表示自动分配 |
| `DSH_AUTH_TRUSTED_HOSTS` | 空 | 逗号分隔，与 `--trusted-host` 合并 |
| `DSH_AUTH_COOKIE_SECURE` | `auto` | `auto` 随监听协议；`required` 用于 HTTPS 代理；`development` 允许 HTTP，原生 TLS 仍强制 Secure |

更细的会话时长、初始化令牌时长、scrypt 参数可通过 profile 的 `cordis.patch.yml` 覆盖 `dsh-auth` 配置，字段见 [AuthGateway Config](src/index.ts)。

## 接口与安全机制

| 方法 | 路径 | 访问要求 |
|---|---|---|
| GET | `/auth/login` | 公开登录 / 初始化页 |
| GET | `/auth/v1/health/live` | 公开存活检查 |
| GET | `/auth/v1/bootstrap/status` | 公开初始化状态和预认证 CSRF token |
| POST | `/auth/v1/bootstrap/complete` | 初始化令牌、同源与 CSRF |
| POST | `/auth/v1/login` | 账号密码、同源与 CSRF |
| GET | `/auth/account` | 插件会话 |
| GET | `/auth/v1/session` | 插件会话 |
| POST | `/auth/v1/account` | 插件会话、当前密码、同源与 CSRF |
| POST | `/auth/v1/logout` | 插件会话、同源与 CSRF |

除上述公开端点外，HTTP 和升级连接统一通过认证网关。会话及 CSRF token 在数据库中仅存 SHA-256 哈希；Cookie 使用 HttpOnly、SameSite=Lax、Path=/，TLS 或 required 模式使用 `__Host-` 前缀与 Secure。认证页面设置严格 CSP、禁止嵌框及缓存；账号密码不会写入浏览器存储。

密码使用 scrypt（默认 N=32768、r=8、p=1、32 字节输出）。未知账号同样执行密码哈希校验；失败按账号、来源、账号与来源组合进行限流，429 返回 `Retry-After`。不信任客户端提供的转发 IP 头。数据库目录和文件权限分别为 0700、0600。

本插件控制对整个 Harness 实例的访问，不提供不同账号之间的工作区隔离。本地能读写进程内存、配置或数据库的程序不在网络认证的防护范围内。版本兼容性和验证范围见 [兼容说明](docs/HARNESS_COMPATIBILITY.md)。

## 开发与验证

```sh
pnpm install
pnpm check                       # 类型检查、单元/HTTP/TLS 测试、构建
pnpm preview                     # 隔离 DSH_HOME 下启动真实 Harness
ORIGIN=http://127.0.0.1:34753 pnpm verify:preview
npm pack --dry-run               # 运行 prepack 并检查发布内容
```

TLS 测试需本机有 `openssl`。预览默认使用 `.local/dsh`，可以用 `DSH_HOME`、`HOST`、`PORT` 覆盖；验证脚本只应对测试实例执行，会初始化测试账号或登录该账号，再验证退出撤销。生产实例不要使用预览令牌或密码。

本地源码安装前先 `pnpm build`，再执行 `dsh plugin --profile web add ./`；修改源码后重新构建并重启。发布包含预构建的 `lib/`，无需用户本地编译。

## 参考与许可

本次更新参考 [dsh-web-startup-auth](https://github.com/GDWhisper/dsh-web-startup-auth) 的远程启动、原生认证衔接、账号管理和 HTTP 浏览器兼容思路，并对照 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的最新代码。

MIT。采用的上游页面注入渲染代码及其许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
