# ds-auths-plugin

[![npm version](https://img.shields.io/npm/v/ds-auths-plugin)](https://www.npmjs.com/package/ds-auths-plugin)
[![npm downloads](https://img.shields.io/npm/dm/ds-auths-plugin)](https://www.npmjs.com/package/ds-auths-plugin)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%E2%89%A522.19%20%7C%20%3E%3D24-brightgreen)](https://nodejs.org)
[![GitHub stars](https://img.shields.io/github/stars/RGardenia/ds-auths-plugin)](https://github.com/RGardenia/ds-auths-plugin/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/RGardenia/ds-auths-plugin)](https://github.com/RGardenia/ds-auths-plugin/commits/main)

DeepSeek Harness Web 的身份认证网关插件（Cordis 组合包）。在首次完成初始化后，**未认证的浏览器无法加载 WebUI 的任何资源、调用任何接口或建立任何实时连接**——认证在 HTTP / 传输层强制执行，不可通过浏览器开发者工具绕过。

插件采取 fail-closed 策略：未初始化或认证服务故障时，一律拒绝放行，绝不匿名暴露工作区。

## 特性

- **全链路门禁**：WebUI 资源、插件 bundle、RPC 接口与 WebSocket 统一在网关处校验会话。
- **默认锁定**：首次启动进入 `uninitialized_locked` 状态，所有请求被拦截，需用一次性初始化令牌创建首位超级管理员。
- **服务器端会话**：Opaque token 存储于服务端数据库，可撤销、可超时，不写入浏览器存储。
- **scrypt 密码哈希**：Node 内置内存硬 KDF，抗 GPU/ASIC 爆破，零外部依赖。
- **登录限流**：按账号、来源、账号+来源三个维度做失败限流，并抹平账号枚举时序差异。
- **安全审计**：关键认证事件写入审计表，形成可追溯记录。
- **独立登录页**：自带深色/浅色自适应登录页，含严格 CSP、防嵌框与安全响应头。

## 架构

认证由两个 Cordis 服务组成，通过组合包补丁 [cordis.patch.yml](cordis.patch.yml) 挂载：

| 层 | 机制 | 未认证行为 |
|---|---|---|
| 认证服务 `AuthGateway` | 持有 SQLite 数据库，负责凭据、会话、限流与审计 | 状态锁定，拒绝登录 |
| Web 服务器 `AuthAwareWebServer` | 注册 `prefix ''` 兜底路由，校验会话后转交 `frontend-static` | 302 → 登录页 |
| RPC / 插件 bundle | 同一 Web 服务器兜底路由统一校验 | 401 / 302 |
| WebSocket 升级 | 升级握手前校验同一会话 | 403 拒绝升级 |

会话由 `HttpOnly; SameSite=Lax` Cookie 携带（`__Host-dsh_auth`），JS 无法读取；状态变更类请求额外校验 CSRF token 与同源来源。

## 安装

本插件是标准**组合包（bundle）**，推荐使用 DSH 官方 `plugin` 命令安装。前提：机器上有 pnpm（Node 自带 corepack，执行 `corepack enable pnpm` 即可启用）。

### 方式一：npm 安装（推荐）

```sh
npx @deepseek-ai/dsh plugin --profile web add ds-auths-plugin
```

从 npm registry 拉取预构建代码，加入依赖并追加到 `dsh.profile.bundles` 列表，补丁行随组合包层自动插入。

### 方式二：本地源码安装（开发）

在插件源码根目录执行：

```sh
npx @deepseek-ai/dsh plugin --profile web add ./
```

以 `link:` 方式安装，改代码 → 重启 DSH 即生效，无需重新安装。

### 通用步骤

安装完成后重启 DSH：

```sh
npx @deepseek-ai/dsh web
```

重启后插件生效，未初始化时所有请求会被拦截并跳转登录页。

## 首次初始化

未初始化时，插件处于 `uninitialized_locked` 状态，宿主日志会输出一次性初始化令牌：

```text
ds-auths-plugin is locked. Complete bootstrap with this one-time token: <token>
```

随后：

1. 访问任意路径，浏览器跳转到 `/auth/login`。
2. 登录页显示「初始化安全管理员」表单。
3. 填入一次性令牌、用户名、显示名称和密码。
4. 提交后创建首位超级管理员，并自动登录进入 Harness 界面。

也可以通过环境变量 `DSH_AUTH_BOOTSTRAP_TOKEN` 预设初始化令牌，避免从日志复制。

## 使用

- **首次启用**：按「首次初始化」创建账号后，认证立即生效。
- **用户名规则**：3–64 位，小写字母或数字开头，可含字母、数字、下划线、点、连字符。
- **密码规则**：12–128 个字符。
- **之后登录**：未登录访问任意路径 → 跳转登录页；登录后凭会话免登录。
- **会话有效期**：空闲超时默认 8 小时，绝对超时默认 24 小时，服务端按到期时间强制失效。
- **退出登录**：`POST /auth/v1/logout`（登录页未提供退出按钮，由宿主前端或其他客户端调用）。

## 配置

配置通过环境变量注入，前缀为 `DSH_AUTH_`：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `DSH_AUTH_DATABASE_PATH` | `dshHomePath('auth/v1/auth.db')` | 认证数据库（SQLite）路径，`:memory:` 表示内存数据库 |
| `DSH_AUTH_BOOTSTRAP_TOKEN` | 空（自动生成） | 首次初始化的一次性令牌 |
| `DSH_AUTH_HOST` | `webStartup.host` 或 `127.0.0.1` | Web 服务器监听地址 |
| `DSH_AUTH_PORT` | `webStartup.port` 或 `3080` | Web 服务器监听端口 |
| `DSH_AUTH_COOKIE_SECURE` | `auto` | `auto` / `required` / `development`，决定 Cookie `Secure` 标记 |
| `DSH_AUTH_TRUSTED_HOSTS` | 空（继承 `webStartup.trustedHosts`） | 额外信任的 `host[:port]` 列表，逗号分隔 |

> 生产环境请显式设置 `DSH_AUTH_BOOTSTRAP_TOKEN`，并配置 `DSH_AUTH_TRUSTED_HOSTS` 与 `DSH_AUTH_COOKIE_SECURE=required`，避免默认行为引入安全隐患。

## 认证接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/auth/login` | 登录页 / 初始化页 |
| GET | `/auth/v1/health/live` | 健康检查（公开） |
| GET | `/auth/v1/bootstrap/status` | 获取初始化状态与 CSRF token（公开） |
| POST | `/auth/v1/bootstrap/complete` | 完成初始化（公开） |
| POST | `/auth/v1/login` | 登录（公开） |
| GET | `/auth/v1/session` | 获取当前会话主体 |
| POST | `/auth/v1/logout` | 退出登录 |

公开端点（登录 / 初始化）本身是认证的必然入口；其余路径与升级连接均受门禁保护。

## 数据存储

凭据、会话、初始化令牌与审计日志统一存储在 SQLite 数据库（`DSH_AUTH_DATABASE_PATH`）中：

- `users`：用户与密码哈希（scrypt）。
- `auth_sessions`：会话令牌哈希、CSRF 哈希与超时时间。
- `bootstrap_tokens`：一次性初始化令牌。
- `audit_log`：认证审计事件。

数据库文件与目录权限分别收紧为 `0600` 与 `0700`。密码以 scrypt 哈希保存，明文不落盘。

## 安全设计

- **密码哈希**：scrypt（`N=32768, r=8, p=1, k=32`），验证失败时同样执行一次完整哈希，抹平「账号不存在 = 响应快」的用户名枚举时序差异。
- **登录限流**：15 分钟窗口内按账号、来源、账号+来源三层限流，失败累积后指数退避封禁。
- **CSRF 防护**：登录 / 初始化 / 退出等状态变更接口校验 `x-dsh-csrf` 头与 Cookie 双重 token。
- **来源校验**：校验 `Host`、`Origin` 与 `Sec-Fetch-Site`，拒绝跨站与非可信来源请求。
- **安全响应头**：严格 CSP、`nosniff`、`DENY` 防嵌框、`no-referrer`、`noindex`、`no-store`。
- **Cookie**：`HttpOnly + SameSite=Lax`，JS 不可读；`Secure` 模式下跨站不携带。
- **令牌哈希**：会话与 CSRF token 仅以 SHA-256 哈希形式入库，比较采用恒定时间比较。

## 开发

```sh
pnpm install          # 安装依赖
pnpm run check        # 类型检查 + 测试 + 构建
pnpm run build        # 构建到 lib/
pnpm run test         # 运行测试
```

### 本地预览

本地预览脚本会安装本插件并启动真实 `dsh web`：

```sh
HOST=0.0.0.0 PORT=34753 \
DSH_AUTH_PREVIEW_TOKEN=preview-bootstrap-token \
pnpm preview
```

随后访问 `/auth/login`，用日志输出的初始化令牌完成初始化即可进入 Harness 界面。

### 验证

```sh
ORIGIN=http://127.0.0.1:34753 \
DSH_AUTH_PREVIEW_TOKEN=preview-bootstrap-token \
pnpm verify:preview
```

该脚本会校验：匿名访问重定向到登录页、认证后返回真实 Harness Boot Manifest 与标题、而非插件占位页。

## 已知边界

- **会话持久化**：会话存于 SQLite，重启 DSH 后未过期的会话仍然有效（与「内存会话」方案不同）。
- **威胁模型为「浏览器 / 网络客户端」**：能直接读写宿主进程内存或文件的本地进程不在防护范围内。
- **忘记密码 / 重置**：删除认证数据库文件后重启，插件回到 `uninitialized_locked` 状态，可重新初始化（会清空所有用户与会话）。

## License

MIT
