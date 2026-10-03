# No.1 的认证组件、请求流程和令牌处理

这里描述的是本仓库的实际实现，入口为 [`app.py`](../app.py)，认证与存储逻辑为 [`auth.py`](../auth.py)。

## 组件

`Handler` 是 HTTP 入口。它检查 Host，限制请求内容长度，只允许指定静态文件路径，并把认证操作委托给 `AuthStore`。所有改变认证状态的 POST 必须来自配置的应用 Origin，使用 JSON；不提供跨源 CORS。

`AuthStore` 负责用户与会话。每次数据库操作新建一个 SQLite 连接，启用外键与事务；SQL 值通过占位符传入。表结构为：

- `users`：用户 ID、规范化邮箱、密码哈希、创建时间。
- `sessions`：用户 ID、会话绝对到期时间、撤销标记。
- `access_tokens`：访问令牌的 SHA-256 摘要、会话 ID、到期时间。
- `refresh_tokens`：刷新令牌的 SHA-256 摘要、会话 ID、是否已使用。

浏览器的 [`app.js`](../static/app.js) 提交表单，将访问令牌保存在 JavaScript 变量里，并以 Bearer 头发送。刷新令牌由浏览器 Cookie 机制管理，页面脚本无法读取。

## 注册与登录

1. `credentials()` 将邮箱去除首尾空格并转成小写，校验邮箱与密码长度；不会修改密码字符。
2. `register()` 创建用户 ID，为每个密码生成 16 字节随机盐，用 scrypt 生成 32 字节哈希。编码包含算法、成本参数、盐和哈希。数据库不保存明文密码。
3. 注册成功仅返回公开用户 ID 与邮箱，要求用户主动登录。
4. `login()` 读取用户哈希，使用原盐重新计算哈希，再由 `hmac.compare_digest()` 比较。未知邮箱也执行一次虚拟密码哈希验证；未知邮箱与错误密码使用相同的 `401` 信息。重复注册的 `409` 仍会暴露邮箱是否存在，这是本示例的行为。
5. 密码正确时，创建一条最长 7 天的会话，通过 `_issue()` 创建访问与刷新令牌。

密码哈希使用 `N=32768, r=8, p=3`。参数选自 [OWASP 密码存储说明的 scrypt 配置](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt)；函数 API 参见 [Python hashlib](https://docs.python.org/3/library/hashlib.html#hashlib.scrypt)。随机盐不需要保密，每个密码使用独立盐。

## 签发与验证令牌

`secrets.token_urlsafe(32)` 为每种令牌生成 32 字节随机数据。它们是不携带用户信息的随机令牌。数据库写入 `SHA256(token)`，原始访问令牌只在签发响应中返回，原始刷新令牌只在 `Set-Cookie` 中发送。

访问令牌的有效期取「现在 + 15 分钟」与「会话到期」中较早者。`GET /api/me` 从 `Authorization: Bearer ...` 提取令牌，`current_user()` 计算摘要并关联用户、会话与令牌表，要求两种有效期尚未到期，且会话未撤销。验证失败返回 `401`，成功只返回用户 ID 与邮箱。用户身份由数据库关联决定，客户端不能自行指定用户 ID。

因为是数据库查表验证，无需在代码中设置共享签名密钥。后端在每次访问时查询会话状态，因此退出可以立即阻止已有访问令牌继续使用。

## 续期、轮换与重放

刷新令牌 Cookie 配置为 `HttpOnly; SameSite=Strict; Path=/api/auth`，没有 Domain 属性；它不会随 `/api/me` 请求发送。本机默认 HTTP 不设置 Secure，HTTPS 代理场景由配置启用。Cookie 属性说明参见 [OWASP 会话管理](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies)。

`refresh()` 通过 `BEGIN IMMEDIATE` 串行执行读写：检查摘要与会话状态，把旧刷新令牌标为已使用，删除该会话已有访问令牌，再创建新的令牌对。旧刷新摘要保留用于识别重放，整个会话的 7 天到期时间保持不变。

如果旧刷新令牌被重复提交，服务把它所属的会话标为撤销，先提交事务，再在事务外抛出认证失败；这样撤销不会被异常回滚。该会话的新旧访问令牌与刷新令牌全部失效，其他独立登录会话不受影响。

页面内通过 `refreshPromise` 合并正在进行的续期。页面重载时，内存访问令牌消失，脚本用 Cookie 尝试续期并取回用户资料。多个浏览器标签页之间没有共享锁，因此同时消费同一个 Cookie 仍可能触发严格重放保护。

## 退出与凭据位置

`logout()` 根据刷新令牌找到会话并撤销，允许重复调用。HTTP 响应用 `Max-Age=0` 清除 Cookie；浏览器清空访问令牌与个人资料。仅关闭页面不会撤销会话。

| 内容 | 保存位置 | 何时使用或删除 |
| --- | --- | --- |
| 明文密码 | 输入框、登录/注册请求与服务器短暂内存 | 提交成功后页面清空输入框；后端只保存密码哈希，Python 不保证立即清零内存 |
| 密码哈希、随机盐、参数 | SQLite `users` | 登录时重新计算并比较 |
| 原始访问令牌 | 页面内存 | Bearer 请求；页面重载、退出时清空；服务端最多 15 分钟有效 |
| 原始刷新令牌 | HttpOnly Cookie | 续期、退出；续期轮换，退出清除，最长不超过会话 7 天 |
| 令牌摘要 | SQLite | 查表验证与重放识别；当前示例没有定期删除过期记录 |
| 签名密钥 | 不使用 | 随机令牌通过服务端状态验证 |

页面不把令牌写入 localStorage 或 sessionStorage，也不显示令牌值。服务器不记录请求正文、认证头或 Cookie，认证响应使用 `Cache-Control: no-store`。数据库与环境文件已从版本控制中排除；仓库不包含演示账号、密码或真实令牌。

## 测试与边界

[`tests/test_auth.py`](../tests/test_auth.py) 验证真实 scrypt 参数、密码与令牌存储、有效期边界、原子续期、重放撤销、独立会话、Cookie 标志、HTTP 请求来源与完整注册登录退出流程。

这是本机学习示例，使用 Python 标准库 HTTP 服务。它不验证邮箱所有权，不包含 OAuth 或角色权限，不声称是已经部署的生产认证服务。启动与配置见 [README](../README.md)。
