# migears/acl-feature

![Version](https://img.shields.io/badge/version-2.0.0-blue)

Endpoint-level access control from a PHP config file — keyed by URL path and HTTP method, deny by default.

> **Background**: miGears is the open-source successor of **TinyGears**, a
> self-developed PHP framework. It was renamed and open-sourced recently because
> the name *TinyGears* is already taken in the open-source community.

## Contents

- [Why](#why)
- [Boundaries](#boundaries)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Errors](#errors)
- [Testing](#testing)
- [License](#license)

## Why

The question is "may this subject call this endpoint?" — and the rules are keyed by URL path and HTTP
method, the same pair the router already uses. That is the point: there is no second vocabulary of
permission names to invent, keep in step with the routes, and re-check on every rename.

- **Config is the endpoint list.** A rule reads `/api/posts => ['GET', 'POST']`, so it looks like the
  route table it guards. Adding an endpoint means adding a line, not inventing an identifier.
- **Deny by default.** An unmatched request is denied. `'default' => true` flips that for a module that
  is mostly open, but the shipped posture is closed.
- **The most specific rule wins; equally specific ones union.** Within a rule map only the patterns that
  anchor the most of the path are consulted, so a precise rule is not widened by a loose one beside it,
  and nothing depends on the order of keys in the file. Role results then union, a user-level `deny` wins
  outright, and a user-level `grant` adds.
- **All-or-nothing at load.** The whole file is validated before an instance exists, so one malformed
  entry loads nothing rather than half a permission set.
- **Zero runtime dependencies, no I/O after load.** One file is read once; `allows()` is then a pure
  function of the config and its arguments. No session, no container, no database, no global state.

## Boundaries

**In scope**

- Deciding whether a `(method, path)` pair is reachable by a subject described as `(roles, userId)`.
- The config format: `default`, `roles`, `users`, and the path/method pattern grammar.
- Loading and validating that config in full, and naming what was wrong when it is not valid.

**Not in scope (by design)**

- Which *rows* a subject may reach — that is `migears/acl-data`. A permission that depends on which
  record is addressed is not an endpoint permission, which is why the pattern grammar has no `:id`.
- Which *columns* of a row a subject may read or write — that is `migears/acl-field`.
- Identifying the subject. Roles and a user id arrive as arguments; authentication and session handling
  belong to `migears/security` and the caller.
- Turning a denial into a response. `assert()` throws; whether that becomes a 403, a redirect or a JSON
  body is the caller's decision.
- Auditing or logging. The library keeps no logger, per the framework's rules.

## Installation

```bash
composer require migears/acl-feature
```

Requires PHP 8.1+. No runtime dependencies.

## Quick Start

Write the rules as data — `config/acl-feature.php`, beside `src/` and `tests/`:

```php
<?php

return [
    // unmatched requests are denied; omit this key and it is already false
    'default' => false,

    'roles' => [
        'admin' => [
            '*' => ['*'],                          // every method, every path
        ],
        'editor' => [
            '/api/posts'   => ['GET', 'POST'],     // list and create
            '/api/posts/*' => ['GET', 'PUT'],      // detail and update
        ],
        'viewer' => [
            '/api/posts'   => ['GET'],
            '/api/posts/*' => ['GET'],
        ],
    ],

    // optional: per-user overrides; deny beats grant, grant beats the role result
    'users' => [
        42 => [
            'grant' => ['/api/billing/*' => ['GET']],
            'deny'  => [
                '/api/posts'   => ['POST'],
                '/api/posts/*' => ['DELETE'],
            ],
        ],
    ],
];
```

Load it once, at the composition root, and check every request in one place:

```php
use MiGears\AclFeature\AclFeature;

$acl = AclFeature::fromFile(__DIR__ . '/config/acl-feature.php');
```

```php
// A base resource class — the recommended call site: the check runs before the
// request reaches a handler, so a denial never runs handler code. The path is
// the request path as the router saw it, and the rule is written with a
// single-segment wildcard for whichever positions carry an id.
protected function before(Request $request): ?Response
{
    // $roles and $userId come from your authentication layer
    $this->acl->assert($request->method, $request->path, $roles, $userId);

    return null;
}
```

Where you want to branch instead of throw, ask directly:

```php
if ($acl->allows('POST', '/api/posts', $roles, $userId)) {
    // …
}
```

## Configuration

| Key | Type | Required | Meaning |
|---|---|---|---|
| `default` | `bool` | no | Outcome when no rule matches; `false` when omitted |
| `roles` | `array<string, array<string, list<string>>>` | one of the two | Role name → path rule map |
| `users` | `array<int\|string, array{grant?: array, deny?: array}>` | one of the two | Per-user grants and denials, each a path rule map |

A path rule map is `path pattern => list of method patterns`. At least one of `roles` and `users` must
be present; a config declaring neither fails to load.

### Pattern grammar

**Method patterns**

| Form | Matches | Example |
|---|---|---|
| `*` | any HTTP method | `'/api/posts' => ['*']` |
| an exact name | that method, case-insensitive | `['get', 'POST']` — either case works |

**Path patterns**

| Form | Matches | Example |
|---|---|---|
| `*` | any path | `'*' => ['GET']` |
| `/prefix/*` | the prefix itself **and** any descendant | `'/api/posts/*'` covers `/api/posts`, `/api/posts/42`, `/api/posts/42/comments`. As a degenerate case, `'/*'` is an empty prefix — it matches `/` itself and every absolute path (without being the bare `*` catch-all, which also matches paths without a leading `/`) |
| `/a/*/b` | the segments line up one for one, `*` covering exactly one | `'/api/posts/*/comments'` covers `/api/posts/42/comments`, but neither `/api/posts/42` nor `/api/posts/42/comments/7` |
| `/a/{name}/b` | the same, with a named single-segment placeholder | `'/posts/{post_id}/comments'` covers `/posts/8757/comments` |
| an exact path | that path and nothing else | `'/api/posts'` does not cover `/api/posts/42` |

The boundary is a segment on both sides of a wildcard: `/api/posts/*` does **not** cover
`/api/postscript`, and `'/api/posts/*/comments'` does not cover `/api/posts/42/commentary`. A wildcard is
always a whole segment — `/post*` is not a pattern. A placeholder names a position, not a value: it says
*any* value may sit there, never *which* one — gating on a particular id belongs to `migears/acl-data`.

Matching ignores case, the way the router does — a segment is matched against a lowercased file name, so
`/USERS/42` and `/users/42` are one route and a rule written `/users/*` covers both. Only case is ignored:
`/user/42` is a different path, and `-` and `_` are not interchangeable.

Covering one segment has two spellings: `*` away from the end, and `{name}` anywhere. A `*` in the last
position is instead the subtree form, and that is the one place the two part ways — `'/posts/{post_id}'` is
a single post, `'/posts/*'` is the collection and everything under it. So an endpoint whose path carries an
id reads like the route it guards: `'/posts/{post_id}/comments'` reaches the comments of a post, and
`'/posts/{post_id}/comments/{comment_id}'` reaches one comment. A malformed brace is rejected at load time
rather than loading as inert literal text.

That is what keeps a nested API precise. Where every endpoint carries an id, a trailing wildcard alone
would hand over the whole subtree — `/api/posts/*` gives a reader every post's every comment. Naming the
position instead (`/api/posts/*/comments`) grants one endpoint: the comments of a post, and nothing below
them. Several positions nest, and a trailing one keeps its breadth, so `/api/posts/*/comments/*` is the
comment detail plus whatever hangs under it.

When two rules match the same path, the more specific one decides which methods apply — a literal segment
beats a `{name}` placeholder, which beats a `*`. An exact rule for one literal value
(`'/posts/ALL/comments'`) is therefore not widened by a wildcard rule beside it (`'/posts/*/comments'`). A
trailing `*` counts as reach rather than precision, so `'/posts'` and `'/posts/*'` stay level on `/posts`
itself and union. Rules of equal specificity union too, which is why the order of keys never matters.

The same path may appear only once per map: PHP silently collapses duplicate array keys and the later
one wins. That is the one sharp edge here, and the loader cannot detect it, because the information is
already gone by the time PHP parses the file — so keep a role's path rules together where they are easy
to scan.

### Evaluation order

1. Start from `default` (`false` when omitted).
2. A role grants the request when the most specific of its patterns that matches the path lists the
   method; patterns level on specificity union. If any role grants it, the result becomes `true`.
3. If a `userId` is given and that id is present under `users`: a matching `deny` returns `false`
   outright; otherwise a matching `grant` returns `true`.
4. Otherwise the result so far stands.

Worked through the config above:

```php
$acl->allows('GET',  '/api/posts', ['viewer']);            // true  — viewer lists it
$acl->allows('POST', '/api/posts', ['viewer']);            // false — viewer does not
$acl->allows('POST', '/api/posts', ['viewer', 'editor']);  // true  — editor unions in
$acl->allows('GET',  '/api/posts/42/comments', ['viewer']); // true  — prefix covers descendants
$acl->allows('GET',  '/api/postscript', ['viewer']);        // false — not under /api/posts
$acl->allows('GET',  '/api/billing/9', ['viewer']);         // false — nothing matches
$acl->allows('GET',  '/api/billing/9', ['viewer'], 42);     // true  — the user's grant adds it
$acl->allows('POST', '/api/posts', ['editor'], 42);         // false — the user's deny wins
```

## API Reference

### `MiGears\AclFeature\AclFeature`

```php
public static function fromFile(string $file): self
public static function fromArray(array $config): self

public function allows(string $method, string $path, string|array $roles, int|string|null $userId = null): bool
public function denies(string $method, string $path, string|array $roles, int|string|null $userId = null): bool
public function forRequest(string $method, string $path, string|array $roles, int|string|null $userId = null): bool
public function assert(string $method, string $path, string|array $roles, int|string|null $userId = null): void
public function withUser(int|string $userId): self
```

`fromFile()` reads and validates the whole file before an instance exists; `fromArray()` does the same
for an array, for tests and for a composition root that assembles the config itself. Its messages carry
no file name, because there is no file.

`assert()` is the only call that throws on a denial. `denies()` is the negation of `allows()`;
`forRequest()` is an alias of it, reading as what a resource's `before()` hook is doing — the per-resource
hook, not a global one. `withUser()` returns a copy bound to one subject, leaving the instance it came
from untouched — useful in a loop over users, and safe because nothing is shared.

Roles accept a single string or a list, and the union of a list is taken.

### `MiGears\AclFeature\AclFeatureException`

Thrown by `fromFile()` and `fromArray()` when a config cannot be used. Extends `RuntimeException`.

### `MiGears\AclFeature\DeniedException`

Thrown by `assert()` when the request is not allowed. Extends `AclFeatureException`, so catching the
base class catches a denial and a config mistake together — which is what a caller wants at the point
where it would otherwise turn the denial into a 403.

## Errors

Every load failure is an assembly mistake, so it fails loudly at initialization rather than surfacing as
a request that was quietly allowed or quietly denied. `<owner>` is `role '<name>'` or `user '<id>'
grant`/`user '<id>' deny`; `: <file>` appears only when the config came from `fromFile()`.

| Condition | Message |
|---|---|
| file missing or unreadable | `ACL feature config not found or not readable: <file>` |
| did not `return` an array | `ACL feature config must return an array, got <type>: <file>` |
| unknown top-level key | `Unknown ACL feature config key '<key>': <file>` |
| `default` is not a bool | `ACL feature config key 'default' must be a bool, got <type>: <file>` |
| `roles` is not an array | `ACL feature config key 'roles' must be an array, got <type>: <file>` |
| `users` is not an array | `ACL feature config key 'users' must be an array, got <type>: <file>` |
| a user entry is not an array | `User entry '<id>' must be an array of grant and deny rules, got <type>: <file>` |
| a user entry has an unknown key | `User entry '<id>' accepts only 'grant' and 'deny': <file>` |
| a rule map is not an array | `Rules for <owner> must be an array of path => methods, got <type>: <file>` |
| invalid path pattern | `Invalid path pattern '<pattern>' for <owner>: <file>` |
| a path's methods are not a list | `Methods for path '<pattern>' of <owner> must be a list, got <type>: <file>` |
| a path's method list is empty | `Path '<pattern>' of <owner> lists no methods: <file>` |
| invalid method name | `Invalid method '<method>' for path '<pattern>' of <owner>: <file>` |
| neither `roles` nor `users` | `ACL feature config declares neither roles nor users: <file>` |
| an assertion is denied | `<METHOD> <path> denied for roles [<roles>]` (a `DeniedException`) |

## Testing

```bash
composer test      # phpunit
composer analyse   # phpstan level 6
```

CI also runs a coverage-threshold job (see `.github/workflows/tests.yml`): line coverage must reach `100%`
to merge. Run it locally with `composer test -- --coverage-text` (requires pcov or xdebug enabled).

## License

MIT. See [LICENSE](LICENSE).

---

# migears/acl-feature

![Version](https://img.shields.io/badge/version-2.0.0-blue)

从一份 PHP 配置文件出发的端点级访问控制 —— 以 URL 路径与 HTTP method 为键，默认拒绝。

> **背景**：miGears 是自研 PHP 框架 **TinyGears** 的开源后继。更名并开源，是因为
> *TinyGears* 这个名字在开源社区已被占用。

## 目录

- [为什么](#为什么)
- [边界](#边界)
- [安装](#安装)
- [快速开始](#快速开始)
- [配置](#配置)
- [API 参考](#api-参考)
- [错误](#错误)
- [测试](#测试)
- [许可证](#许可证)

## 为什么

它回答的问题是「这个主体能不能调用这个端点」，而规则以 URL 路径与 HTTP method 为键——也就是路由已经在用的
那一对。这正是要点：不需要另造一套权限名去发明、去跟住路由、去在每次改名后重新核对。

- **配置就是端点清单。** 一条规则读作 `/api/posts => ['GET', 'POST']`，所以它长得像它所守护的那张路由表。
  加一个端点就是加一行，而不是发明一个标识符。
- **默认拒绝。** 未命中的请求一律拒绝。对大部分开放的模块，`'default' => true` 可以翻转这一点，但出厂姿态是收紧的。
- **最具体的规则胜出，同具体度取并集。** 同一张规则表里只有锚定路径最多的那些模式会被采纳，因此精确规则不会被
  旁边的宽泛规则放大，结果也完全不取决于文件里键的顺序。随后角色结果取并集，用户级 `deny` 直接胜出，再由用户级
  `grant` 追加。
- **加载时全有或全无。** 整份文件在实例产生之前就校验完，因此一个畸形条目载入的是零，而不是半套权限。
- **零运行时依赖，加载之后没有 I/O。** 文件只读一次；此后 `allows()` 是配置与参数之上的纯函数。
  没有会话、没有容器、没有数据库、没有全局状态。

## 边界

**范围内**

- 判定一个 `(method, path)` 对是否可被一个以 `(roles, userId)` 描述的主体触及。
- 配置格式：`default`、`roles`、`users`，以及路径与方法的模式语法。
- 完整加载并校验该配置，并在配置不合法时点名错在哪里。

**范围外（刻意不做）**

- 主体能触及哪些*行* —— 那是 `migears/acl-data` 的事。依赖「被寻址的是哪条记录」的权限不是端点权限，
  这也是模式语法里没有 `:id` 的原因。
- 一行里的哪些*列*可读可写 —— 那是 `migears/acl-field` 的事。
- 识别主体。角色与用户 id 以参数形式传入；认证与会话属于 `migears/security` 与调用方。
- 把拒绝变成响应。`assert()` 会抛异常；至于它变成 403、跳转还是 JSON 体，由调用方决定。
- 审计或日志。按框架规矩，库内不带 logger。

## 安装

```bash
composer require migears/acl-feature
```

需要 PHP 8.1+。无运行时依赖。

## 快速开始

把规则写成数据 —— `config/acl-feature.php`，与 `src/`、`tests/` 同级：

```php
<?php

return [
    // 未命中的请求一律拒绝；省略这个键时它本来就是 false
    'default' => false,

    'roles' => [
        'admin' => [
            '*' => ['*'],                          // 全部方法、全部路径
        ],
        'editor' => [
            '/api/posts'   => ['GET', 'POST'],     // 列表与创建
            '/api/posts/*' => ['GET', 'PUT'],      // 详情与更新
        ],
        'viewer' => [
            '/api/posts'   => ['GET'],
            '/api/posts/*' => ['GET'],
        ],
    ],

    // 可选：按用户覆盖；deny 优先于 grant，grant 优先于角色结果
    'users' => [
        42 => [
            'grant' => ['/api/billing/*' => ['GET']],
            'deny'  => [
                '/api/posts'   => ['POST'],
                '/api/posts/*' => ['DELETE'],
            ],
        ],
    ],
];
```

在组合根加载一次，并在一处检查每个请求：

```php
use MiGears\AclFeature\AclFeature;

$acl = AclFeature::fromFile(__DIR__ . '/config/acl-feature.php');
```

```php
// 某个资源基类 —— 推荐调用点：检查在请求到达处理器之前完成，
// 因此拒绝时处理器的代码根本不会执行。路径用路由器看到的请求路径，
// 规则里凡是有 id 的位置写单段通配即可。
protected function before(Request $request): ?Response
{
    // $roles 与 $userId 来自你的认证层
    $this->acl->assert($request->method, $request->path, $roles, $userId);

    return null;
}
```

想分支而不是抛异常时，直接询问：

```php
if ($acl->allows('POST', '/api/posts', $roles, $userId)) {
    // …
}
```

## 配置

| 键 | 类型 | 必填 | 含义 |
|---|---|---|---|
| `default` | `bool` | 否 | 无规则命中时的结果；省略时为 `false` |
| `roles` | `array<string, array<string, list<string>>>` | 二者之一 | 角色名 → 路径规则表 |
| `users` | `array<int\|string, array{grant?: array, deny?: array}>` | 二者之一 | 按用户的授权与拒绝，各自是一张路径规则表 |

路径规则表即 `路径模式 => 方法模式列表`。`roles` 与 `users` 至少要有一个；两者都不声明的配置无法加载。

### 模式语法

**方法模式**

| 写法 | 匹配 | 示例 |
|---|---|---|
| `*` | 任何 HTTP method | `'/api/posts' => ['*']` |
| 精确名称 | 该方法，大小写不敏感 | `['get', 'POST']` —— 两种大小写都行 |

**路径模式**

| 写法 | 匹配 | 示例 |
|---|---|---|
| `*` | 任何路径 | `'*' => ['GET']` |
| `/前缀/*` | 该前缀本身**以及**任意后代路径 | `'/api/posts/*'` 覆盖 `/api/posts`、`/api/posts/42`、`/api/posts/42/comments`。作为退化形式，`'/*'` 是空前缀——它匹配 `/` 本身与每一个绝对路径（但并不是裸 `*` 的通吃，裸 `*` 还会匹配不带前导 `/` 的路径） |
| `/a/*/b` | 各段一一对齐，其中 `*` 恰好覆盖一段 | `'/api/posts/*/comments'` 覆盖 `/api/posts/42/comments`，但不覆盖 `/api/posts/42`，也不覆盖 `/api/posts/42/comments/7` |
| `/a/{name}/b` | 同上，只是用带名字的单段占位符 | `'/posts/{post_id}/comments'` 覆盖 `/posts/8757/comments` |
| 精确路径 | 只匹配该路径 | `'/api/posts'` 不覆盖 `/api/posts/42` |

边界在通配符两侧都落在段上：`/api/posts/*` **不**覆盖 `/api/postscript`，`'/api/posts/*/comments'` 也
不覆盖 `/api/posts/42/commentary`。通配符永远是完整的一段——`/post*` 不是合法写法。占位符指名的是位置，
不是值：它表达「这个位置上可以是任意值」，而非「是哪一个值」——按具体 id 放行属于 `migears/acl-data`。

匹配不区分大小写，口径与路由一致——段是与「转小写后的文件名」比对的，所以 `/USERS/42` 与 `/users/42` 是
同一条路由，写成 `/users/*` 的规则对两者都生效。被忽略的只有大小写：`/user/42` 是另一条路径，`-` 与 `_`
也不可互换。

覆盖一段有两种写法：不在末尾的 `*`，以及任意位置的 `{name}`。位于末尾的 `*` 则是子树形式，这也是两者唯一
分道扬镳之处——`'/posts/{post_id}'` 是一篇文章，`'/posts/*'` 是该集合及其下所有内容。于是带 id 的端点可以
照着它所守护的路由写：`'/posts/{post_id}/comments'` 到达某篇文章的评论，
`'/posts/{post_id}/comments/{comment_id}'` 到达某一条评论。花括号写法不完整会在加载期被拒绝，不会被当成
普通文本静默载入。

这正是嵌套 API 得以精确的原因。当每个端点都带 id 时，只用尾部通配等于把整棵子树交出去——`/api/posts/*`
会让读者拿到所有文章的所有评论。改为点名位置（`/api/posts/*/comments`）就只放行一个端点：某篇文章的
评论，且不含评论之下的任何东西。多个这样的位置可以嵌套，而尾部那段仍保留其广度，所以
`/api/posts/*/comments/*` 是评论详情，连同它下面的路径一并覆盖。

当两条规则命中同一路径时，更具体的那条决定可用方法——字面段胜于 `{name}` 占位符，占位符又胜于 `*`。因此针对
某个字面值的精确规则（`'/posts/ALL/comments'`）不会被旁边的通配规则（`'/posts/*/comments'`）放大。尾部 `*`
算作广度而非精度，所以 `'/posts'` 与 `'/posts/*'` 在 `/posts` 本身上同级并取并集。具体度相同的规则同样取
并集，这也是键的顺序从不起作用的原因。

同一张表里同一个路径只能出现一次：PHP 会静默折叠重复的数组键，后写的胜出。这是这里唯一的坑，而加载器无法
察觉它——PHP 解析文件时信息就已经丢了——因此请把一个角色的路径规则写在一处，便于一眼扫完。

### 求值顺序

1. 从 `default` 起步（省略时为 `false`）。
2. 某个角色下，命中该路径的模式中最具体的那条决定方法是否可用；具体度相同的取并集。只要有任一角色放行，结果就变为 `true`。
3. 若给了 `userId` 且该 id 出现在 `users` 中：命中的 `deny` 直接返回 `false`；否则命中的 `grant` 返回 `true`。
4. 否则维持此前的结果。

用上面的配置走一遍：

```php
$acl->allows('GET',  '/api/posts', ['viewer']);            // true  —— viewer 列了它
$acl->allows('POST', '/api/posts', ['viewer']);            // false —— viewer 没列
$acl->allows('POST', '/api/posts', ['viewer', 'editor']);  // true  —— editor 并集进来
$acl->allows('GET',  '/api/posts/42/comments', ['viewer']); // true  —— 前缀覆盖后代
$acl->allows('GET',  '/api/postscript', ['viewer']);        // false —— 不在 /api/posts 之下
$acl->allows('GET',  '/api/billing/9', ['viewer']);         // false —— 什么都没命中
$acl->allows('GET',  '/api/billing/9', ['viewer'], 42);     // true  —— 用户的 grant 追加进来
$acl->allows('POST', '/api/posts', ['editor'], 42);         // false —— 用户的 deny 胜出
```

## API 参考

### `MiGears\AclFeature\AclFeature`

```php
public static function fromFile(string $file): self
public static function fromArray(array $config): self

public function allows(string $method, string $path, string|array $roles, int|string|null $userId = null): bool
public function denies(string $method, string $path, string|array $roles, int|string|null $userId = null): bool
public function forRequest(string $method, string $path, string|array $roles, int|string|null $userId = null): bool
public function assert(string $method, string $path, string|array $roles, int|string|null $userId = null): void
public function withUser(int|string $userId): self
```

`fromFile()` 在实例产生之前完整读取并校验文件；`fromArray()` 对数组做同样的事，供测试与自行拼装配置的
组合根使用，它的消息不带文件名，因为没有文件。

`assert()` 是唯一在拒绝时抛异常的调用。`denies()` 是 `allows()` 的取反；`forRequest()` 是它的别名，
读起来正是资源基类的 `before()` 钩子在做的事——是每个资源自己的那个钩子，不是全局钩子。
`withUser()` 返回一个绑定到某主体的副本，原实例不受影响——
在遍历用户时有用，也因为什么都不共享而安全。

角色参数接受单个字符串或一个列表，列表按并集处理。

### `MiGears\AclFeature\AclFeatureException`

配置不可用时由 `fromFile()` 与 `fromArray()` 抛出。继承 `RuntimeException`。

### `MiGears\AclFeature\DeniedException`

`assert()` 判定请求不被允许时抛出。它继承 `AclFeatureException`，因此捕获基类可以同时捕获拒绝与配置
错误——这正是调用方在即将把拒绝变成 403 的那个位置所需要的。

## 错误

每个加载失败都是装配错误，因此在初始化时大声失败，而不是稍后表现为一个被无声放行或被无声拒绝的请求。
`<owner>` 为 `role '<name>'` 或 `user '<id>' grant`/`user '<id>' deny`；`: <file>` 仅在配置来自
`fromFile()` 时出现。

| 情形 | 消息 |
|---|---|
| 文件缺失或不可读 | `ACL feature config not found or not readable: <file>` |
| 没有 `return` 数组 | `ACL feature config must return an array, got <type>: <file>` |
| 顶层键未知 | `Unknown ACL feature config key '<key>': <file>` |
| `default` 不是 bool | `ACL feature config key 'default' must be a bool, got <type>: <file>` |
| `roles` 不是数组 | `ACL feature config key 'roles' must be an array, got <type>: <file>` |
| `users` 不是数组 | `ACL feature config key 'users' must be an array, got <type>: <file>` |
| 用户条目不是数组 | `User entry '<id>' must be an array of grant and deny rules, got <type>: <file>` |
| 用户条目含未知键 | `User entry '<id>' accepts only 'grant' and 'deny': <file>` |
| 规则表不是数组 | `Rules for <owner> must be an array of path => methods, got <type>: <file>` |
| 路径模式不合法 | `Invalid path pattern '<pattern>' for <owner>: <file>` |
| 某路径的方法不是列表 | `Methods for path '<pattern>' of <owner> must be a list, got <type>: <file>` |
| 某路径的方法列表为空 | `Path '<pattern>' of <owner> lists no methods: <file>` |
| 方法名不合法 | `Invalid method '<method>' for path '<pattern>' of <owner>: <file>` |
| `roles` 与 `users` 皆缺 | `ACL feature config declares neither roles nor users: <file>` |
| 断言被拒 | `<METHOD> <path> denied for roles [<roles>]`（抛 `DeniedException`） |

## 测试

```bash
composer test      # phpunit
composer analyse   # phpstan level 6
```

CI 还跑一项覆盖率阈值任务（见 `.github/workflows/tests.yml`）：行覆盖率必须达到 `100%`
才能合并。本地可通过 `composer test -- --coverage-text` 触发（需启用 pcov 或 xdebug）。

## 许可证

MIT，见 [LICENSE](LICENSE)。
