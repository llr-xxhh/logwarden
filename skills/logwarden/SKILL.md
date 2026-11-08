---
name: logwarden
description: 操作本地日志分诊台 LogWarden——建排查任务、导入 evtx/nginx/auth/syslog 日志、新增或修改解析模板与检测规则、读告警并产出带证据行的结论。当用户要求分析日志、排查入侵痕迹、定位可疑 IP / 进程 / 路径，或者需要往日志平台里接入新日志格式、编写新检测规则时使用。
---

# LogWarden 操作手册（给 AI agent）

LogWarden 是一个只监听 `127.0.0.1` 的本地日志排查服务。界面是给人看的，但**所有动作背后都有 HTTP 接口**——优先用接口，不要模拟点击。

## 0. 先判断走哪条路

| 场景 | 走法 | 理由 |
|---|---|---|
| 建任务、导日志、查统计、读告警、改规则、改模板 | **HTTP API**（默认） | 一步到位，不依赖界面状态 |
| 需要给人看效果、确认布局、演示全流程 | CDP 操控界面 | 人能同步看到 |
| 只做只读分析、服务没起 | 直接读 DuckDB 文件 | `data-duck/task_*.duckdb` |

**默认用 API。** 模拟点击的每一步都可能被动画、懒加载、缓存打断，而 API 调用是原子的。

## 1. 连接

```bash
curl -s --noproxy '*' http://127.0.0.1:8766/api/health
# {"ok":true,"app":"logwarden","engine":"duckdb","version":"0.7","storage":"...","tasks":0}
```

- 默认端口 **8766**（可用 `LOGVIEW_PORT` 改）；调试端口 9223（CDP）
- 数据目录：`data-duck/`（任务库）+ `meta.duckdb`，可用 `LOGVIEW_DATA_DIR` 指到别处
- 没起服务时：`python start.py --browser none`
- **所有请求都要绕开系统代理**（Python `urllib` 用 `ProxyHandler({})`，curl 加 `--noproxy '*'`），否则会打到代理上

## 2. 界面直达（CDP 模式下用）

| URL | 效果 |
|---|---|
| `/#<task_id>` | 打开指定任务 |
| `/?nt=1&sel=nginx,windows` | 直接弹新建任务，预勾组件 |
| `/?evi=1#<task_id>` | 直接打开证据清单抽屉 |
| `/?pg=logs\|stats\|alerts\|rules\|import#<task_id>` | 直达对应页 |

每个界面状态都有 URL，CDP 里直接 `page.goto()` 比点菜单可靠。

## 3. 五步排查流程

```bash
# ① 看有哪些组件和日志源
curl -s --noproxy '*' http://127.0.0.1:8766/api/bootstrap
# → {components:[{id,name,sources:[...]}], sources:[{id,name,format,paths,level,...}], templates:[...]}

# ② 建任务（source_ids 必须是所选组件范围内的源）
curl -s -X POST http://127.0.0.1:8766/api/tasks \
  -H 'Content-Type: application/json' \
  -d '{"name":"排查：web-01","arch":"单机 nginx","components":["nginx"],"source_ids":["nginx_access"]}'

# ③ 导日志（text 接口最省事；大文件走 multipart 的 /imports）
curl -s -X POST http://127.0.0.1:8766/api/tasks/<tid>/imports/text \
  -H 'Content-Type: application/json' \
  -d '{"source_id":"nginx_access","fmt":"combined","filename":"access.log","text":"..."}'
# → {"id":"i_xxx","rows":951,"failed":0,"errors":[...],"nulls":{...}}

# ④ 统计与告警（按源查，不是按任务）
curl -s --noproxy '*' "http://127.0.0.1:8766/api/tasks/<tid>/sources/nginx_access/stats?window=60"
curl -s --noproxy '*' "http://127.0.0.1:8766/api/tasks/<tid>/sources/nginx_access/alerts"

# ⑤ 取具体行（结论要挂证据）
curl -s -X POST http://127.0.0.1:8766/api/tasks/<tid>/query \
  -H 'Content-Type: application/json' \
  -d '{"source_id":"nginx_access","size":50,"sort":{"k":"ts","dir":-1},
       "fk":{"ip":"203.0.113.45"},
       "colf":{"path":{"q":"upload"}}}'
```

**关键约束**：导入前必须确认 `source_id` 已在任务的 `source_ids` 里，否则接口返回 400（`该日志源未加入当前任务`）。要加源用 `PATCH /api/tasks/{id}/sources`。

## 4. 模板操作 ★

一个日志源只挂一个模板。模板决定「这行日志拆成哪些列」，语义字段进统计和规则，其余字段各建一列。

### 结构

```json
{
  "name": "自研订单系统",
  "kind": "regex",
  "pattern": "(?P<ts>\\S+ \\S+) (?P<level>\\w+) (?P<user>\\S+) order=(?P<order_id>\\w+) amount=(?P<amount>[\\d.]+)",
  "time_format": "%Y-%m-%d %H:%M:%S",
  "types": {"amount": "REAL"},
  "note": "订单服务 stdout",
  "source_ids": ["custom_order"]
}
```

- **`kind: "nginx"`** —— `template` 里直接粘整段 `log_format`，`$变量` 自动编译成正则。顺序随便写，多字段少字段都不影响显示：

```json
{"name":"nginx 主站","kind":"nginx","template":"$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"","source_ids":["nginx_access"]}
```

- **`kind: "regex"`** —— `pattern` 里 `(?P<名字>...)` 的命名组就是列名。

### 语义字段（决定能不能进统计和规则）

| 字段 | 类型 | 说明 |
|---|---|---|
| `ip` / `srcip` / `dstip` | TEXT | 来源 / 目的地址 |
| `srcport` / `dstport` | INTEGER | 端口 |
| `xff` | TEXT | X-Forwarded-For |
| `host` | TEXT | 主机名 |
| `user` | TEXT | 账号 |
| `ts` | INTEGER | **毫秒**时间戳 |
| `method` / `path` | TEXT | HTTP 方法与路径 |
| `status` | INTEGER | 状态码 |
| `bytes` | INTEGER | 响应字节 |
| `ua` / `ref` | TEXT | User-Agent / Referer |

其余名字照样建列，但不参与排行、频次、基线这些统计，也不进规则。

### 接入一种新日志的四步

```bash
# ① 粘一行真实日志，让系统猜个草稿（认不出会返回空，那就自己写正则）
curl -s -X POST http://127.0.0.1:8766/api/formats/detect \
  -H 'Content-Type: application/json' -d '{"line":"<一行原始日志>"}'

# ② 拿草稿改（改 name / 补语义字段名 / 调 types）

# ③ 试解析（两种 kind 的入口不一样）
#    kind=nginx：把 log_format 原样传给 template
curl -s -X POST http://127.0.0.1:8766/api/formats/preview \
  -H 'Content-Type: application/json' \
  -d '{"template":"$remote_addr [$time_local] \"$request\" $status","text":"<几行日志>"}'

#    kind=regex：这个接口只认 log_format。正则模板要先保存并绑到某个源，
#    再用导入预览接口按源看解析结果
curl -s -X POST http://127.0.0.1:8766/api/preview \
  -H 'Content-Type: application/json' -d '{"source_id":"nginx_access","text":"<几行日志>"}'

# ④ 保存（带 id 是编辑，不带是新建）
curl -s -X POST http://127.0.0.1:8766/api/formats \
  -H 'Content-Type: application/json' -d '{"spec":{...},"id":"<可选>"}'
```

### 模板的六个常见错误

1. **语义字段名写错**（比如写成 `source_ip` 而不是 `srcip`）→ 能建列但统计和规则都用不上，看起来"导入成功但什么都查不到"
2. **`ts` 写成秒** → 时间轴全错。必须是毫秒
3. **正则用了 Python 不支持的语法**（变长后顾、条件组）→ 导入时整批失败，`errors` 里有行号和原因
4. **一个源挂两个模板** → 后保存的覆盖前者，旧模板不会报错，只会静默失效
5. **改了模板不重新导入** → 新列对已有数据是空的。模板只管新导入的数据
6. **`log_format` 和日志行结构不一致**（少写 `$body_bytes_sent`、多了引号）→ 编译出来的正则整行匹配不上，`rows` 是空的但接口返回 200。**字段必须是日志行的完整超集**，顺序可以不同，数量不能少

## 5. 规则操作 ★

规则是 JSON，内置 164 条（`rules/builtin/`），自定义的存 `rules/custom/`，**同 id 覆盖内置**。

### 行规则

```json
{
  "id": "web_webshell_upload",
  "name": "上传目录里的脚本被请求",
  "severity": "high",
  "kind": "row",
  "scope": "web",
  "match": {
    "path": {"iregex": "^/(upload|uploads|files)/.*\\.(php|jsp|asp|aspx)$"},
    "status": {"in": [200, 201, 302]}
  },
  "explain": "上传目录里出现可执行脚本且被成功访问，是 webshell 落地的直接信号",
  "false_positive": "业务本身把脚本放在 upload 目录下时需要白名单",
  "triage": "取该 IP 的全部请求，看上传前是否有探测、上传后是否执行命令",
  "tags": ["webshell"],
  "enabled": true
}
```

### match 语法

只有三个组合键，**没有 `all`**：

| 写法 | 含义 |
|---|---|
| 顶层平铺多个字段 | AND。`{"status": {"eq": 404}, "path": {"contains": "admin"}}` 两个条件都要成立 |
| `{"any": [ ... ]}` | OR。数组里每一项递归当成一个完整条件，所以项内部可以再 AND |
| `{"not": {...} }` | NOT。取反里面整个条件 |

⚠️ **没有 `all`**。走 API 保存会被直接拒掉（报「字段 all 的条件必须是非空对象」）；如果绕过接口直接改 JSON 文件，它会被当成"名为 all 的字段"，规则**永远不命中且不报错**。需要 AND 就直接平铺字段。

需要 `(A AND B) OR C` 这种组合时，写成：

```json
{"any": [
  {"a": {"eq": 1}, "b": {"eq": 2}},
  {"c": {"eq": 3}}
]}
```

### 操作符

| 操作符 | 语义 | 能否下推 SQL |
|---|---|---|
| `eq` / `ne` | 相等（数字按数值比） | ✅ |
| `in` / `not_in` | 集合 | ✅ |
| `gt` `gte` `lt` `lte` | 数值比较 | ✅ |
| `contains` / `icontains` | 子串（i = 忽略大小写） | ✅ |
| `contains_any` / `icontains_any` | 任一子串命中 | ✅ |
| `starts_with` / `ends_with` | 前缀 / 后缀 | ✅ |
| `regex` / `iregex` / `not_regex` | 正则 | ✅（RE2 语法，不支持前后查找和反向引用） |
| `exists` / `not_exists` | 非空 / 为空 | ✅ |
| `len_lt` `len_gt` `len_eq` | 字符串长度 | ✅ |

**注意**：`eq` / `starts_with` / `ends_with` **区分大小写**，`iregex` / `icontains` 不区分。写规则时别混。

### 聚合规则（时序模式）

```json
{
  "id": "auth_bruteforce", "name": "认证失败爆发", "severity": "high",
  "kind": "aggregate", "scope": ["auth", "win"],
  "match": {"agg": {
    "type": "window_count",
    "where": {"msg": {"icontains": "failed password"}},
    "group_by": "ip",
    "window_sec": 60,
    "min_count": 10,
    "distinct": "user",
    "min_distinct": 3
  }},
  "explain": "...", "false_positive": "..."
}
```

聚合规则**永远走 Python 流式扫描**，不能下推 SQL。1000 万行级别约 20–40 秒。

### scope 取值

`web`（HTTP 访问日志）· `auth`（认证）· `win`（Windows 安全日志）· `sysmon` · `ps`（脚本块）· `shell` · `audit`（auditd）· `syslog` · `firewall` · `text`（任意文本）

可以是字符串或数组。**写错 scope 规则不会报错，只是永远不命中**——这是最常见的坑。

### 保存时的硬校验（不满足直接 400）

| 字段 | 要求 |
|---|---|
| `name` | 非空 |
| `severity` | **只能是 `high` / `medium` / `low`**，没有 critical |
| `false_positive` | **必填且不能是空串**。这是强制的，哪怕写「无」也得写 |
| `kind` | `row` 或 `aggregate` |
| `scope` | 必须是上表里的有效值，**不允许 `all`** |
| `match` | 非空；组合键只能是 `any` / `not` / `agg` |
| 操作符 | 必须在支持列表内，拼错会报「未知匹配操作符」 |
| `in` 类 | `in` / `not_in` / `contains_any` / `icontains_any` 的数组不能为空 |

正则保存时用 **Python `re`** 校验，所以带前后查找（lookaround）的规则能存进去；但 SQL 下推用的是 DuckDB 的 RE2，跑不了这类语法，会自动退回 Python 逐行——**结果对，但慢**。

### 新增/改规则的流程

```bash
# ① 拉现有规则，找同 id 的（有就覆盖）
curl -s --noproxy '*' http://127.0.0.1:8766/api/rules

# ② 保存（POST 新建 / PUT 改）
curl -s -X PUT http://127.0.0.1:8766/api/rules/web_my_rule \
  -H 'Content-Type: application/json' -d '{...}'

# ③ 立刻验证：查这个源的告警，看 count 是不是符合预期
curl -s --noproxy '*' "http://127.0.0.1:8766/api/tasks/<tid>/sources/nginx_access/alerts"
```

**改完必须验证命中数。** 规则保存成功 ≠ 规则能命中：scope 写错、字段名写错、正则语法对但语义不对，都会静默返回 0。

## 6. 结论必须挂证据

AI 给结论时，**每条都要能指回具体的行**：

1. 从 `alerts` 里拿命中规则的 `hits`，每个 hit 带 `id`（行号）
2. 从 `query` 里按 `id` 精确取原文
3. 结论写成「判断 + 证据行 id + 一行原文摘要」

不要给"发现可疑活动"这种没有出处的结论。用户点不回原文的判断，在这个工具里等于没做。

## 7. 坑

| 坑 | 表现 | 处理 |
|---|---|---|
| **`filters` 参数** | 传了直接 400 | 筛选只能用 `fk`（字段=值）或 `colf`（列条件），没有 `filters` |
| 前端缓存 | 改了前端看不到效果 | `live.js?v=N` 要同步升版本号 |
| 系统代理 | 请求打到代理上超时 | `--noproxy '*'` / `ProxyHandler({})` |
| 源不在任务里 | 导入 400 | 先 `PATCH /api/tasks/{id}/sources` 加进去 |
| 模板改完没重导 | 新列全空 | 模板只作用于之后导入的数据 |
| 规则 scope 写错 | 保存成功、命中 0 | 核对 scope 与源的 kind 是否匹配 |
| 规则写了 `all` | API 保存直接 400；直接改文件则不命中也不报错 | 没有 `all`，AND 直接平铺字段 |
| 保存规则报 400 | 多半是漏了 `false_positive` 或 `severity` 用了 critical | 见「保存时的硬校验」 |
| 正则模板试解析失败 | `/api/formats/preview` 只认 nginx log_format | 正则模板保存绑定源后，用 `/api/preview` 带 `source_id` |
| NULL 与空串 | 统计里"缺失"和"空值"混了 | 解析器把 `-` 落成 NULL 还是字符串，影响 `exists` 判断 |

## 8. 查询接口的参数（最容易写错的一处）

`POST /api/tasks/{id}/query` 的 body：

```json
{
  "source_id": "nginx_access",
  "size": 100,                       // 1-2000
  "page": 1,
  "sort": {"k": "ts", "dir": -1},    // dir: 1 升序 / -1 降序
  "fk":   {"status": "404"},         // 字段 = 值（精确，按文本比）
  "colf": {                          // 列条件，只支持三种写法
    "path": {"q": "upload"},         //   子串（不区分大小写）
    "ip":   {"vals": ["1.2.3.4"]},   //   IN
    "ts":   {"from": 1762300000000, "to": 1762399999999}   // 仅 ts 支持区间，毫秒
  },
  "q": "/union select/i",            // 全文搜 raw，/.../ 是正则，末尾 i 忽略大小写
  "ex404": true,                     // 快捷：排除 404
  "exStatic": true,                  // 快捷：排除静态资源
  "exProbe": true,                   // 快捷：排除探活 UA
  "omit": ["raw"],                   // 不返回大字段，列表页常用
  "cursor": {"id": 12345}            // 游标分页，比 page 快
}
```

**没有 `filters` 参数**，传了会 400（历史上很多人踩过，接口故意报错而不是静默忽略）。

## 9. API 速查

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| GET | `/api/bootstrap` | 组件、日志源、模板全量 |
| GET/POST | `/api/tasks` | 列表 / 新建 |
| GET/DELETE | `/api/tasks/{id}` | 详情（含 evidence）/ 删除 |
| PATCH | `/api/tasks/{id}/sources` | 增删任务的日志源（body: `{"source_ids":[...]}`） |
| POST | `/api/tasks/{id}/imports` | 上传文件（multipart） |
| POST | `/api/tasks/{id}/imports/text` | 文本导入 |
| GET/DELETE | `/api/tasks/{id}/imports[/{iid}]` | 导入历史 / 回滚整次导入 |
| POST | `/api/tasks/{id}/query` | 参数化查询（筛选、排序、游标分页） |
| GET | `/api/tasks/{id}/sources/{sid}/stats` | 统计（`?window=` 秒） |
| GET | `/api/tasks/{id}/sources/{sid}/alerts` | 告警 |
| GET/POST/PUT/DELETE | `/api/rules*` | 规则 CRUD、`/errors` 加载错误、`/reset` 重置 |
| GET/POST/DELETE | `/api/formats*` | 模板 CRUD、`/preview` 试解析、`/detect` 识别、`/presets` 内置参考 |
| GET/POST/DELETE | `/api/sources/custom*` | 自定义日志源 |
| POST | `/api/preview` | 导入前预览解析结果 |

交互式文档：`http://127.0.0.1:8766/api/docs`
