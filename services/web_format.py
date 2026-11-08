"""日志格式模板：把「一行日志怎么切字段」存成 JSON，按源绑定。

两种写法：

1. kind = "nginx"   —— 整段 log_format 粘进来，$变量 自动编译成正则
2. kind = "regex"   —— 自己给正则，命名捕获组就是字段名

为什么要有第二种：nginx 用 $remote_addr、Apache 用 %h、Tomcat 用 %a、
Caddy 用 {remote_host}，变量名各家都不一样，只认 nginx 语法覆盖不了。
正则方案对所有厂商都成立——只要能用正则切出字段，就能解析。

字段名有语义：ip / ts / method / path / status / bytes / ua / ref / xff /
host / user 会被下游当成标准字段用（排行、频次、基线、规则）；
其余任意名字（request_time、upstream_addr、用户自己起的名）导入时各建一列。
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FORMAT_DIR = Path(__file__).resolve().parents[1] / "formats"
TOKEN_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# 变量 → (列名, 类型)。类型 None 表示不落列（$request 会拆成 method + path）。
VARIABLES = {
    "remote_addr": ("ip", "TEXT"),
    "http_x_forwarded_for": ("xff", "TEXT"),
    "http_x_real_ip": ("xff", "TEXT"),
    "host": ("host", "TEXT"),
    "server_name": ("host", "TEXT"),
    "remote_user": ("user", "TEXT"),
    "time_local": ("ts", "INTEGER"),
    "time_iso8601": ("ts", "INTEGER"),
    "request": ("request", None),
    "request_method": ("method", "TEXT"),
    "request_uri": ("path", "TEXT"),
    "uri": ("path", "TEXT"),
    "document_uri": ("path", "TEXT"),
    "status": ("status", "INTEGER"),
    "body_bytes_sent": ("bytes", "INTEGER"),
    "bytes_sent": ("bytes", "INTEGER"),
    "http_referer": ("ref", "TEXT"),
    "http_user_agent": ("ua", "TEXT"),
}

# 语义字段 → 列类型。正则模板里组名直接用这些名字时套用。
# 端口按 INTEGER：文本列排序会变成 100 < 22 < 80，找异常端口就废了。
SEMANTIC_TYPES = {
    "ip": "TEXT",
    "srcip": "TEXT",
    "dstip": "TEXT",
    "srcport": "INTEGER",
    "dstport": "INTEGER",
    "xff": "TEXT",
    "host": "TEXT",
    "user": "TEXT",
    "ts": "INTEGER",
    "method": "TEXT",
    "path": "TEXT",
    "status": "INTEGER",
    "bytes": "INTEGER",
    "ua": "TEXT",
    "ref": "TEXT",
}

# 未在 VARIABLES 里的变量按变量名建列。这里只决定类型，没列出的默认 TEXT：
# 宁可存字符串也不要因为 "-" 或 "0.1, 0.2" 这类值把数值列写坏。
EXTRA_TYPES = {
    "request_time": "REAL",
    "request_length": "INTEGER",
    "msec": "REAL",
    "connection": "INTEGER",
    "connection_requests": "INTEGER",
    "server_port": "INTEGER",
    "remote_port": "INTEGER",
    "upstream_status": "TEXT",       # 可能是 "200, 502" 列表
    "upstream_addr": "TEXT",         # 可能是 "10.0.0.1:80, 10.0.0.2:80"
    "upstream_response_time": "TEXT",
    "upstream_connect_time": "TEXT",
    "upstream_header_time": "TEXT",
    "upstream_cache_status": "TEXT",
}

# 表内固定列，不能被模板字段占用
RESERVED_COLUMNS = {"id", "task_id", "import_id", "line_no", "raw", "source_id", "ext"}
COLUMN_RE = re.compile(r"[^A-Za-z0-9_]+")

# 相邻两个变量都用 .+? 会互相抢字符（"200 123" 会切成 "2" 和 "00"），
# 已知字段给出确定形状，剩下的才退回非贪婪。
FIELD_PATTERNS = {
    "ip": r"\S+",
    "srcip": r"\S+",
    "dstip": r"\S+",
    "srcport": r"\d+|-",
    "dstport": r"\d+|-",
    "xff": r'[^"\s]*',
    "host": r'[^"\s]+',
    "user": r"\S+",
    "ts": r"[^\]]+",
    "request": r'[^"]*',
    "method": r"[A-Z]+",
    "path": r"\S+",
    "status": r"\d{3}|-",
    "bytes": r"\d+|-",
    "ref": r'[^"]*',
    "ua": r'[^"]*',
}

# 时间格式：模板没指定 time_format 时按这些顺序试
TIME_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%b %d %H:%M:%S",
)


# ---------- 编译 ----------

def column_for(variable: str) -> tuple[str, str]:
    """nginx 变量名 → (列名, 类型)。已知变量走语义映射，未知变量用变量名本身。"""
    spec = VARIABLES.get(variable)
    if spec:
        return spec
    name = COLUMN_RE.sub("_", variable).strip("_").lower()
    if not name or not name[0].isalpha():
        name = "v_" + name
    if name in RESERVED_COLUMNS:
        name = "x_" + name
    return name, EXTRA_TYPES.get(variable, "TEXT")


def normalize_format(text: str) -> str:
    """把 nginx 配置片段还原成单行模板。"""
    s = (text or "").strip().lstrip("\ufeff")
    if not s:
        raise ValueError("log_format 内容为空")
    s = re.sub(r"^\s*log_format\s+\S+\s+", "", s, flags=re.I)
    s = s.rstrip().rstrip(";").strip()
    # 配置里跨行靠相邻单引号拼接，把引号内容按顺序粘回去
    parts = re.findall(r"'([^']*)'", s)
    if parts:
        s = "".join(parts)
    return s


def _compile_nginx(text: str) -> dict[str, Any]:
    template = normalize_format(text)
    if "$" not in template:
        raise ValueError("模板里没有 $变量，无法判断字段位置")
    parts: list[str] = []
    groups: list[tuple[str, str]] = []
    columns: dict[str, str] = {}
    pos = 0
    for match in TOKEN_RE.finditer(template):
        literal = template[pos:match.start()]
        if literal:
            parts.append(re.escape(literal))
        field, ctype = column_for(match.group(0)[1:])
        if ctype is not None and field not in columns:
            columns[field] = ctype      # $request 这类派生字段不进 columns
        group = "f%d" % len(groups)
        groups.append((group, field))
        parts.append("(?P<%s>%s)" % (group, FIELD_PATTERNS.get(field, ".+?")))
        pos = match.end()
    tail = template[pos:]
    if tail:
        parts.append(re.escape(tail))
    if not groups:
        raise ValueError("模板里没有可识别的变量")
    return {
        "kind": "nginx",
        "template": template,
        "pattern": re.compile("^" + "".join(parts) + r"\s*$"),
        "groups": groups,
        "columns": columns,
        "time_format": None,
    }


def _column_type(name: str, custom: dict[str, str]) -> str:
    if name in custom:
        value = str(custom[name]).upper()
        return value if value in ("TEXT", "INTEGER", "REAL") else "TEXT"
    if name in SEMANTIC_TYPES:
        return SEMANTIC_TYPES[name]
    return EXTRA_TYPES.get(name, "TEXT")


def _compile_regex(spec: dict[str, Any]) -> dict[str, Any]:
    text = str(spec.get("pattern") or "").strip()
    if not text:
        raise ValueError("pattern 不能为空")
    try:
        pattern = re.compile(text)
    except re.error as exc:
        raise ValueError("正则写法有问题：%s" % exc) from exc
    names = sorted(pattern.groupindex, key=lambda n: pattern.groupindex[n])
    if not names:
        raise ValueError("正则里没有命名捕获组，字段名要用 (?P<ip>...) 这种写法")
    custom = spec.get("types") if isinstance(spec.get("types"), dict) else {}
    columns: dict[str, str] = {}
    for name in names:
        if not FIELD_NAME_RE.match(name):
            raise ValueError("字段名「%s」只能用字母、数字、下划线，且不能以数字开头" % name)
        if name in RESERVED_COLUMNS:
            raise ValueError("字段名「%s」是内部保留列，换一个名字" % name)
        if name == "request":
            continue                 # $request 同款：拆成 method + path
        columns[name] = _column_type(name, custom)
    if not columns:
        raise ValueError("正则里至少要有一个能落库的字段（不能只有 request）")
    return {
        "kind": "regex",
        "pattern_text": text,
        "pattern": pattern,
        "groups": [(name, name) for name in names],
        "columns": columns,
        "time_format": spec.get("time_format") or None,
    }


def compile_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """把模板 JSON 编译成可用于匹配的结构。两种 kind 统一入口。"""
    if not isinstance(spec, dict):
        raise ValueError("模板必须是 JSON 对象")
    kind = str(spec.get("kind") or "nginx").strip().lower()
    if kind == "nginx":
        return _compile_nginx(str(spec.get("template") or ""))
    if kind == "regex":
        return _compile_regex(spec)
    raise ValueError("kind 只能是 nginx 或 regex，当前是「%s」" % kind)


# 兼容旧调用：只给 nginx 文本
def compile_format(text: str) -> dict[str, Any]:
    return _compile_nginx(text)


# ---------- 取值 ----------

def _epoch_ms(text: str, time_format: str | None = None) -> int | None:
    raw = (text or "").strip()
    if not raw or raw == "-":
        return None
    formats = ([time_format] if time_format else []) + list(TIME_FORMATS)
    for fmt in formats:
        if not fmt:
            continue
        try:
            return int(datetime.strptime(raw, fmt).timestamp() * 1000)
        except ValueError:
            continue
    try:                       # 纯数字按秒或毫秒
        number = float(raw)
        return int(number * 1000) if number < 1e11 else int(number)
    except ValueError:
        pass
    try:
        return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def _integer(text: str) -> int | None:
    raw = (text or "").strip()
    return int(raw) if re.fullmatch(r"-?\d+", raw) else None


def parse_line(compiled: dict[str, Any], line: str) -> dict[str, Any]:
    """按编译结果取字段。模板里没有的字段不会出现在返回值里。"""
    match = compiled["pattern"].match(line)
    if not match:
        raise ValueError("与自定义日志格式不匹配")
    raw: dict[str, str] = {}
    for group, field in compiled["groups"]:
        if not field:
            continue
        try:
            value = match.group(group)
        except IndexError:          # 可选组没参与匹配
            continue
        if value is not None:
            raw[field] = value
    if not raw:
        raise ValueError("匹配到了，但没有取到任何字段")

    row: dict[str, Any] = {}
    if "ts" in raw:
        row["ts"] = _epoch_ms(raw["ts"], compiled.get("time_format"))
    if "ip" in raw:
        row["ip"] = raw["ip"].strip() or None
    if "xff" in raw:
        xff = raw["xff"].strip().strip('"')
        row["xff"] = xff or None
    if "host" in raw:
        host = raw["host"].strip().strip('"')
        row["host"] = host or None
    if "request" in raw:
        parts = raw["request"].split(" ", 2)
        row["method"] = parts[0] or None
        row["path"] = parts[1] if len(parts) > 1 else raw["request"] or None
    if "method" in raw:
        row["method"] = raw["method"].strip() or None
    if "path" in raw:
        row["path"] = raw["path"].strip() or None
    if "status" in raw:
        row["status"] = _integer(raw["status"])
    if "bytes" in raw:
        row["bytes"] = _integer(raw["bytes"])
    for port in ("srcport", "dstport"):
        if port in raw:
            row[port] = _integer(raw[port])
    if "ua" in raw:
        row["ua"] = raw["ua"].strip().strip('"') or None
    if "ref" in raw:
        row["ref"] = raw["ref"].strip().strip('"') or None
    if "user" in raw:
        user = raw["user"].strip()
        row["user"] = user if user and user != "-" else None
    # 模板里其余字段统一去引号后落库；"-" 存 NULL，否则统计里会多一个 "-" 分组
    for field, value in raw.items():
        if field in row or field in ("request", "ts", "status", "bytes"):
            continue
        text = (value or "").strip().strip('"')
        row[field] = text if text and text != "-" else None
    return row


# ---------- 厂商识别 ----------

# 常见几家访问日志的写法。命中就给出可直接用的 JSON 模板，不用用户自己写正则。
DETECT_CANDIDATES: list[dict[str, Any]] = [
    {
        "key": "vhost", "order": 50,
        "vendor": "nginx / Apache combined（带 vhost 前缀）",
        "kind": "regex",
        "pattern": r'^(?P<host>\S+) (?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"',
        "time_format": "%d/%b/%Y:%H:%M:%S %z",
        "sample": 'shop.example.com 1.2.3.4 - - [04/Nov/2026:09:00:00 +0800] "GET /a HTTP/1.1" 200 123 "-" "curl/8"',
        "note": "前面多了站点名，常见于多站点共用一个 access.log",
    },
    {
        "key": "combined", "order": 40,
        "vendor": "nginx / Apache combined（标准）",
        "kind": "regex",
        "pattern": r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"',
        "time_format": "%d/%b/%Y:%H:%M:%S %z",
        "sample": '1.2.3.4 - - [04/Nov/2026:09:00:00 +0800] "GET /a HTTP/1.1" 200 123 "-" "curl/8"',
        "note": "最通用的写法，nginx 默认 combined、Apache combined 都是这个形状",
    },
    {
        "key": "clf", "order": 60,
        "vendor": "Apache / Tomcat 公共日志格式（CLF）",
        "kind": "regex",
        "pattern": r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)',
        "time_format": "%d/%b/%Y:%H:%M:%S %z",
        "sample": '192.168.1.5 - frank [04/Nov/2026:09:00:00 +0800] "GET /a.gif HTTP/1.0" 200 2326',
        "note": "没有 Referer 和 UA 两段；Tomcat AccessLogValve 默认 pattern 就是它",
    },
    {
        "key": "iso", "order": 120,
        "vendor": "通用：ISO 时间开头 + IP",
        "kind": "regex",
        "pattern": r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*) (?P<ip>\S+) \S+ "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)',
        "time_format": "%Y-%m-%dT%H:%M:%S%z",
        "sample": '2026-11-04T09:00:00+08:00 10.0.0.7 - "GET /x HTTP/1.1" 200 88',
        "note": "时间在行首、带时区，常见于网关和中间件自己打的访问日志",
    },
]

# 内置格式参考：模板页直接把「系统已经认识哪些格式」列出来。
# order 决定展示顺序，按实际排查中遇到的频率排。
PRESETS: list[dict[str, Any]] = [
    {
        "key": "nginx-format", "order": 10, "name": "main",
        "vendor": "nginx 标准 combined（log_format 写法）",
        "kind": "nginx",
        "template": "log_format main '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"';",
        "sample": '1.2.3.4 - - [04/Nov/2026:09:00:00 +0800] "GET /a HTTP/1.1" 200 123 "-" "curl/8"',
        "note": "服务器配置里没改过 log_format 就用这条",
    },
    {
        "key": "nginx-xff", "order": 20, "name": "nginx-xff",
        "vendor": "nginx 带 XFF（CDN / 反向代理后面）",
        "kind": "regex",
        "pattern": r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)" "(?P<xff>[^"]*)"',
        "time_format": "%d/%b/%Y:%H:%M:%S %z",
        "sample": '10.0.0.5 - - [04/Nov/2026:09:00:00 +0800] "GET /a HTTP/1.1" 200 123 "-" "curl/8" "203.0.113.9, 198.51.100.2"',
        "note": "remote_addr 这时是代理 IP，真实来源在 XFF；按真实 IP 排行要改用 xff 列",
    },
    {
        "key": "nginx-upstream", "order": 30, "name": "nginx-upstream",
        "vendor": "nginx 带 upstream 耗时",
        "kind": "regex",
        "pattern": r'^(?P<ip>\S+) \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) (?P<request_time>\S+) (?P<upstream_response_time>\S+) (?P<upstream_addr>\S+) (?P<upstream_status>\S+)',
        "time_format": "%d/%b/%Y:%H:%M:%S %z",
        "types": {"request_time": "REAL"},
        "sample": '10.0.0.5 [04/Nov/2026:09:00:00 +0800] "GET /a HTTP/1.1" 200 123 0.052 0.048 172.16.0.9:8080 200',
        "note": "末尾多四个值；request_time 按小数建列，能直接排慢请求",
    },
    {
        "key": "nginx-error", "order": 70, "name": "nginx-error",
        "vendor": "nginx error.log",
        "kind": "regex",
        "pattern": r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#\d+: (?P<msg>.*)',
        "time_format": "%Y/%m/%d %H:%M:%S",
        "sample": '2026/11/04 09:00:00 [error] 1234#0: *5678 open() "/var/www/a.php" failed (2: No such file or directory)',
        "note": "没有来源 IP；排查 webshell 试探时看 open() 失败和 level",
    },
    {
        "key": "haproxy", "order": 80, "name": "haproxy",
        "vendor": "HAProxy HTTP 日志",
        "kind": "regex",
        "pattern": r'^(?:.*?haproxy\[\d+\]:\s+)?(?P<ip>[0-9.]+):\d+ \[(?P<ts>[^\]]+)\] (?P<frontend>\S+) (?P<backend>\S+) \S+ (?P<status>\d{3}) (?P<bytes>\d+) .*?"(?P<request>[^"]*)"',
        "time_format": "%d/%b/%Y:%H:%M:%S.%f",
        "sample": 'Feb  6 12:12:12 localhost haproxy[12345]: 10.0.0.1:51234 [06/Feb/2026:12:12:12.000] web app/srv1 0/0/1/1/3 200 1234 - - ---- 5/4/0/0/0 0/0 "GET /a HTTP/1.1"',
        "note": "客户端 IP 在行首且带端口；frontend / backend 单独成列",
    },
    {
        "key": "squid", "order": 90, "name": "squid",
        "vendor": "Squid 代理访问日志",
        "kind": "regex",
        "pattern": r'^(?P<ts>\d+\.\d+) (?P<elapsed>\d+) (?P<ip>\S+) (?P<cache>\S+)/(?P<status>\d{3}) (?P<bytes>\d+) (?P<method>[A-Z]+) (?P<url>\S+) (?P<user>\S+) (?P<hier>\S+) (?P<ctype>\S+)',
        "sample": "1697691234.123 45 10.0.0.1 TCP_MISS/200 1234 GET http://example.com/a - HIER_DIRECT/93.184.216.34 text/html",
        "note": "时间是 Unix 秒；完整 URL 在 url 列，缓存命中情况在 cache 列",
    },
    {
        "key": "egress", "order": 95, "name": "egress-access",
        "vendor": "出站访问（代理 / 网关 / 堡垒机）",
        "kind": "regex",
        "pattern": r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<ip>[0-9.]+) -> (?P<dstip>[0-9.]+):(?P<dstport>\d+) (?P<protocol>[A-Z]+) (?P<action>[A-Z]+) (?P<bytes>\d+)',
        "time_format": "%Y-%m-%d %H:%M:%S",
        "sample": "2026-11-04 09:00:00 10.0.0.21 -> 93.184.216.34:443 TCP ALLOW 1420",
        "note": "出站视角：ip 是内部发起方，dstip / dstport 是访问目标；排行切到「目的 IP」看外联",
    },
    {
        "key": "log4j", "order": 100, "name": "java-log4j",
        "vendor": "Java 应用（log4j / logback 默认格式）",
        "kind": "regex",
        "pattern": r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+ (?P<level>[A-Z]+) \[(?P<thread>[^\]]+)\] (?P<logger>\S+) - (?P<msg>.*)',
        "time_format": "%Y-%m-%d %H:%M:%S",
        "sample": "2026-11-04 09:00:00.123 ERROR [http-nio-8080-exec-1] com.x.Controller - 登录失败 user=admin ip=1.2.3.4",
        "note": "级别、线程、类名分开成列，正文整段进 msg，规则按 msg 匹配",
    },
    {
        "key": "app-custom", "order": 110, "name": "app-access",
        "vendor": "自研应用：任意格式 + 自定义列类型",
        "kind": "regex",
        "pattern": r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<ip>[0-9.]+) (?P<method>[A-Z]+) (?P<path>\S+) (?P<status>\d{3}) (?P<cost_ms>\d+)',
        "time_format": "%Y-%m-%d %H:%M:%S",
        "types": {"cost_ms": "INTEGER"},
        "sample": "2026-11-04 09:00:00 10.0.0.7 GET /api/order 200 35",
        "note": "应用自己打的日志：时间在行首、末尾多一个耗时，耗时按整数建列",
    },
    {
        "key": "json", "order": 200, "name": "json",
        "vendor": "JSON 行（Caddy / ELK / 自研）",
        "kind": "none",
        "sample": '{"@timestamp":"2026-11-04T09:00:00Z","host":{"name":"w1"},"message":"ok"}',
        "note": "不用模板：建日志源时解析格式选 json，导入时选「JSON 行」，字段名自动识别",
    },
    {
        "key": "w3c", "order": 210, "name": "w3c",
        "vendor": "IIS / W3C 扩展日志",
        "kind": "none",
        "sample": "#Software: Microsoft Internet Information Services 10.0\n#Fields: date time s-ip cs-method cs-uri-stem sc-status",
        "note": "不用模板：建日志源时解析格式选 w3c，表头自带字段名，顺序变了也不影响",
    },
]


def _preset_json(item: dict[str, Any]) -> str:
    """把预设还原成一份可直接保存的模板 JSON，供页面展示和复制。"""
    payload: dict[str, Any] = {"name": item.get("name") or item["key"], "kind": item["kind"]}
    if item["kind"] == "nginx":
        payload["template"] = item.get("template", "")
    else:
        payload["pattern"] = item.get("pattern", "")
        if item.get("time_format"):
            payload["time_format"] = item["time_format"]
        if item.get("types"):
            payload["types"] = item["types"]
    if item.get("note"):
        payload["note"] = item["note"]
    payload["source_ids"] = []          # 保存时勾选日志源后再填
    return json.dumps(payload, ensure_ascii=False, indent=2)


def presets() -> list[dict[str, Any]]:
    """内置格式参考。能编译的算出字段清单和模板 JSON，前端直接展示。"""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, source in enumerate(PRESETS + DETECT_CANDIDATES):
        key = source.get("key") or ("detect-%d" % index)
        if key in seen:                 # 同一个格式只列一次
            continue
        seen.add(key)
        item = dict(source)
        item["key"] = key
        item.setdefault("order", 900)
        item.setdefault("note", "")
        item.setdefault("name", key)
        if item["kind"] == "none":
            item["fields"] = []
            item["code"] = ""
            items.append(item)
            continue
        try:
            compiled = compile_spec(item)
        except ValueError as exc:       # 内置示例自己写错，不能把整页弄崩
            item["fields"] = []
            item["code"] = ""
            item["note"] = "示例有误：%s" % exc
            items.append(item)
            continue
        item["fields"] = list(compiled["columns"])
        item["code"] = _preset_json(item)
        items.append(item)
    items.sort(key=lambda x: x["order"])
    return items


def detect_format(line: str) -> dict[str, Any]:
    """拿一行真实日志猜是哪家的格式，返回可直接保存的模板 JSON。"""
    text = (line or "").strip()
    if not text:
        raise ValueError("先粘一行日志")
    if text.startswith("{"):
        return {
            "kind": "none",
            "vendor": "JSON 日志（Caddy / ELK / 自研）",
            "note": "这种格式不用模板：新建日志源时解析格式选 json，导入时选「JSON 行」即可，字段名会在解析时自动识别。",
        }
    if text.startswith("#Fields:") or text.startswith("#Software:"):
        return {
            "kind": "none",
            "vendor": "IIS / W3C 扩展日志",
            "note": "这种格式不用模板：新建日志源时解析格式选 w3c。表头里有 #Fields 一行，字段名自动对齐，顺序变了也不影响。",
        }
    tried = []
    for item in DETECT_CANDIDATES:
        spec = {"kind": item["kind"], "pattern": item["pattern"], "time_format": item["time_format"]}
        try:
            compiled = compile_spec(spec)
            row = parse_line(compiled, text)
        except ValueError as exc:
            tried.append("%s：%s" % (item["vendor"], exc))
            continue
        return {
            "kind": item["kind"],
            "vendor": item["vendor"],
            "pattern": item["pattern"],
            "time_format": item["time_format"],
            "fields": list(compiled["columns"]),
            "sample": {k: v for k, v in row.items() if v is not None},
            "note": "已按这家格式生成模板，核对字段无误后保存即可。对方格式和这里不完全一致时，改 pattern 里的 (?P<...>) 分组名。",
        }
    return {
        "kind": "unknown",
        "vendor": "没认出来",
        "tried": tried,
        "note": "这家格式不在内置清单里。用正则自己写：把每个要保留的值用 (?P<字段名>...) 包起来，字段名用 ip / ts / request / status / bytes 这类标准名，其余按需起名。",
    }


# ---------- 编辑说明用的示例 ----------
# 用原始字符串写，反斜杠原样保留，正好是 JSON 里该有的转义层数。
NGINX_SAMPLE = r'''{
  "name": "main",
  "kind": "nginx",
  "template": "log_format main '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"';",
  "source_ids": ["nginx_access"]
}'''

APACHE_SAMPLE = r'''{
  "name": "apache-combined",
  "kind": "regex",
  "pattern": "^(?P<ip>\\S+) \\S+ (?P<user>\\S+) \\[(?P<ts>[^\\]]+)\\] \"(?P<request>[^\"]*)\" (?P<status>\\d{3}) (?P<bytes>\\S+) \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\"",
  "time_format": "%d/%b/%Y:%H:%M:%S %z",
  "source_ids": ["apache_access"]
}'''

SIMPLE_SAMPLE = r'''{
  "name": "自研应用访问日志",
  "kind": "regex",
  "pattern": "^(?P<ts>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) (?P<ip>[0-9.]+) (?P<method>[A-Z]+) (?P<path>\\S+) (?P<status>\\d{3}) (?P<cost_ms>\\d+)",
  "time_format": "%Y-%m-%d %H:%M:%S",
  "types": {"cost_ms": "INTEGER"},
  "note": "应用自己打的日志，时间在前面、末尾多一个耗时",
  "source_ids": ["app_access"]
}'''

SAMPLES = [
    {"title": "nginx：整段 log_format 粘进 template", "text": NGINX_SAMPLE},
    {"title": "Apache / Tomcat：自己写正则，命名组就是字段", "text": APACHE_SAMPLE},
    {"title": "自研应用：任意格式 + 自定义列类型", "text": SIMPLE_SAMPLE},
]


# ---------- 模板存取：一个日志源只挂一个模板，后保存的覆盖前者 ----------

SPEC_KEYS = ("name", "kind", "template", "pattern", "time_format", "types", "note")


def _paths() -> list[Path]:
    FORMAT_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(FORMAT_DIR.glob("*.json"))


def list_formats() -> list[dict[str, Any]]:
    items = []
    for path in _paths():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        data["id"] = data.get("id") or path.stem
        data.setdefault("kind", "nginx")
        items.append(data)
    return items


def format_for_source(source_id: str) -> dict[str, Any] | None:
    for item in list_formats():
        if source_id and source_id in (item.get("source_ids") or []):
            return item
    return None


def compile_item(item: dict[str, Any]) -> dict[str, Any]:
    """已存模板 → 编译结果。旧数据没有 kind 字段，按 nginx 处理。"""
    return compile_spec(item)


def save_format(spec: Any, format_id: str | None = None, source_ids: list[str] | None = None, legacy_id: str | None = None) -> dict[str, Any]:
    # 旧签名 save_format(name, template, source_ids, id) 仍兼容，避免外部脚本一次性全改
    if isinstance(spec, str):
        spec = {"kind": "nginx", "name": spec, "template": format_id or "", "source_ids": source_ids or []}
        format_id = legacy_id
    if not isinstance(spec, dict):
        raise ValueError("模板必须是 JSON 对象")
    compiled = compile_spec(spec)          # 先编译，坏的模板不落盘
    name = str(spec.get("name") or "").strip()
    if not name:
        raise ValueError("name 不能为空")
    source_ids = list(dict.fromkeys(str(s) for s in (spec.get("source_ids") or []) if s))
    if not source_ids:
        raise ValueError("source_ids 不能为空，至少绑一个日志源")

    formats = list_formats()
    if format_id and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", format_id):
        # format_id 会被拼进落盘路径，先于任何查找校验掉
        raise ValueError("模板 id 只允许字母、数字、下划线和中划线")
    old = next((x for x in formats if x["id"] == format_id), None) if format_id else None
    if format_id and old is None:
        raise KeyError("模板不存在")
    # 同一个源只保留一份模板，避免解析时选中哪份看运气；被摘掉的要报给前端，不能静默
    detached = []
    for item in formats:
        if item["id"] == format_id:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(item.get("id") or "")):
            continue   # 磁盘文件里被手改过的非法 id 不碰，防路径穿越
        taken = [s for s in (item.get("source_ids") or []) if s in source_ids]
        if not taken:
            continue
        remain = [s for s in item["source_ids"] if s not in source_ids]
        detached.append({"name": item.get("name") or item["id"], "sources": taken})
        if remain:
            item["source_ids"] = remain
            (FORMAT_DIR / (item["id"] + ".json")).write_text(json.dumps(item, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            (FORMAT_DIR / (item["id"] + ".json")).unlink(missing_ok=True)

    data: dict[str, Any] = {
        "id": format_id or ("fmt_" + uuid.uuid4().hex[:10]),
        "name": name,
        "kind": compiled["kind"],
        "source_ids": source_ids,
        "created_at": (old or {}).get("created_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if compiled["kind"] == "nginx":
        data["template"] = compiled["template"]
    else:
        data["pattern"] = compiled["pattern_text"]
        if spec.get("time_format"):
            data["time_format"] = spec["time_format"]
        if isinstance(spec.get("types"), dict) and spec["types"]:
            data["types"] = {str(k): str(v).upper() for k, v in spec["types"].items()}
    if spec.get("note"):
        data["note"] = str(spec["note"]).strip()

    (FORMAT_DIR / (data["id"] + ".json")).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    data["detached"] = detached
    return data


def format_usage(known_sources: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """模板与源的绑定全貌：哪些源有模板、哪些没有。"""
    items = list_formats()
    bound: dict[str, str] = {}
    for item in items:
        for sid in item.get("source_ids") or []:
            bound[sid] = item.get("name") or item["id"]
    unbound = [s for s in (known_sources or []) if s.get("id") and s["id"] not in bound]
    return {"bound": bound, "unbound": unbound, "total": len(items)}


def delete_format(format_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", format_id or ""):
        raise ValueError("非法模板 ID")
    path = FORMAT_DIR / (format_id + ".json")
    if not path.exists():
        raise KeyError("模板不存在")
    path.unlink()


def preview_spec(spec: dict[str, Any], lines: list[str], limit: int = 20) -> dict[str, Any]:
    compiled = compile_spec(spec)
    rows, errors = [], []
    for index, line in enumerate(lines[:limit], start=1):
        if not line.strip():
            continue
        try:
            row = parse_line(compiled, line)
            rows.append(dict(row, line_no=index, raw=line))
        except ValueError as exc:
            errors.append({"line": index, "error": str(exc)})
    semantic = set(SEMANTIC_TYPES)
    columns = compiled["columns"]
    return {
        "kind": compiled["kind"],
        "pattern": compiled.get("pattern_text") or compiled.get("template"),
        "fields": list(columns),
        "extra": [name for name in columns if name not in semantic],
        "rows": rows,
        "errors": errors,
    }


def preview(template: str, lines: list[str], limit: int = 20) -> dict[str, Any]:
    """兼容旧接口：只给 nginx log_format 文本。"""
    return preview_spec({"kind": "nginx", "template": template}, lines, limit)
