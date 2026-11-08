"""把 row 规则的 match 条件翻译成 DuckDB SQL。

背景：`alerts()` 原来把整表连 `raw` 原文拉进 Python 再逐行跑正则，2.7 万行
要 2 秒、1000 万行要 19 GB 内存。这里把条件下沉到引擎里执行，内存与表大小
无关——DuckDB 是列存，`count(*) FILTER (WHERE ...)` 一次扫描就能算完全部规则。

只适用于 DuckDB：依赖 `regexp_matches` / `strpos` / `FILTER` 子句，SQLite 都
没有。调用方必须先用 `available()` 判断，翻译失败要用 `Unsupported` 回退到
原来的 Python 逐行实现（保持语义完全一致）。

已知不能翻译的情形（会抛 Unsupported，交给 Python 兜底）：
- 正则含 lookaround `(?=...)` / `(?<=...)`：DuckDB 底层是 RE2，不支持
- 正则含反向引用 `\\1`
- 出现本模块未覆盖的操作符（见 `OPS`），宁可回退也不猜语义
"""
from __future__ import annotations

import re
from typing import Any

# 与 rule_engine.condition 的 op 集合保持同步；多一个未知 op 就回退
OPS = {
    "eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte",
    "contains", "icontains", "contains_any", "icontains_any",
    "starts_with", "ends_with", "regex", "iregex", "not_regex",
    "exists", "not_exists", "len_lt", "len_gt", "len_eq",
}

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_LOOKAROUND = ("(?=", "(?!", "(?<=", "(?<!")
_BACKREF = re.compile(r"\\[1-9]")
_NUM = re.compile(r"-?\d+(?:\.\d+)?")
_GROUP_KEYS = ("any", "all", "not")


class Unsupported(Exception):
    """该规则无法安全翻译成 SQL，调用方应回退到 Python 逐行判断。"""


def ident(name: Any) -> str:
    text = str(name)
    if not _IDENT.match(text):
        raise Unsupported("非法字段名 %r" % text)
    return '"' + text + '"'


def available(store: Any) -> bool:
    """只有 DuckDB 存储支持下推；其他引擎一律回退。"""
    return str(getattr(store, "ENGINE", "")).lower() == "duckdb"


def _check_pattern(pattern: str) -> None:
    for token in _LOOKAROUND:
        if token in pattern:
            raise Unsupported("正则含 lookaround（RE2 不支持）：" + token)
    if _BACKREF.search(pattern):
        raise Unsupported("正则含反向引用（RE2 不支持）")


def _text(col: str) -> str:
    """统一按文本比较：`compare()` 走的是宽松相等，转成文本后语义一致。"""
    return "COALESCE(CAST(%s AS VARCHAR), '')" % col


def field_sql(field: str, spec: dict[str, Any], params: list[Any]) -> str:
    """单个字段的多个操作符之间是 AND。"""
    if not isinstance(spec, dict):
        raise Unsupported("字段条件不是对象")
    col = ident(field)
    text = _text(col)
    parts: list[str] = []
    for op, raw in spec.items():
        if op not in OPS:
            raise Unsupported("未知操作符 " + str(op))
        if op == "eq":
            if _NUM.fullmatch(str(raw)):
                # REAL 列 CAST 成 VARCHAR 是 '1.0'，与规则的 '1' 文本不等但数值相等；
                # Python 侧 compare() 是宽松相等，这里必须对齐，否则两边命中数不一致
                parts.append("CAST(%s AS REAL) = CAST(? AS REAL)" % col)
                params.append(str(raw))
            else:
                parts.append("%s = ?" % text)
                params.append(str(raw))
        elif op == "ne":
            if _NUM.fullmatch(str(raw)):
                parts.append("COALESCE(CAST(%s AS REAL) <> CAST(? AS REAL), TRUE)" % col)
                params.append(str(raw))
            else:
                parts.append("%s <> ?" % text)
                params.append(str(raw))
        elif op == "in":
            values = list(raw)
            if not values:
                raise Unsupported("in 的空列表")
            parts.append("%s IN (%s)" % (text, ", ".join(["?"] * len(values))))
            params.extend(str(v) for v in values)
        elif op == "not_in":
            values = list(raw)
            if not values:
                raise Unsupported("not_in 的空列表")
            parts.append("%s NOT IN (%s)" % (text, ", ".join(["?"] * len(values))))
            params.extend(str(v) for v in values)
        elif op in ("gt", "gte", "lt", "lte"):
            sqlop = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
            # 与 condition() 一致：两侧都按 float 比，VARCHAR 列也能用
            parts.append("TRY_CAST(%s AS DOUBLE) %s ?" % (col, sqlop))
            params.append(float(raw))
        elif op == "contains":
            parts.append("strpos(%s, ?) > 0" % text)
            params.append(str(raw))
        elif op == "icontains":
            parts.append("strpos(lower(%s), lower(?)) > 0" % text)
            params.append(str(raw))
        elif op == "contains_any":
            values = list(raw)
            if not values:
                raise Unsupported("contains_any 的空列表")
            parts.append("(" + " OR ".join("strpos(%s, ?) > 0" % text for _ in values) + ")")
            params.extend(str(v) for v in values)
        elif op == "icontains_any":
            values = list(raw)
            if not values:
                raise Unsupported("icontains_any 的空列表")
            parts.append("(" + " OR ".join("strpos(lower(%s), lower(?)) > 0" % text for _ in values) + ")")
            params.extend(str(v) for v in values)
        elif op == "starts_with":
            parts.append("%s LIKE ?" % text)
            params.append(str(raw) + "%")
        elif op == "ends_with":
            parts.append("%s LIKE ?" % text)
            params.append("%" + str(raw))
        elif op in ("regex", "iregex"):
            _check_pattern(str(raw))
            parts.append("regexp_matches(%s, ?%s)" % (text, ", 'i'" if op == "iregex" else ""))
            params.append(str(raw))
        elif op == "not_regex":
            _check_pattern(str(raw))
            parts.append("NOT regexp_matches(%s, ?)" % text)
            params.append(str(raw))
        elif op in ("exists", "not_exists"):
            nonempty = "(%s IS NOT NULL AND CAST(%s AS VARCHAR) <> '')" % (col, col)
            want = bool(raw) if op == "exists" else not bool(raw)
            parts.append(nonempty if want else "NOT " + nonempty)
        elif op == "len_lt":
            parts.append("length(%s) < ?" % text)
            params.append(int(raw))
        elif op == "len_gt":
            parts.append("length(%s) > ?" % text)
            params.append(int(raw))
        elif op == "len_eq":
            parts.append("length(%s) = ?" % text)
            params.append(int(raw))
    if not parts:
        raise Unsupported("空条件")
    return "(" + " AND ".join(parts) + ")"


def match_sql(node: Any) -> tuple[str, list[Any]]:
    """把 match 树翻成 WHERE 片段。`any`→OR、`all`→AND、`not`→NOT。"""
    if not isinstance(node, dict) or not node:
        raise Unsupported("match 不是非空对象")
    params: list[Any] = []
    parts: list[str] = []
    for key, spec in node.items():
        if key == "any":
            if not isinstance(spec, list) or not spec:
                raise Unsupported("any 不是非空数组")
            subs = []
            for item in spec:
                sql, sub_params = match_sql(item)
                subs.append(sql)
                params.extend(sub_params)
            parts.append("(" + " OR ".join(subs) + ")")
        elif key == "not":
            sql, sub_params = match_sql(spec)
            parts.append("NOT " + sql)
            params.extend(sub_params)
        elif key == "all":
            # matches() 只认 any / not；规则里出现 all 会被它当字段处理并报错。
            # 这里必须同样拒绝，否则 SQL 能跑、Python 跑不了，两套语义分叉。
            raise Unsupported("matches() 不支持 all 组合")
        elif key == "agg":
            raise Unsupported("聚合规则不能按行翻译")
        else:
            parts.append(field_sql(key, spec, params))
    if not parts:
        raise Unsupported("空 match")
    return "(" + " AND ".join(parts) + ")", params


def translate(rule: dict[str, Any]) -> tuple[str, list[Any]]:
    """规则 → (WHERE 片段, 参数)。不能翻译就抛 Unsupported。"""
    if rule.get("params"):
        # resolve_param 依赖运行时取值，SQL 里没法安全展开
        raise Unsupported("规则带 params 占位符")
    return match_sql((rule.get("match") or {}))


def counts_sql(table: str, rules: list[dict[str, Any]], task_id: str,
               source_id: str) -> tuple[str, list[Any]]:
    """一条 SQL 算完全部规则的命中数：一次扫描，N 个 FILTER 列。"""
    if not rules:
        raise Unsupported("没有可下推的规则")
    selects: list[str] = []
    params: list[Any] = []
    for index, rule in enumerate(rules):
        where, sub = translate(rule)
        selects.append("count(*) FILTER (WHERE %s) AS %s" % (where, ident("c%d" % index)))
        params.extend(sub)
    params.extend([task_id, source_id])
    sql = "SELECT %s FROM %s WHERE task_id=? AND source_id=?" % (", ".join(selects), ident(table))
    return sql, params


def hits_sql(table: str, rule: dict[str, Any], task_id: str, source_id: str,
             limit: int = 100) -> tuple[str, list[Any]]:
    """只把命中行取回来做样本，最多 limit 行。"""
    where, params = translate(rule)
    sql = "SELECT * FROM %s WHERE task_id=? AND source_id=? AND %s ORDER BY id LIMIT ?" % (
        ident(table), where)
    return sql, [task_id, source_id] + list(params) + [int(limit)]


def needs_raw(rule: dict[str, Any]) -> bool:
    """规则是否引用了 raw 列（决定流式取数时能不能裁掉原文）。"""
    def walk(node: Any) -> bool:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _GROUP_KEYS:
                    if walk(value):
                        return True
                elif key == "raw":
                    return True
                elif isinstance(value, dict) and walk(value):
                    return True
        elif isinstance(node, list):
            for item in node:
                if walk(item):
                    return True
        return False

    return walk(rule.get("match") or {})
