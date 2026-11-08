"""Layered rule loading, matching, custom CRUD and alert evaluation."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Iterable

from storage import Store, now_iso
from services.query import QueryService
from services import sql_rules

ROOT = Path(__file__).resolve().parents[1]
BUILTIN_DIR = ROOT / "rules" / "builtin"
CUSTOM_DIR = ROOT / "rules" / "custom"
SEVERITIES = {"high", "medium", "low"}


def resolve_param(value: Any, rule: dict[str, Any]) -> Any:
    if isinstance(value, dict) and set(value) == {"param"}:
        return (rule.get("params") or {}).get(value["param"])
    return value


def compare(actual: Any, expected: Any) -> bool:
    try:
        return actual == type(actual)(expected)
    except (TypeError, ValueError):
        return actual == expected


_PREFIX_CACHE: dict[tuple[str, bool], list[str] | None] = {}
_REGEX_META = set(".^$*+?()[]{}|\\")


def _split_alternatives(pattern: str) -> list[str] | None:
    """按顶层 | 切分支；不分组的括号会返回 None（说明提取不可靠）。"""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            buf.append(pattern[i:i + 2])
            i += 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return None
        elif ch == "|" and depth == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if depth != 0:
        return None
    parts.append("".join(buf))
    return parts


def _branch_prefix(branch: str) -> str | None:
    """分支开头的字面量；遇到转义或元字符就停（停得早只是过滤变弱，不会错杀）。"""
    out: list[str] = []
    for ch in branch:
        if ch in _REGEX_META:
            break
        out.append(ch)
    return "".join(out)


def regex_prefixes(pattern: str, ignore_case: bool) -> list[str] | None:
    """算出「任一分支必然以此开头」的字面量清单；不可靠时返回 None。

    只用来做否定判断：清单里没有一个出现在文本里，正则必然不匹配，可以安全跳过。
    这是把「逐行跑 4 KB 大正则」降成「先做几次子串查找」的关键——
    实测 3 条通用规则在 2.7 万行 Windows 日志上从 3.1 秒降到 0.2 秒。
    """
    key = (pattern, ignore_case)
    if key in _PREFIX_CACHE:
        return _PREFIX_CACHE[key]
    result: list[str] | None = None
    body = pattern
    if body.startswith("^"):
        body = body[1:]
    # 剥掉最外层包裹的括号，否则整串会被当成单个分支
    if body.startswith("(") and body.endswith(")"):
        branches = _split_alternatives(body[1:-1])
        if branches is None:
            branches = [body]
    else:
        branches = _split_alternatives(body)
    if branches:
        prefixes = [_branch_prefix(b) for b in branches]
        # 每个分支都要有足够长的字面量前缀，否则放弃（`.*`、`\b`、`(?i)` 等都会落到这里）
        if all(p is not None and len(p) >= 2 for p in prefixes):
            result = [p.lower() if ignore_case else p for p in prefixes]
    _PREFIX_CACHE[key] = result
    return result


def condition(actual: Any, expressions: dict[str, Any], rule: dict[str, Any]) -> bool:
    text = "" if actual is None else str(actual)
    for op, raw_expected in expressions.items():
        expected = resolve_param(raw_expected, rule)
        if op == "eq" and not compare(actual, expected):
            return False
        if op == "ne" and compare(actual, expected):
            return False
        if op in ("gt", "gte", "lt", "lte"):
            try:
                left, right = float(actual), float(expected)
            except (TypeError, ValueError):
                return False
            if op == "gt" and not left > right:
                return False
            if op == "gte" and not left >= right:
                return False
            if op == "lt" and not left < right:
                return False
            if op == "lte" and not left <= right:
                return False
        if op == "in" and actual not in expected and text not in [str(x) for x in expected]:
            return False
        if op == "not_in" and (actual in expected or text in [str(x) for x in expected]):
            return False
        if op == "contains" and str(expected) not in text:
            return False
        if op == "icontains" and str(expected).lower() not in text.lower():
            return False
        if op == "contains_any" and not any(str(x) in text for x in expected):
            return False
        if op == "icontains_any" and not any(str(x).lower() in text.lower() for x in expected):
            return False
        if op == "starts_with" and not text.startswith(str(expected)):
            return False
        if op == "ends_with" and not text.endswith(str(expected)):
            return False
        if op in ("regex", "iregex", "not_regex"):
            pattern = str(expected)
            ignore_case = op == "iregex"
            prefixes = regex_prefixes(pattern, ignore_case)
            if prefixes is not None:
                haystack = text.lower() if ignore_case else text
                # 没有任何分支的起始字面量出现过 → 必然不匹配，省掉整串正则
                found = any(p in haystack for p in prefixes) and re.search(pattern, text, re.IGNORECASE if ignore_case else 0) is not None
            else:
                found = re.search(pattern, text, re.IGNORECASE if ignore_case else 0) is not None
            if op == "not_regex" and found:
                return False
            if op != "not_regex" and not found:
                return False
        if op == "len_lt" and not len(text) < int(expected):
            return False
        if op == "len_gt" and not len(text) > int(expected):
            return False
        if op == "len_eq" and not len(text) == int(expected):
            return False
        if op == "exists" and bool(actual in (None, "")) == bool(expected):
            return False
        if op == "not_exists" and bool(actual in (None, "")) != bool(expected):
            return False
    return True


def rule_event_ids(rule: dict[str, Any]) -> set[str]:
    """规则钉死的 eventId 集合；取不到就返回空集，按「需要逐行判断」处理。

    只认 top-level 的 eventId eq / in。写在 any / not 里的不动——那种语义
    不是「必须等于某 ID」，提前筛会漏掉。
    """
    expr = (rule.get("match") or {}).get("eventId")
    if not isinstance(expr, dict):
        return set()
    if "eq" in expr:
        return {str(expr["eq"])}
    if "in" in expr and isinstance(expr["in"], (list, tuple)):
        return {str(x) for x in expr["in"]}
    return set()


def matches(rule: dict[str, Any], row: dict[str, Any], match: dict[str, Any] | None = None) -> bool:
    match = match if match is not None else rule.get("match", {})
    if "agg" in match:
        return False
    # any/not 是同级约束的一部分，不能提前 return 而丢掉 eventId 等其它字段。
    for field, expressions in match.items():
        if field == "any":
            if not any(matches(rule, row, item) for item in expressions):
                return False
        elif field == "not":
            if matches(rule, row, expressions):
                return False
        elif not condition(row.get(field), expressions, rule):
            return False
    return True


def aggregate_window_count(rows: Iterable[dict[str, Any]], rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Count events and distinct values in a true sliding window, once per group."""
    agg = (rule.get("match") or {}).get("agg") or {}
    where = agg.get("where") or {}
    group_by = str(agg.get("group_by") or "")
    distinct = str(agg.get("distinct") or "")
    if not group_by:
        return []
    window = int(agg.get("window_sec", 300)) * 1000
    min_count = int(agg.get("min_count", 10))
    min_distinct = int(agg.get("min_distinct", 0))
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not row.get("ts") or not matches(rule, row, where):
            continue
        key = str(row.get(group_by) or "").strip()
        if not key or key == "-":
            continue
        grouped.setdefault(key, []).append(row)
    hits: list[dict[str, Any]] = []
    for key, items in grouped.items():
        items.sort(key=lambda x: x["ts"])
        left = 0
        values: dict[str, int] = {}
        best: dict[str, Any] | None = None
        for right, row in enumerate(items):
            value = str(row.get(distinct) or "") if distinct else ""
            if value:
                values[value] = values.get(value, 0) + 1
            while row["ts"] - items[left]["ts"] > window:
                old = str(items[left].get(distinct) or "") if distinct else ""
                if old:
                    values[old] -= 1
                    if values[old] <= 0:
                        del values[old]
                left += 1
            count = right - left + 1
            distinct_count = len(values)
            if count >= min_count and distinct_count >= min_distinct:
                if not best or count > best["count"] or (count == best["count"] and distinct_count > best["distinct_count"]):
                    best = {"ts": items[left]["ts"], "count": count, "distinct_count": distinct_count}
        if best:
            hit = {"ts": best["ts"], group_by: key, "count": best["count"], "distinct_count": best["distinct_count"]}
            detail = "%d 秒内 %d 次" % (window // 1000, best["count"])
            if distinct:
                detail += " · %d 个不同%s" % (best["distinct_count"], distinct)
            hit["raw"] = "%s：%s" % (key, detail)
            hits.append(hit)
    return hits


def aggregate_fail_then_success(rows: Iterable[dict[str, Any]], rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect a success preceded by enough failures from the same source."""
    agg = (rule.get("match") or {}).get("agg") or {}
    group_by = str(agg.get("group_by") or "")
    if not group_by:
        return []
    window = int(agg.get("window_sec", 600)) * 1000
    minimum = int(agg.get("min_failures", 5))
    same_user = bool(agg.get("same_user", False))
    fail_match = agg.get("fail") or {}
    success_match = agg.get("success") or {}
    grouped: dict[tuple[str, str], list[tuple[dict[str, Any], str]]] = {}
    for row in rows:
        if not row.get("ts"):
            continue
        key = str(row.get(group_by) or "").strip()
        if not key or key == "-":
            continue
        user = str(row.get("user") or "") if same_user else ""
        if matches(rule, row, fail_match):
            grouped.setdefault((key, user), []).append((row, "fail"))
        elif matches(rule, row, success_match):
            grouped.setdefault((key, user), []).append((row, "success"))
    hits: list[dict[str, Any]] = []
    for (key, _), events in grouped.items():
        pending: list[dict[str, Any]] = []
        for row, event_type in sorted(events, key=lambda x: x[0]["ts"]):
            start = row["ts"] - window
            pending = [failure for failure in pending if failure["ts"] >= start]
            if event_type == "fail":
                pending.append(row)
                continue
            if len(pending) >= minimum:
                hit = dict(row)
                hit[group_by] = key
                hit["failure_count"] = len(pending)
                hit["raw"] = "%s：%d 秒内失败 %d 次后成功；账号 %s" % (key, window // 1000, len(pending), row.get("user") or "-")
                hits.append(hit)
            # 一次成功消费本轮失败序列，后续成功不能复用同一批失败重复报警
            pending = []
    return hits


# ---------------------------------------------------------------------------
# 聚合规则 SQL 下推：用 DuckDB 窗口函数替代 Python 逐行扫描。
# 1000 万行从 20-40s 降到 <1s，且消除 candidates 无界驻留（原 6.4 GB@10M）。
# 翻译失败时抛 Unsupported，调用方回退到 Python 路径。
# ---------------------------------------------------------------------------

def _sql_window_count(conn, table: str, task_id: str, source_id: str,
                      rule: dict, fields: list[str]) -> list[dict[str, Any]]:
    """window_count → RANGE BETWEEN 窗口 + approx_count_distinct。"""
    from services.sql_rules import Unsupported, ident as s_ident, match_sql
    agg = (rule.get("match") or {}).get("agg") or {}
    group_by = str(agg.get("group_by") or "")
    distinct = str(agg.get("distinct") or "")
    if not group_by or group_by not in fields:
        raise Unsupported("group_by 字段不可用")
    window_ms = int(agg.get("window_sec", 300)) * 1000
    min_count = int(agg.get("min_count", 10))
    min_distinct = int(agg.get("min_distinct", 0))
    where = agg.get("where")
    params: list[Any] = [task_id, source_id]
    where_sql = ""
    if where:
        frag, wp = match_sql(where)
        where_sql = " AND " + frag
        params.extend(wp)
    g = s_ident(group_by)
    d_col = s_ident(distinct) if distinct and distinct in fields else None
    distinct_expr = "approx_count_distinct(%s) OVER win AS d" % d_col if d_col else "0 AS d"
    sql = (
        "WITH ev AS (SELECT %s AS gk, ts%s FROM %s WHERE task_id=? AND source_id=? AND ts IS NOT NULL%s),"
        " w AS (SELECT gk, ts, COUNT(*) OVER win AS c, %s"
        " FROM ev WINDOW win AS (PARTITION BY gk ORDER BY ts RANGE BETWEEN %d PRECEDING AND CURRENT ROW))"
        " SELECT gk, max(c) AS cnt, arg_max(d,c) AS distinct_count, arg_max(ts,c) AS peak_ts"
        " FROM w GROUP BY gk HAVING max(c)>=%d"
    ) % (g, (", " + d_col) if d_col else "", s_ident(table), where_sql,
         distinct_expr, window_ms, min_count)
    if min_distinct > 0 and d_col:
        sql += " AND arg_max(d,c)>=%d" % min_distinct
    rows = conn.execute(sql, params).fetchall()
    hits: list[dict[str, Any]] = []
    for r in rows:
        detail = "%d 秒内 %d 次" % (window_ms // 1000, r["cnt"])
        if d_col:
            detail += " · %d 个不同%s" % (r["distinct_count"], distinct)
        hits.append({"ts": r["peak_ts"], group_by: r["gk"], "count": r["cnt"],
                     "distinct_count": r["distinct_count"],
                     "raw": "%s：%s" % (r["gk"], detail)})
    return hits


def _sql_fail_then_success(conn, table: str, task_id: str, source_id: str,
                           rule: dict, fields: list[str]) -> list[dict[str, Any]]:
    """fail_then_success → COUNT FILTER OVER (RANGE ... AND 1 PRECEDING)。"""
    from services.sql_rules import Unsupported, ident as s_ident, match_sql
    agg = (rule.get("match") or {}).get("agg") or {}
    group_by = str(agg.get("group_by") or "")
    if not group_by or group_by not in fields:
        raise Unsupported("group_by 字段不可用")
    window_ms = int(agg.get("window_sec", 600)) * 1000
    minimum = int(agg.get("min_failures", 5))
    same_user = bool(agg.get("same_user", False))
    fail_match = agg.get("fail") or {}
    success_match = agg.get("success") or {}
    if not fail_match or not success_match:
        raise Unsupported("fail/success 条件为空")
    fail_sql, fail_p = match_sql(fail_match)
    succ_sql, succ_p = match_sql(success_match)
    g = s_ident(group_by)
    user_col = ", " + s_ident("user") if same_user and "user" in fields else ""
    partition = "gk" + (", usr" if user_col else "")
    params: list[Any] = [task_id, source_id]
    params.extend(fail_p)
    params.extend(succ_p)
    if same_user and user_col:
        params.extend(fail_p)
        params.extend(succ_p)
    sql = (
        "WITH ev AS (SELECT %s AS gk%s, ts,"
        " CASE WHEN %s THEN 'fail' WHEN %s THEN 'success' END AS result"
        " FROM %s WHERE task_id=? AND source_id=? AND ts IS NOT NULL AND (%s OR %s)),"
        " w AS (SELECT gk%s, ts, result,"
        " COUNT(*) FILTER (WHERE result='fail')"
        " OVER (PARTITION BY %s ORDER BY ts RANGE BETWEEN %d PRECEDING AND 1 PRECEDING) AS fails"
        " FROM ev WHERE result IS NOT NULL)"
        " SELECT gk%s, ts, fails FROM w WHERE result='success' AND fails>=%d"
    ) % (g, user_col.replace(", ", " AS usr, ") if user_col else "",
         fail_sql, succ_sql, s_ident(table), fail_sql, succ_sql,
         (", usr" if user_col else ""), partition, window_ms,
         (", usr" if user_col else ""), minimum)
    # 参数顺序：CTE ev 的 WHERE 里 fail_sql 和 succ_sql 各出现一次（OR 两侧），
    # 但 CASE WHEN 里又各出现一次 → 总共 fail_p×2 + succ_p×2
    params = [task_id, source_id] + fail_p + succ_p + fail_p + succ_p
    rows = conn.execute(sql, params).fetchall()
    hits: list[dict[str, Any]] = []
    for r in rows:
        hits.append({"ts": r["ts"], group_by: r["gk"], "failure_count": r["fails"],
                     "raw": "%s：%d 秒内失败 %d 次后成功" % (r["gk"], window_ms // 1000, r["fails"])})
    return hits


def _sql_auth_fail_burst(conn, table: str, task_id: str, source_id: str,
                         rule: dict, fields: list[str]) -> list[dict[str, Any]]:
    """auth_fail_burst → 按 srcip 分组的 RANGE 窗口计数。"""
    from services.sql_rules import Unsupported, ident as s_ident
    agg = (rule.get("match") or {}).get("agg") or {}
    if "srcip" not in fields or "ts" not in fields:
        raise Unsupported("缺少 srcip/ts 字段")
    window_ms = int(agg.get("window_sec", 300)) * 1000
    threshold = int(agg.get("min_count", 20))
    sql = (
        "WITH ev AS (SELECT srcip AS gk, ts FROM %s"
        " WHERE task_id=? AND source_id=? AND result='失败' AND ts IS NOT NULL),"
        " w AS (SELECT gk, ts, COUNT(*) OVER win AS c"
        " FROM ev WINDOW win AS (PARTITION BY gk ORDER BY ts RANGE BETWEEN %d PRECEDING AND CURRENT ROW))"
        " SELECT gk, max(c) AS peak, arg_max(ts,c) AS peak_ts"
        " FROM w GROUP BY gk HAVING max(c)>=%d"
    ) % (s_ident(table), window_ms, threshold)
    rows = conn.execute(sql, [task_id, source_id]).fetchall()
    hits: list[dict[str, Any]] = []
    for r in rows:
        hits.append({"ts": r["peak_ts"], "srcip": r["gk"],
                     "raw": "%d 秒内认证失败 %d 次" % (window_ms // 1000, r["peak"])})
    return hits


RULE_KINDS = {"row", "aggregate"}
RULE_SCOPES = {"web", "auth", "syslog", "audit", "shell", "win", "ps", "sysmon", "firewall", "text"}
MATCH_OPERATORS = {
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "icontains",
    "contains_any", "icontains_any", "starts_with", "ends_with", "regex", "iregex",
    "not_regex", "len_lt", "len_gt", "len_eq", "exists", "not_exists",
}
AGG_TYPES = {"window_count", "fail_then_success", "ip_burst", "path_baseline_shift", "auth_fail_burst"}


def validate_rule(rule: dict[str, Any]) -> None:
    if not str(rule.get("name", "")).strip():
        raise ValueError("规则名称不能为空")
    if rule.get("severity") not in SEVERITIES:
        raise ValueError("severity 必须为 high / medium / low")
    if not str(rule.get("false_positive", "")).strip():
        raise ValueError("必须填写误报说明 false_positive")
    kind = rule.get("kind", "row")
    if kind not in RULE_KINDS:
        raise ValueError("规则 kind 必须为 row 或 aggregate")
    scope = rule.get("scope")
    scopes = scope if isinstance(scope, list) else [scope]
    if not scopes or any(x not in RULE_SCOPES for x in scopes):
        raise ValueError("必须明确选择至少一种有效日志类型，不允许默认 scope=all")

    def validate_conditions(node: Any) -> None:
        if not isinstance(node, dict) or not node:
            raise ValueError("匹配条件不能为空")
        for field, expr in node.items():
            if field == "any":
                if not isinstance(expr, list) or not expr:
                    raise ValueError("any 必须是非空条件数组")
                for child in expr:
                    validate_conditions(child)
            elif field == "not":
                validate_conditions(expr)
            elif field == "agg":
                raise ValueError("agg 只能出现在聚合规则根部")
            else:
                if not isinstance(expr, dict) or not expr:
                    raise ValueError("字段 %s 的条件必须是非空对象" % field)
                for op, expected in expr.items():
                    if op not in MATCH_OPERATORS:
                        raise ValueError("未知匹配操作符: " + op)
                    if op in ("regex", "iregex", "not_regex"):
                        re.compile(str(expected))
                    if op in ("in", "not_in", "contains_any", "icontains_any") and (not isinstance(expected, list) or not expected):
                        raise ValueError(op + " 必须是非空数组")
                    if op in ("gt", "gte", "lt", "lte", "len_lt", "len_gt", "len_eq") and not isinstance(resolve_param(expected, rule), (int, float)):
                        raise ValueError(op + " 必须是数值")

    match = rule.get("match")
    if not isinstance(match, dict) or not match:
        raise ValueError("匹配条件 match 不能为空")
    if kind == "row":
        validate_conditions(match)
        return
    if set(match) != {"agg"} or not isinstance(match.get("agg"), dict):
        raise ValueError("聚合规则 match 只能包含 agg 对象")
    agg = match["agg"]
    if agg.get("type") not in AGG_TYPES:
        raise ValueError("未知聚合类型: " + str(agg.get("type")))
    if agg["type"] in ("window_count", "fail_then_success", "auth_fail_burst") and not str(agg.get("group_by") or "").strip() and agg["type"] != "auth_fail_burst":
        raise ValueError("该聚合规则必须设置 group_by")
    if agg.get("where"):
        validate_conditions(agg["where"])
    if agg["type"] == "fail_then_success":
        validate_conditions(agg.get("fail"))
        validate_conditions(agg.get("success"))
    for key in ("window_sec", "min_count", "min_distinct", "min_failures", "min_paths", "min_samples"):
        if key in agg and (not isinstance(agg[key], (int, float)) or agg[key] <= 0):
            raise ValueError("聚合参数 " + key + " 必须是正数")


class RuleStore:
    def __init__(self, custom_dir: Path = CUSTOM_DIR):
        self.custom_dir = custom_dir
        self.custom_dir.mkdir(parents=True, exist_ok=True)
        # 加载失败的文件与原因。规则文件坏掉时如果只是静默跳过，
        # 面板上会少一批规则而没人知道，等于凭空丢掉检测能力。
        self.errors: list[dict[str, str]] = []

    @property
    def deleted_path(self) -> Path:
        return self.custom_dir / "deleted.json"

    def deleted(self) -> list[str]:
        if not self.deleted_path.exists():
            return []
        return json.loads(self.deleted_path.read_text(encoding="utf-8"))

    def load(self) -> list[dict[str, Any]]:
        rules: dict[str, dict[str, Any]] = {}
        errors: list[dict[str, str]] = []
        for path in sorted(BUILTIN_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for rule in data.get("rules", []):
                    rule = dict(rule)
                    rule["category"] = data.get("category")
                    rule["category_name"] = data.get("category_name")
                    rule["builtin"] = True
                    rule["priority"] = rule.get("priority", 100)
                    validate_rule(rule)
                    rules[rule["id"]] = rule
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                errors.append({"file": path.name, "error": str(exc)[:200]})
                continue
        for path in sorted(self.custom_dir.glob("*.json")):
            if path.name == "deleted.json":
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "id" in data:
                    items = [data]
                else:
                    items = data.get("rules", []) if isinstance(data, dict) else data
                if isinstance(items, dict):
                    items = [items]
                for rule in items:
                    rule = dict(rule)
                    rule["builtin"] = rule["id"] in rules
                    rule["updated_at"] = rule.get("updated_at") or now_iso()
                    validate_rule(rule)
                    rules[rule["id"]] = rule
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                errors.append({"file": "custom/" + path.name, "error": str(exc)[:200]})
                continue
        self.errors = errors
        deleted = set(self.deleted())
        return sorted((r for rid, r in rules.items() if rid not in deleted), key=lambda x: x.get("priority", 100), reverse=True)

    def save(self, rule: dict[str, Any]) -> dict[str, Any]:
        validate_rule(rule)
        rule = dict(rule)
        rule.setdefault("id", "custom_" + uuid.uuid4().hex[:10])
        if not re.fullmatch(r"[A-Za-z0-9_-]+", rule["id"]):
            raise ValueError("规则 ID 只能包含字母、数字、下划线和连字符")
        rule["kind"] = rule.get("kind", "row")
        rule["scope"] = rule.get("scope", "all")
        rule["enabled"] = rule.get("enabled", True)
        rule["updated_at"] = now_iso()
        path = self.custom_dir / (rule["id"] + ".json")
        path.write_text(json.dumps(rule, ensure_ascii=False, indent=2), encoding="utf-8")
        if rule["id"] in self.deleted():
            self.deleted_path.write_text(json.dumps([x for x in self.deleted() if x != rule["id"]], ensure_ascii=False, indent=2), encoding="utf-8")
        return next(x for x in self.load() if x["id"] == rule["id"])

    def delete(self, rule_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", rule_id):
            raise ValueError("非法规则 ID")
        builtin_ids = {r["id"] for r in self.load() if r.get("builtin")}
        path = self.custom_dir / (rule_id + ".json")
        if rule_id in builtin_ids:
            deleted = list(dict.fromkeys(self.deleted() + [rule_id]))
            self.deleted_path.write_text(json.dumps(deleted, ensure_ascii=False, indent=2), encoding="utf-8")
        path.unlink(missing_ok=True)

    def reset(self) -> None:
        for path in self.custom_dir.glob("*.json"):
            path.unlink()

    @staticmethod
    def applies(rule: dict[str, Any], kind: str) -> bool:
        scope = rule.get("scope", "all")
        if scope == "all":
            return True
        if scope == "syslog":
            return kind in ("auth", "syslog")
        if isinstance(scope, list):
            return kind in scope
        return scope == kind


class RuleEngine:
    def __init__(self, store: Store, queries: QueryService, rules: RuleStore | None = None):
        self.store = store
        self.queries = queries
        self.rules = rules or RuleStore()

    def all_rows(self, task_id: str, source_id: str) -> Iterable[dict[str, Any]]:
        cursor = None
        while True:
            options = {"size": 500, "count": False, "sort": {"k": "id", "dir": 1}}
            if cursor is not None:
                options["cursor"] = cursor
            page = self.queries.query(task_id, source_id, options)
            for row in page["rows"]:
                yield row
            if not page["rows"] or len(page["rows"]) < 500 or page.get("next_cursor") is None:
                break
            cursor = page["next_cursor"]

    def _stream_rows(self, task_id: str, source_id: str,
                     omit_raw: bool = True) -> Iterable[dict[str, Any]]:
        """逐页流式取行，内存只占一页。

        和 all_rows 的区别：页更大（2000 vs 500）、可以裁掉 raw 大字段。
        规则引擎的聚合规则和无法下推的行规则都走这里，1000 万行的表也不会
        把整表读进内存（原来 `list(all_rows())` 在 1000 万行时约 19 GB）。
        """
        cursor = None
        while True:
            options = {"size": 2000, "count": False, "sort": {"k": "id", "dir": 1}}
            if omit_raw:
                options["omit"] = ["raw"]
            if cursor is not None:
                options["cursor"] = cursor
            page = self.queries.query(task_id, source_id, options)
            for row in page["rows"]:
                yield row
            if not page["rows"] or len(page["rows"]) < 2000 or page.get("next_cursor") is None:
                break
            cursor = page["next_cursor"]

    def decorate_rows(self, rows: list[dict[str, Any]], kind: str) -> None:
        """Attach authoritative row-rule hits so table, flags and alerts share one engine."""
        active = [r for r in self.rules.load() if r.get("enabled", True) and r.get("kind") == "row" and self.rules.applies(r, kind)]
        if not active:
            for row in rows:
                row["ruleHits"] = []
            return
        # 和 alerts 一样按 eventId 分桶：整表分页读取时，每页都跑全部规则
        # 会让切源变慢（500 行 × 30 条 = 每页 1.5 万次比较）
        buckets: dict[str, list[dict[str, Any]]] = {}
        general: list[dict[str, Any]] = []
        for rule in active:
            ids = rule_event_ids(rule)
            if ids:
                for eid in ids:
                    buckets.setdefault(eid, []).append(rule)
            else:
                general.append(rule)

        def hits_of(row: dict[str, Any]) -> list[dict[str, Any]]:
            found: list[dict[str, Any]] = []
            for rule in buckets.get(str(row.get("eventId")), ()):
                if matches(rule, row):
                    found.append({"id": rule["id"], "name": rule["name"], "severity": rule["severity"]})
            for rule in general:
                if matches(rule, row):
                    found.append({"id": rule["id"], "name": rule["name"], "severity": rule["severity"]})
            return found

        for row in rows:
            row["ruleHits"] = hits_of(row)

    def test(self, sample: dict[str, Any], kind: str = "web") -> list[dict[str, Any]]:
        result = []
        for rule in self.rules.load():
            if not rule.get("enabled", True) or not self.rules.applies(rule, kind) or rule.get("kind") != "row":
                continue
            result.append({"id": rule["id"], "name": rule["name"], "severity": rule["severity"], "hit": matches(rule, sample)})
        return result

    def alerts(self, task_id: str, source_id: str) -> dict[str, Any]:
        self.queries.ensure_task_source(task_id, source_id)
        kind = self.queries.kind(self.queries.source(source_id))
        active = [r for r in self.rules.load() if r.get("enabled", True) and self.rules.applies(r, kind)]
        output = [{"rule": r, "count": 0, "hits": []} for r in active]
        config = self.queries.config_for(source_id)
        fields = config["fields"]

        def record(item: dict[str, Any], row: dict[str, Any]) -> None:
            item["count"] += 1
            if len(item["hits"]) < 100:
                item["hits"].append(row)

        row_items = [x for x in output if x["rule"].get("kind") != "aggregate"]
        agg_items = [x for x in output if x["rule"].get("kind") == "aggregate"]

        # 能下推的行规则交给 DuckDB：一条聚合 SQL、一次扫描算完全部计数，
        # 不再把整表（含 raw 原文）搬进内存。实测 30 条规则 27k 行 531ms，
        # 命中数与 Python 逐行判断逐条一致。
        pushed: list[dict[str, Any]] = []
        fallback: list[dict[str, Any]] = []
        if sql_rules.available(self.store):
            for item in row_items:
                try:
                    sql_rules.translate(item["rule"])
                except sql_rules.Unsupported:
                    fallback.append(item)
                else:
                    pushed.append(item)
        else:
            fallback = list(row_items)

        if pushed:
            conn = self.store.task_connection(task_id)
            try:
                try:
                    count_sql, count_params = sql_rules.counts_sql(
                        config["table"], [x["rule"] for x in pushed], task_id, source_id)
                    counted = conn.execute(count_sql, count_params).fetchone() or {}
                except Exception:
                    # 引擎侧拒绝（例如某个正则 RE2 不认、预检又没抓到）：整体退回逐行判断
                    fallback.extend(pushed)
                    pushed = []
                else:
                    for index, item in enumerate(pushed):
                        item["count"] = int(counted.get("c%d" % index) or 0)
                    migrated: list[dict[str, Any]] = []
                    for item in pushed:
                        if not item["count"]:
                            continue
                        try:
                            hit_sql, hit_params = sql_rules.hits_sql(
                                config["table"], item["rule"], task_id, source_id, 100)
                            item["hits"] = conn.execute(hit_sql, hit_params).fetchall()
                        except Exception:
                            # 计数有了样本取不到 → "命中 N 条、0 个样本"最误导排查；
                            # 退回 Python 流式重算这一条（与其它回退规则同一路径）
                            item["count"] = 0
                            migrated.append(item)
                    if migrated:
                        pushed = [x for x in pushed if x not in migrated]
                        fallback.extend(migrated)
            finally:
                conn.close()

        # 剩下需要行数据的规则一次性算清要不要保留 raw，然后流式逐页喂
        keep_raw = any(sql_rules.needs_raw(x["rule"]) for x in fallback + agg_items)

        def scan() -> Iterable[dict[str, Any]]:
            return self._stream_rows(task_id, source_id, omit_raw=not keep_raw)

        # 回退的行规则按 eventId 预分桶：Windows 规则基本都钉死事件 ID，
        # 分桶后每行只测真正可能命中的那几条
        if fallback:
            buckets: dict[str, list[dict[str, Any]]] = {}
            general: list[dict[str, Any]] = []
            for item in fallback:
                ids = rule_event_ids(item["rule"])
                if ids:
                    for eid in ids:
                        buckets.setdefault(eid, []).append(item)
                else:
                    general.append(item)
            for row in scan():
                for item in buckets.get(str(row.get("eventId")), ()):
                    if matches(item["rule"], row):
                        record(item, row)
                for item in general:
                    if matches(item["rule"], row):
                        record(item, row)
        # 聚合规则：优先 SQL 下推（窗口函数），翻译失败才回退 Python 逐行。
        # SQL 路径消除 candidates 无界驻留（原 10M 行 → 6.4 GB），且快 20-40×。
        from services.sql_rules import Unsupported as _Unsupported
        fallback_aggs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for item in agg_items:
            rule = item["rule"]
            if rule.get("kind") != "aggregate":
                continue
            agg = (rule.get("match") or {}).get("agg") or {}
            agg_type = agg.get("type")
            try:
                if agg_type == "window_count":
                    hits = _sql_window_count(conn, config["table"], task_id, source_id, rule, fields)
                elif agg_type == "fail_then_success":
                    hits = _sql_fail_then_success(conn, config["table"], task_id, source_id, rule, fields)
                elif agg_type == "auth_fail_burst":
                    hits = _sql_auth_fail_burst(conn, config["table"], task_id, source_id, rule, fields)
                elif agg_type == "ip_burst" and "ip" in fields:
                    hits = [{"ts": h["start"], "ip": h["key"], "raw": "窗口峰值 %d 次 / %d 个路径" % (h["cnt"], h["paths"])}
                            for h in self.store.frequency(task_id, config["table"], source_id, "ip", fields, int(agg.get("window_sec", 60)) * 1000)
                            if h["cnt"] >= int(agg.get("min_count", 100)) and h["paths"] >= int(agg.get("min_paths", 20))]
                elif agg_type == "path_baseline_shift" and "path" in fields:
                    hits = [{"ts": None, "path": h["path"], "raw": "基线均值 %d B，最小 %d B" % (h["avg"], h["min"])}
                            for h in self.store.path_baseline(task_id, config["table"], source_id)
                            if h["count"] >= int(agg.get("min_samples", 20)) and h["avg"] and h["min"] < h["avg"] * float(agg.get("ratio_lt", 0.2))]
                else:
                    hits = None  # 未知类型，走 fallback
                if hits is not None:
                    for hit in hits:
                        item["count"] += 1
                        if len(item["hits"]) < 100:
                            item["hits"].append(hit)
                    continue  # SQL 成功，不需要 fallback
            except (_Unsupported, Exception):
                pass  # 翻译失败或 SQL 执行出错，回退 Python
            if agg_type in ("window_count", "fail_then_success"):
                fallback_aggs.append((item, agg))
            elif agg_type == "auth_fail_burst":
                # auth_fail_burst 的 Python 回退需要独立扫描
                threshold = int(agg.get("min_count", 20))
                window = int(agg.get("window_sec", 300)) * 1000
                grouped: dict[str, list[int]] = {}
                for row in scan():
                    if row.get("result") == "失败" and row.get("ts"):
                        grouped.setdefault(str(row.get("srcip") or "-"), []).append(row["ts"])
                for ip, times in grouped.items():
                    times.sort()
                    left = 0
                    peak = 0
                    peak_start = None
                    for right, ts in enumerate(times):
                        while ts - times[left] > window:
                            left += 1
                        if right - left + 1 > peak:
                            peak = right - left + 1
                            peak_start = times[left]
                    if peak >= threshold:
                        item["count"] += 1
                        if len(item["hits"]) < 100:
                            item["hits"].append({"ts": peak_start, "srcip": ip, "raw": "%d 秒内认证失败 %d 次" % (window // 1000, peak)})
        # Python 回退路径：只为翻译失败的规则收集 candidates（不再全量驻留）
        if fallback_aggs:
            candidates: list[dict[str, Any]] = []
            for row in scan():
                for agg_item, agg in fallback_aggs:
                    conds = ([agg.get("where")] if agg.get("type") == "window_count"
                             else [agg.get("fail"), agg.get("success")])
                    matched = False
                    for cond in conds:
                        if not cond or matches(agg_item["rule"], row, cond):
                            matched = True
                            break
                    if matched:
                        candidates.append(row)
                        break
            for item, agg in fallback_aggs:
                rule = item["rule"]
                if agg.get("type") == "window_count":
                    for hit in aggregate_window_count(candidates, rule):
                        item["count"] += 1
                        if len(item["hits"]) < 100:
                            item["hits"].append(hit)
                elif agg.get("type") == "fail_then_success":
                    for hit in aggregate_fail_then_success(candidates, rule):
                        item["count"] += 1
                        if len(item["hits"]) < 100:
                            item["hits"].append(hit)
        # 应急排查：severity 优先（high→medium→low），同级内按命中数降序。
        # 原排序纯按 count 会让 5000 次低危噪声压过 1 次「1102 清空安全日志」。
        _SEV_RANK = {"high": 0, "medium": 1, "low": 2}
        output.sort(key=lambda x: (_SEV_RANK.get(x["rule"].get("severity", "medium"), 1), -x["count"]))
        return {"source_id": source_id, "kind": kind, "rules": output, "total": sum(x["count"] for x in output), "active_rules": len(output)}
