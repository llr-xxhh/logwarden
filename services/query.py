"""Task/source catalog enrichment and query/statistics service."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from storage import Store
from services.parsing import parser_config
from services import custom_sources

ROOT = Path(__file__).resolve().parents[1]


class QueryService:
    def __init__(self, store: Store):
        self.store = store
        self.catalog = json.loads((ROOT / "templates" / "catalog.json").read_text(encoding="utf-8"))
        self.sources = {s["id"]: s for s in self.catalog["sources"]}
        self.components = {c["id"]: c for c in self.catalog["components"]}
        self.templates = {}
        for path in (ROOT / "templates").glob("*.json"):
            if path.name == "catalog.json":
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            self.templates[data["id"]] = data
        self._custom_ids: set[str] = set()
        self.reload_sources()

    def reload_sources(self) -> None:
        """合并界面添加的日志源。新增/删除后调用，不必重启服务。"""
        fresh = {item["id"]: item for item in custom_sources.list_custom()}
        for sid in list(self._custom_ids - set(fresh)):
            self.sources.pop(sid, None)
        self.sources.update(fresh)
        self._custom_ids = set(fresh)
        component = custom_sources.custom_component(list(fresh.values()))
        if component:
            self.components[component["id"]] = component
        else:
            self.components.pop("custom", None)

    def source(self, source_id: str) -> dict[str, Any]:
        if source_id not in self.sources:
            raise KeyError("未知日志源: " + source_id)
        return self.sources[source_id]

    @staticmethod
    def kind(source: dict[str, Any]) -> str:
        sid = source["id"]
        # 自定义源的 id 由用户起，不能靠前缀猜；只看它选了哪个解析器
        if source.get("builtin") is False:
            return {
                "combined": "web", "w3c": "web", "tomcat": "web",
                "syslog": "syslog", "audit": "audit", "shell": "shell",
                "windows_event": "win", "firewall": "firewall",
            }.get(source.get("format", ""), "text")
        if sid in ("linux_auth", "centos_auth", "ubuntu_auth"):
            return "auth"
        if sid.startswith(("centos_", "ubuntu_")):
            if sid.endswith("_history"):
                return "shell"
            if sid.endswith("_audit"):
                return "audit"
            if sid.endswith(("_syslog", "_kernel", "_cron", "_journal")):
                return "syslog"
        if sid == "linux_audit":
            return "audit"
        if sid == "linux_history":
            return "shell"
        if sid.startswith("firewall_"):
            return "firewall"
        if sid in ("win_security", "win_system", "win_taskscheduler", "win_rdp", "win_defender"):
            # 这几个通道同属 Windows 事件语义：漏掉一个就会落到 text，
            # 而 scope=text 的通用正则（含 Redis/MySQL 那些带 (?=[\s\S]*) 的）
            # 会套到 Windows 日志上——既误报又极慢（实测单条规则 110 秒）
            return "win"
        if sid == "win_powershell":
            return "ps"
        if sid == "win_sysmon":
            return "sysmon"
        if source.get("format") in ("combined", "w3c", "tomcat"):
            return "web"
        return "text"

    def config_for(self, source_id: str) -> dict[str, Any]:
        return parser_config(self.source(source_id).get("format", "text"))

    def schema_for(self, task_id: str, source_id: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
        """返回解析器配置 + 该任务库里这张表的真实列。

        模板补出来的列会出现在这里，因此「统计维度 / 筛选字段 / 表格列」跟着模板走，
        不需要改解析器配置，也不需要重导数据。
        """
        config = self.config_for(source_id)
        conn = self.store.task_connection(task_id)
        try:
            actual = self.store.table_schema(conn, config["table"])
        finally:
            conn.close()
        declared = set(config["fields"])
        # 声明过的列排在前面（时间、IP、路径这些固定在前），模板补的列跟在后面
        ordered = [c for c in actual if c["name"] in declared] + [c for c in actual if c["name"] not in declared]
        return config, ordered

    def task_view(self, task_id: str) -> dict[str, Any]:
        task = self.store.get_task(task_id)
        imports = self.store.list_imports(task_id)
        counts = task["stats"]["source_counts"]
        # 源列表严格跟证据清单的勾选走：取消勾选的源从台面隐藏（数据保留在库里，
        # 重新勾选即恢复）。导入器强制"源必须先在清单内"，这里不需要再并入 counts。
        known_ids = list(task["source_ids"])
        views = []
        for sid in known_ids:
            if sid not in self.sources:
                continue
            src = dict(self.sources[sid])
            src["count"] = counts.get(sid, 0)
            src["kind"] = self.kind(src)
            views.append(src)
        task["sources"] = views
        task["imports"] = imports
        evidence = []
        selected = set(task["source_ids"])
        for cid in task["components"]:
            component = self.components.get(cid)
            if not component:
                continue
            logs = []
            for sid in component["sources"]:
                if sid not in selected:
                    continue
                src = self.sources.get(sid)
                if not src:
                    continue
                enabled = src.get("enabled_by_default", True)
                count = counts.get(sid, 0)
                state = "ok" if count else ("miss" if enabled else "off")
                logs.append({
                    "id": sid,
                    "name": src["name"],
                    "format": src["format"],
                    "level": src.get("level") or "recommended",
                    "count": count,
                    "state": state,
                    "enabled_by_default": enabled,
                    # 默认路径：证据清单/日志清单直接展示，用户不用去查文档就知道去哪个文件取
                    "paths": list(src.get("paths") or []),
                })
            # 证据分母只认「必要项」；该组件没有必要项时退到「推荐项」，再退到全部可收集项。
            # 否则可选项永远收不齐，「证据 x/y」就成了假指标。
            graded = [x for x in logs if x["state"] != "off"]
            base = [x for x in graded if x["level"] == "required"]
            basis = "required"
            if not base:
                base = [x for x in graded if x["level"] == "recommended"]
                basis = "recommended"
            if not base:
                base = graded
                basis = "all"
            got = sum(1 for x in base if x["state"] == "ok")
            evidence.append({
                "id": cid,
                "name": component["name"],
                "desc": component.get("desc", ""),
                "got": got,
                "expected": len(base),
                "basis": basis,
                "logs": logs,
            })
        task["evidence"] = evidence
        by_level: dict[str, dict[str, int]] = {}
        for item in evidence:
            for log in item["logs"]:
                slot = by_level.setdefault(log["level"], {"total": 0, "got": 0, "off": 0})
                slot["total"] += 1
                if log["state"] == "ok":
                    slot["got"] += 1
                elif log["state"] == "off":
                    slot["off"] += 1
        task["evidence_summary"] = {
            "got": sum(x["got"] for x in evidence),
            "expected": sum(x["expected"] for x in evidence),
            "by_level": by_level,
        }
        return task

    def ensure_task_source(self, task_id: str, source_id: str) -> None:
        task = self.store.get_task(task_id)
        self.source(source_id)
        if source_id not in task["source_ids"]:
            raise ValueError("该日志源未加入当前任务，不能导入或查询")

    def query(self, task_id: str, source_id: str, options: dict[str, Any]) -> dict[str, Any]:
        self.ensure_task_source(task_id, source_id)
        config, schema = self.schema_for(task_id, source_id)
        fields = [c["name"] for c in schema] or list(config["fields"])
        result = self.store.query_rows(task_id, config["table"], source_id, fields, options)
        result["source_id"] = source_id
        result["kind"] = self.kind(self.source(source_id))
        result["schema"] = schema
        return result

    def stats(self, task_id: str, source_id: str, dimension: str | None = None, sort: str = "cnt", window_sec: int = 60) -> dict[str, Any]:
        self.ensure_task_source(task_id, source_id)
        config, schema = self.schema_for(task_id, source_id)
        fields = [c["name"] for c in schema] or list(config["fields"])
        summary = self.store.source_summary(task_id, config["table"], source_id, fields)
        src = self.source(source_id)
        kind = self.kind(src)
        # 窗口只影响统计范围；判定已折算成次/分钟，换窗口不会改变结论口径
        window_sec = max(5, min(86400, int(window_sec or 60)))
        if dimension is None:
            dimension = "ip" if kind == "web" else ("srcip" if "srcip" in fields else ("host" if "host" in fields else fields[0]))
        group = "ip" if kind == "web" else ("srcip" if "srcip" in fields else ("host" if "host" in fields else dimension))
        return {
            "source_id": source_id,
            "kind": kind,
            "window_sec": window_sec,
            "summary": summary,
            "ranking": self.store.rank(task_id, config["table"], source_id, dimension, fields, sort),
            "frequency": self.store.frequency(task_id, config["table"], source_id, group, fields, window_sec * 1000, kind == "web"),
            "baseline": self.store.path_baseline(task_id, config["table"], source_id) if kind == "web" else [],
            "schema": schema,
        }
