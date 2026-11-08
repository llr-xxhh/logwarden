"""界面添加的日志源。

内置源目录 `templates/catalog.json` 是只读的：新增一个源不该改代码，所以自定义源
单独落在 `sources/*.json`，启动时与内置目录合并。表结构仍复用所选解析器，
数据靠 source_id 区分。
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "sources"
ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
GROUPS = ("web", "linux", "windows", "security", "network", "app", "cloud", "db")
LEVELS = ("required", "recommended", "optional")
# 允许复用的解析器：新增源本质是"起个名字 + 选个解析器 + 挂模板"
FORMATS = ("combined", "w3c", "syslog", "audit", "shell", "windows_event", "json", "text", "firewall", "tomcat")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def list_custom() -> list[dict[str, Any]]:
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(SOURCE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        data["id"] = data.get("id") or path.stem
        data["builtin"] = False
        items.append(data)
    return items


def custom_ids() -> set[str]:
    return {item["id"] for item in list_custom()}


def _path(source_id: str) -> Path:
    return SOURCE_DIR / (source_id + ".json")


def save_custom(data: dict[str, Any], builtin_ids: set[str] | None = None) -> dict[str, Any]:
    source_id = str(data.get("id") or "").strip().lower()
    name = str(data.get("name") or "").strip()
    fmt = str(data.get("format") or "text")
    if not ID_RE.fullmatch(source_id):
        raise ValueError("日志源 ID 只能用小写字母开头、字母数字下划线，3–32 位")
    if builtin_ids and source_id in builtin_ids:
        raise ValueError("ID 与内置日志源冲突：" + source_id)
    if not name:
        raise ValueError("日志源名称不能为空")
    if fmt not in FORMATS:
        raise ValueError("不支持的解析格式：" + fmt)
    group = str(data.get("group") or "app")
    if group not in GROUPS:
        group = "app"
    level = str(data.get("level") or "recommended")
    if level not in LEVELS:
        level = "recommended"
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    existing = {}
    if _path(source_id).exists():
        try:
            existing = json.loads(_path(source_id).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
    item = {
        "id": source_id,
        "name": name,
        "group": group,
        "platform": data.get("platform") or [],
        "paths": data.get("paths") or [],
        "format": fmt,
        "enabled_by_default": bool(data.get("enabled_by_default", True)),
        "enable_hint": data.get("enable_hint"),
        "records": str(data.get("records") or "").strip(),
        "value": str(data.get("value") or "").strip(),
        "level": level,
        "caveat": str(data.get("caveat") or "").strip(),
        "builtin": False,
        "created_at": existing.get("created_at") or _now(),
        "updated_at": _now(),
    }
    _path(source_id).write_text(json.dumps(item, ensure_ascii=False, indent=2), encoding="utf-8")
    return item


def delete_custom(source_id: str) -> None:
    if not ID_RE.fullmatch(source_id or ""):
        raise ValueError("非法日志源 ID")
    path = _path(source_id)
    if not path.exists():
        raise KeyError("自定义日志源不存在")
    path.unlink()


def custom_component(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    """把自定义源收进一个虚拟组件，界面上和内置组件一样可选。"""
    if not items:
        return None
    return {
        "id": "custom",
        "name": "自定义日志源",
        "group": items[0].get("group") or "app",
        "platform": [],
        "desc": "在「日志模板」页添加，复用所选解析器，可挂自定义 log_format",
        "sources": [item["id"] for item in items],
        "custom": True,
    }
