"""本机 Windows 事件日志一键导入：枚举 winevt\\Logs，按日志源直读 EVTX。

设计边界：
- 只认 %SystemRoot%\\System32\\winevt\\Logs 下的裸文件名，不做任意路径读取——
  这是个本地 Web 服务，放开路径等于给浏览器开了任意文件读接口；
- 文件被 EventLog 服务持有写锁，用共享读打开（Python open 默认 DENYNO），
  正在写入的最后一个 chunk 可能解析失败，计入 failed 行，不影响其余事件；
- Security.evtx 默认只有管理员/SYSTEM 可读，枚举时逐个探测可读性，
  前端据此禁用勾选并提示提权，而不是导入到一半才报错。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def logs_dir() -> Path:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return Path(root) / "System32" / "winevt" / "Logs"


def resolve(filename: str) -> Path:
    """把用户提交的文件名解析成 winevt\\Logs 下的真实路径，越界一律拒绝。"""
    name = str(filename or "").strip()
    if not name:
        raise ValueError("缺少文件名")
    # 只允许裸文件名：带分隔符、盘符、.. 的都拒绝，防路径穿越
    if name != Path(name).name or ":" in name:
        raise ValueError("只接受 winevt\\Logs 目录下的文件名，不接受路径")
    if not name.lower().endswith(".evtx"):
        raise ValueError("只支持 .evtx 文件")
    base = logs_dir().resolve()
    path = (base / name).resolve()
    if path.parent != base:
        raise ValueError("文件不在本机事件日志目录内")
    if not path.is_file():
        raise ValueError("本机不存在该日志文件：%s" % name)
    return path


def _readable(path: Path) -> bool:
    """探测能否共享读打开；Security.evtx 无权限时在这里暴露，而不是导入中途。"""
    try:
        with open(path, "rb") as fh:
            fh.read(8)
        return True
    except OSError:
        return False


def channel_name(filename: str) -> str:
    """EVTX 文件名 → 通道名：%4 是 / 的转义，去掉后缀便于阅读。"""
    stem = filename[:-5] if filename.lower().endswith(".evtx") else filename
    return stem.replace("%4", "/")


def list_files(sources: dict[str, Any], allowed_ids: set[str] | None = None) -> dict[str, Any]:
    """枚举本机 EVTX，并按目录里各日志源的默认路径做「文件 → 日志源」映射。

    返回 files 与 evtx_sources（EVTX 格式的日志源，供前端给未匹配文件手动归属）。
    allowed_ids 给出时（= 任务组件范围内的源）：evtx_sources 只留范围内的，
    文件带 allowed 标记，排序按「必要项 → 推荐项 → 可选项」，范围外的沉底。
    """
    base = logs_dir()
    mapping: dict[str, dict[str, Any]] = {}
    evtx_sources: list[dict[str, Any]] = []
    for sid, src in sources.items():
        if src.get("format") != "evtx":
            continue
        if allowed_ids is None or sid in allowed_ids:
            evtx_sources.append({"id": sid, "name": src.get("name") or sid,
                                 "level": src.get("level") or "recommended"})
        # 映射表收全部源：范围外的文件也要能标出「它是什么、只是不在本任务」
        for p in src.get("paths") or []:
            fname = Path(str(p)).name.lower()
            if fname.endswith(".evtx") and fname not in mapping:
                mapping[fname] = {"id": sid, "name": src.get("name") or sid,
                                  "level": src.get("level") or "recommended",
                                  "enabled": src.get("enabled_by_default", True)}

    rank = {"required": 0, "recommended": 1, "optional": 2}
    files: list[dict[str, Any]] = []
    if base.is_dir():
        for path in base.iterdir():
            if not path.is_file() or path.suffix.lower() != ".evtx":
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            hit = mapping.get(path.name.lower())
            if hit is None:
                cat, allowed = 1, None
            elif allowed_ids is None or hit["id"] in allowed_ids:
                cat, allowed = 0, True
            else:
                cat, allowed = 2, False
            files.append({
                "file": path.name,
                "channel": channel_name(path.name),
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
                "readable": _readable(path),
                "source_id": hit["id"] if hit else None,
                "source_name": hit["name"] if hit else None,
                "level": hit["level"] if hit else None,
                "enabled": hit["enabled"] if hit else True,
                "allowed": allowed,
                "_cat": cat,
                "_rank": rank.get(hit["level"], 1) if hit else 1,
            })
    files.sort(key=lambda f: (f["_cat"], f["_rank"], -f["size"]))
    for f in files:
        del f["_cat"], f["_rank"]
    return {"dir": str(base), "files": files, "evtx_sources": evtx_sources}
