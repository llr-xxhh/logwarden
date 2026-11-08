"""EVTX 直读：把 Windows 二进制事件日志转成 raw_evtx 表能用的扁平记录。

依赖 `evtx`（Rust 绑定，纯二进制轮子、无需编译）：本机 20 MB Security.evtx
（27125 条）解析约 0.03 s，比 PowerShell 导出 XML 再导入快两个数量级。

没装该组件时不阻塞其他格式：导入器会提示装包或改导出方式。
"""
from __future__ import annotations

import json
from typing import Any, BinaryIO, Iterator

try:  # 组件可选，缺了只影响 .evtx
    from evtx import PyEvtxParser
except ImportError:  # pragma: no cover - 环境相关
    PyEvtxParser = None  # type: ignore[assignment]

EVTX_MAGIC = b"ElfFile\x00"


def available() -> bool:
    """本机是否有可用的 evtx 解析组件。"""
    return PyEvtxParser is not None


def is_evtx_file(filename: str, head: bytes = b"") -> bool:
    """按扩展名或文件头判断（导出文件常被改名，魔数更可靠）。"""
    return filename.lower().endswith(".evtx") or head[: len(EVTX_MAGIC)] == EVTX_MAGIC


def to_record(event: dict[str, Any]) -> dict[str, Any]:
    """evtx 的 {"Event": {...}} 结构 → event_record() 认得的扁平结构。"""
    from services.parsing import event_record, flatten_event_data  # 延迟导入，避免模块循环

    system = event.get("System") if isinstance(event.get("System"), dict) else {}
    created = system.get("TimeCreated")
    stamp = None
    if isinstance(created, dict):
        stamp = (created.get("#attributes") or {}).get("SystemTime")
    elif created:
        stamp = created
    provider = system.get("Provider")
    flat = flatten_event_data(event)
    # event_record() 合成消息和 detail 时要读原始 EventData。只传展开后的扁平字典，
    # 它会拿到空块，导致没有 RenderingInfo.Message 的通道（Firewall / WMI /
    # CodeIntegrity 等）整列消息全空——Security 因为有渲染好的 Message 掩盖了这一点。
    raw_data = event.get("EventData")
    if not isinstance(raw_data, dict):
        raw_data = event.get("UserData") if isinstance(event.get("UserData"), dict) else {}
    flat.update(
        {
            "EventID": system.get("EventID"),
            "Computer": system.get("Computer"),
            "TimeCreated": stamp,
            "Level": system.get("Level"),
            "Channel": system.get("Channel"),
        }
    )
    if isinstance(provider, dict):
        flat.setdefault("Provider", (provider.get("#attributes") or {}).get("Name"))
    rendering = event.get("RenderingInfo")
    if isinstance(rendering, dict) and rendering.get("Message"):
        flat.setdefault("Message", rendering.get("Message"))
    flat["EventData"] = raw_data
    return event_record(flat)


def iter_records(stream: BinaryIO) -> Iterator[tuple[str, dict[str, Any]]]:
    """逐条产出 (原始 JSON, 记录)。流式读取，不落临时文件。

    坏块按 `skip_errors` 跳过（告警而非中断），保证一个损坏的 chunk
    不会让整份日志前功尽弃。
    """
    if PyEvtxParser is None:
        raise RuntimeError("未安装 evtx 组件，无法读取 EVTX")
    try:
        parser = PyEvtxParser(stream, skip_errors=True, indent=False)
        for raw in parser.records_json():
            payload = json.loads(raw["data"])
            event = payload.get("Event") if isinstance(payload.get("Event"), dict) else payload
            yield json.dumps(payload, ensure_ascii=False, separators=(",", ":")), to_record(event)
    except RuntimeError as exc:
        # 文件头魔数不对 / 结构损坏：转成 ValueError，接口按 400 返回可读提示，而不是 500
        detail = (str(exc) or "结构损坏").splitlines()[0]
        raise ValueError("不是有效的 EVTX 文件：%s" % detail[:160]) from exc
