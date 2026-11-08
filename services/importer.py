"""Streaming import service: decode, parse, batch insert, report bad lines."""
from __future__ import annotations

import gzip
import io
from pathlib import Path
from typing import Any, BinaryIO, Iterable

from storage import Store
from services import evtx_reader
from services.parsing import LogParser, parser_config

BATCH_SIZE = 1000
MAX_FILE_SIZE = 500 * 1024 * 1024
# EVTX 逐条流式解析，且服务器日志常超过 500 MB：Security.evtx 常态 4-8 GB，放宽到 16 GB
MAX_EVTX_SIZE = 16 * 1024 * 1024 * 1024


def _peek(stream: BinaryIO, size: int = 8) -> bytes:
    """读文件头判断魔数，读完复位；流不支持 seek 时放弃判断。"""
    try:
        head = stream.read(size) or b""
        stream.seek(0)
        return head
    except Exception:
        return b""


class Importer:
    def __init__(self, store: Store, queries=None):
        self.store = store
        self.queries = queries

    def import_stream(
        self,
        task_id: str,
        source_id: str,
        fmt: str,
        filename: str,
        stream: BinaryIO,
        size: int = 0,
        encoding: str = "utf-8",
    ) -> dict[str, Any]:
        task = self.store.get_task(task_id)
        if source_id not in task["source_ids"]:
            raise ValueError("该日志源未加入当前任务，不能导入")
        is_evtx = evtx_reader.is_evtx_file(filename, _peek(stream))
        if is_evtx and not evtx_reader.available():
            raise ValueError("读取 EVTX 需要 evtx 组件：在项目目录执行 .venv\\Scripts\\pip install evtx；或先导出为 JSON / XML")
        # 二进制 EVTX 是逐条流式读，不必按行拆分；服务器上的 Security.evtx 动辄 1 GB+
        limit = MAX_EVTX_SIZE if is_evtx else MAX_FILE_SIZE
        if size > limit:
            raise ValueError("单文件超过 %d MB，请按时间拆分后导入" % (limit // (1024 * 1024)))
        config = parser_config(fmt)
        if self.queries is not None:
            expected = self.queries.config_for(source_id)
            if config["table"] != expected["table"]:
                raise ValueError("所选格式与日志源不匹配：应使用 %s，不能用 %s" % (expected["id"], config["id"]))
        parser = LogParser(fmt, source_id)
        import_id = self.store.begin_import(task_id, source_id, config["id"], filename, size)
        conn = self.store.task_connection(task_id)
        rows = 0
        failed = 0
        errors: list[dict[str, Any]] = []
        first_ts = None
        last_ts = None
        batch: list[dict[str, Any]] = []
        # 模板可能补列，这两个清单在补列后追加；用同一个 list 对象，闭包里能读到最新内容
        write_fields: list[str] = list(config["fields"])
        checked = [f for f in config["fields"] if f != "source_id"]
        nulls: dict[str, int] = {}

        def flush() -> None:
            nonlocal batch, rows, first_ts, last_ts
            if batch:
                # 空值先记在本地，commit 成功后再并入，保证与 rows 同口径（失败批次不能算进去）
                local_nulls: dict[str, int] = {}
                for record in batch:
                    for field in checked:
                        if record.get(field) in (None, "", "-"):
                            local_nulls[field] = local_nulls.get(field, 0) + 1
                timestamps = [r["ts"] for r in batch if r.get("ts") is not None]
                next_rows = rows + len(batch)
                next_first = min(([first_ts] if first_ts is not None else []) + timestamps) if timestamps or first_ts is not None else None
                next_last = max(([last_ts] if last_ts is not None else []) + timestamps) if timestamps or last_ts is not None else None
                self.store.insert_batch(conn, config["table"], write_fields, batch)
                conn.execute("UPDATE import SET rows=?,first_ts=?,last_ts=? WHERE id=?", (next_rows, next_first, next_last, import_id))
                conn.commit()
                rows, first_ts, last_ts = next_rows, next_first, next_last
                for field, count in local_nulls.items():
                    nulls[field] = nulls.get(field, 0) + count
                batch = []

        def field_warnings() -> list[dict[str, Any]]:
            return self.store.field_warnings(config["id"], rows, failed, nulls)

        try:
            self.store.ensure_raw_table(conn, config)
            # 模板里出现的变量都建列：多了能统计能筛选，少了也不影响基础列
            extra = parser.template_columns()
            self.store.ensure_columns(conn, config["table"], extra)
            for name in extra:
                if name not in write_fields:
                    write_fields.append(name)
                if name not in checked:
                    checked.append(name)
            conn.commit()
            raw_stream = gzip.GzipFile(fileobj=stream) if filename.lower().endswith(".gz") else stream
            last_line = 0

            def emit(record: dict[str, Any], line_no: int, raw: str) -> None:
                record.update({"task_id": task_id, "import_id": import_id, "line_no": line_no, "raw": raw, "source_id": source_id})
                batch.append(record)
                if len(batch) >= BATCH_SIZE:
                    flush()

            if is_evtx:
                # EVTX 是二进制，不能按行读：交给 evtx 组件逐条出事件，一条记录一次 emit
                for line_no, (raw, record) in enumerate(evtx_reader.iter_records(raw_stream), 1):
                    last_line = line_no
                    try:
                        emit(record, line_no, raw)
                    except Exception as exc:
                        failed += 1
                        if len(errors) < 50:
                            errors.append({"line": line_no, "error": str(exc), "raw": raw[:500]})
            else:
                selected_encoding = "gb18030" if encoding.lower() in ("gbk", "gb18030") else "utf-8-sig"
                with io.TextIOWrapper(raw_stream, encoding=selected_encoding, errors="replace", newline=None) as text:
                    for line_no, line in enumerate(text, 1):
                        last_line = line_no
                        try:
                            for record in parser.parse_line(line, line_no):
                                raw_out = record.pop("_raw", line.rstrip("\r\n"))
                                # 超长单行（无换行的 dump/二进制误入）截断存储：
                                # 不截的话这行会在 batch 里常驻，且后续对 raw 的正则要全文扫
                                if len(raw_out) > 1_000_000:
                                    raw_out = raw_out[:1_000_000] + " …[截断]"
                                emit(record, line_no, raw_out)
                        except Exception as exc:
                            failed += 1
                            if len(errors) < 50:
                                errors.append({"line": line_no, "error": str(exc), "raw": line.rstrip("\r\n")[:500]})
                    try:
                        for record in parser.finalize():
                            emit(record, last_line, record.pop("_raw", ""))
                    except Exception as exc:
                        failed += 1
                        if len(errors) < 50:
                            errors.append({"line": last_line, "error": str(exc), "raw": "文件末尾"})
            flush()
            warnings = field_warnings()
            status = "done" if rows or failed == 0 else "failed"
            self.store.finish_import(task_id, import_id, rows, failed, errors, first_ts, last_ts, status, nulls)
            return {"id": import_id, "task_id": task_id, "source_id": source_id, "format": config["id"], "filename": filename, "rows": rows, "failed": failed, "errors": errors, "nulls": {k: v for k, v in nulls.items() if v}, "warnings": warnings, "first_ts": first_ts, "last_ts": last_ts, "status": status}
        except Exception as exc:
            conn.rollback()
            if failed == 0:
                failed = 1
            self.store.finish_import(task_id, import_id, rows, failed, errors + [{"line": 0, "error": str(exc)}], first_ts, last_ts, "failed")
            raise
        finally:
            conn.close()

    def import_text(self, task_id: str, source_id: str, fmt: str, text: str, filename: str = "paste.log") -> dict[str, Any]:
        payload = text.encode("utf-8")
        return self.import_stream(task_id, source_id, fmt, filename, io.BytesIO(payload), len(payload))

    @staticmethod
    def preview(fmt: str, source_id: str, text: str, limit: int = 100) -> dict[str, Any]:
        parser = LogParser(fmt, source_id)
        rows = []
        errors = []
        last_line = 0
        for line_no, line in enumerate(io.StringIO(text), 1):
            last_line = line_no
            if len(rows) >= limit:
                break
            try:
                for record in parser.parse_line(line, line_no):
                    record["line_no"] = line_no
                    record["raw"] = record.pop("_raw", line.rstrip("\r\n"))
                    rows.append(record)
                    if len(rows) >= limit:
                        break
            except Exception as exc:
                errors.append({"line": line_no, "error": str(exc), "raw": line.rstrip("\r\n")[:500]})
        if len(rows) < limit:
            try:
                for record in parser.finalize():
                    record["line_no"] = last_line
                    record["raw"] = record.pop("_raw", "")
                    rows.append(record)
            except Exception as exc:
                errors.append({"line": last_line, "error": str(exc), "raw": "文件末尾"})
        return {"rows": rows[:limit], "errors": errors, "config": parser_config(fmt)}
