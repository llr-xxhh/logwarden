"""DuckDB storage boundary for LogWarden (并行于 SQLite 版的独立实现)。

与 storage.py 的公开方法签名完全一致，services/ 与 app.py 不需要知道自己连的是哪种库。
差异集中在四件事：

1. 连接不能随用随关 —— DuckDB 打开库要读元数据，且同一文件只允许一个进程可写。
   这里按文件路径缓存连接，`close()` 做成 no-op，真正释放只在删除任务时。
2. DuckDB 的 connection 不是线程安全的，所有执行都过一把全局可重入锁。
3. 没有 `executescript`、没有 `AUTOINCREMENT`、`executemany` 慢到不可用。
   分别用「按分号拆语句」「SEQUENCE + DEFAULT nextval」「Appender 批量灌」替代。
4. 行对象不是 sqlite3.Row，查询结果统一包成 dict。

时间列 ts 仍是毫秒，取小时要 `EXTRACT(hour FROM to_timestamp(ts/1000.0))`，
session 时区默认跟随系统，与 SQLite 的 'localtime' 等价。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import duckdb

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("LOGVIEW_DATA_DIR", BASE_DIR)).resolve()
ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# DuckDB 把 TEXT 存成 VARCHAR、INTEGER 存成 BIGINT。前端按 SQLite 的类型名决定
# 筛选控件（数字框 / 文本框），这里映射回去，否则界面行为会和 SQLite 版不一致。
TYPE_MAP = {
    "VARCHAR": "TEXT", "CHAR": "TEXT", "BPCHAR": "TEXT", "JSON": "TEXT", "UUID": "TEXT",
    "BIGINT": "INTEGER", "INTEGER": "INTEGER", "HUGEINT": "INTEGER",
    "SMALLINT": "INTEGER", "TINYINT": "INTEGER", "UBIGINT": "INTEGER",
    "DOUBLE": "REAL", "FLOAT": "REAL", "REAL": "REAL", "DECIMAL": "REAL",
    "BOOLEAN": "INTEGER", "BLOB": "BLOB",
    "TIMESTAMP": "TEXT", "TIMESTAMP WITH TIME ZONE": "TEXT", "DATE": "TEXT", "TIME": "TEXT",
}
AUTOINC_RE = re.compile(r"\bid\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", re.I)

KEY_FIELDS = {
    "combined": ("ts", "ip"),
    "w3c": ("ts", "ip"),
    "syslog": ("ts", "host", "user"),
    "audit": ("ts", "type"),
    "shell": ("cmd",),
    "windows_event": ("ts", "eventId"),
    "json": ("ts", "msg"),
    "text": ("ts", "msg"),
    "firewall": ("ts", "srcip", "dstip"),
}
NULL_WARN_MIN_ROWS = 20
NULL_WARN_RATIO = 0.95
NULL_WARN_MAX_FAILED = 0.2

INTERNAL_COLUMNS = {"id", "task_id", "import_id", "line_no", "raw", "source_id", "ext"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return prefix + "_" + uuid.uuid4().hex[:12]


def valid_id(value: str) -> str:
    if not value or not ID_RE.fullmatch(value):
        raise ValueError("非法任务或导入 ID")
    return value


def ident(value: str) -> str:
    if not value or not IDENT_RE.fullmatch(value):
        raise ValueError("非法 SQL 标识符")
    return value


class Rows:
    """把 DuckDB 的 tuple 结果包成 sqlite3.Row 那样能按列名取的对象。

    各方法沿用 SQLite 版的消费习惯：fetchone / fetchall / for 循环三种都有，
    所以这里把三种都实现一遍，方法体本身就不用动。
    """

    __slots__ = ("_rows", "_cols", "_i", "_affected")

    def __init__(self, rows: list[tuple], cols: list[str], affected: int = -1):
        self._rows = rows
        self._cols = cols
        self._i = 0
        self._affected = affected

    def fetchone(self) -> dict[str, Any] | None:
        if self._i >= len(self._rows):
            return None
        row = dict(zip(self._cols, self._rows[self._i]))
        self._i += 1
        return row

    def fetchall(self) -> list[dict[str, Any]]:
        out = [dict(zip(self._cols, r)) for r in self._rows[self._i:]]
        self._i = len(self._rows)
        return out

    def __iter__(self):
        return self.fetchall().__iter__()

    def __len__(self) -> int:
        return len(self._rows) - self._i

    @property
    def rowcount(self) -> int:
        # DuckDB 对 DELETE/UPDATE/INSERT 返回一行一列的 Count，而连接对象自带的
        # rowcount 才是真正的受影响行数；SELECT 没有这个概念，用结果长度兜底。
        if self._affected >= 0:
            return self._affected
        return len(self._rows)


class Conn:
    """线程安全的连接包装：每个库一把独立锁，close() 释放引用计数。"""

    def __init__(self, raw: duckdb.DuckDBPyConnection, lock: threading.RLock):
        self._raw = raw
        self._lock = lock
        self._ready = False
        self._refs = 0         # 活跃调用者计数；>0 时连接池不淘汰
        self.last_used = 0.0   # 连接池 LRU 淘汰用

    def touch(self) -> None:
        self.last_used = time.time()

    def acquire(self) -> None:
        """标记一个调用者正在使用此连接（task_connection 时调用）。"""
        self._refs += 1

    # --- 执行 ---------------------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] | None = None) -> Rows:
        with self._lock:
            cur = self._raw.execute(sql, list(params)) if params is not None else self._raw.execute(sql)
            cols = [d[0] for d in cur.description] if cur.description else []
            # 必须当场取完：DuckDB 的 execute 返回连接本身，下一条语句会覆盖结果集
            rows = cur.fetchall() if cols else []
            affected = getattr(cur, "rowcount", -1)
        return Rows(rows, cols, affected if isinstance(affected, int) else -1)

    def executescript(self, sql: str) -> None:
        """DuckDB 没有 executescript，按分号拆开逐条执行。

        这些脚本都是自己写的 DDL，不含分号字面量，简单切分是安全的。
        """
        with self._lock:
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    self._raw.execute(stmt)

    def stream(self, sql: str, params: Iterable[Any] | None = None, batch: int = 50000):
        """全表遍历专用：用独立游标，不持锁 yield，不冻结其他库的操作。

        旧实现把池级全局锁包住整个生成器，frequency() 扫 50M 行期间
        /api/health、其他任务查询全部阻塞 50 秒。现在每个库一把锁，
        且 stream 只在创建游标时短暂持锁，fetchmany 在锁外进行。
        """
        with self._lock:
            cur = self._raw.cursor()
            if params is not None:
                cur.execute(sql, list(params))
            else:
                cur.execute(sql)
            cols = [d[0] for d in cur.description]
        try:
            while True:
                chunk = cur.fetchmany(batch)
                if not chunk:
                    break
                for row in chunk:
                    yield dict(zip(cols, row))
        finally:
            try:
                cur.close()
            except Exception:
                pass

    def append_batch(self, table: str, columns: list[str], rows: list[tuple]) -> None:
        """Appender 是 DuckDB 唯一的快速写入通道（executemany 只有 1200 行/秒）。"""
        with self._lock:
            app = self._raw.appender(ident(table), columns=[ident(c) for c in columns])
            for row in rows:
                app.append_row(*row)
            app.flush()

    def commit(self) -> None:
        """DuckDB 默认自动提交，方法保留只是为了调用点不用改。"""

    def rollback(self) -> None:
        with self._lock:
            try:
                self._raw.execute("ROLLBACK")
            except Exception:
                pass

    def close(self) -> None:
        """释放一个引用。连接仍留在池中，直到被 LRU 淘汰。"""
        self._refs = max(0, self._refs - 1)

    @property
    def ready(self) -> bool:
        return self._ready

    def mark_ready(self) -> None:
        self._ready = True


class ConnPool:
    """按库文件路径缓存连接。DuckDB 打开一次要读元数据，反复开代价太高。

    每个库一把独立 RLock（不再共用池锁），不同任务的查询/导入可并行。
    池锁只保护 _conns 字典本身的 get/evict 操作。
    """

    MAX_OPEN = 16

    def __init__(self) -> None:
        self._lock = threading.RLock()   # 仅保护 _conns 字典
        self._conns: dict[str, tuple[duckdb.DuckDBPyConnection, Conn]] = {}

    def get(self, path: Path) -> Conn:
        key = str(path)
        with self._lock:
            found = self._conns.get(key)
            if found is not None:
                found[1].touch()
                return found[1]
            self._evict()
            Path(key).parent.mkdir(parents=True, exist_ok=True)
            raw = duckdb.connect(key)
            raw.execute("SET threads=4")
            raw.execute("SET memory_limit='2GB'")
            # 关掉插入顺序保持，批量灌数据时排序开销能省一大截
            raw.execute("SET preserve_insertion_order=false")
            conn = Conn(raw, threading.RLock())   # 每库独立锁
            conn.touch()
            self._conns[key] = (raw, conn)
            return conn

    def _evict(self) -> None:
        """超过上限时关掉最久未用且无活跃引用的库。"""
        if len(self._conns) < self.MAX_OPEN:
            return
        candidates = sorted(
            ((c.last_used, k) for k, c in ((k, v[1]) for k, v in self._conns.items())),
            reverse=False,
        )
        for last_used, key in candidates:
            if len(self._conns) < self.MAX_OPEN:
                break
            found = self._conns.get(key)
            if found is None:
                continue
            # 有活跃调用者（导入线程/拉取线程）时跳过，不关正在用的连接
            if found[1]._refs > 0:
                continue
            self._conns.pop(key, None)
            try:
                found[0].close()
            except Exception:
                pass

    def drop(self, path: Path) -> None:
        """删除任务文件前必须真关连接，Windows 上被占用的文件删不掉。"""
        key = str(path)
        with self._lock:
            found = self._conns.pop(key, None)
            if found is not None:
                try:
                    found[0].close()
                except Exception:
                    pass

    def close_all(self) -> None:
        with self._lock:
            for raw, _ in self._conns.values():
                try:
                    raw.close()
                except Exception:
                    pass
            self._conns.clear()


def sqlite_type(duck_type: str) -> str:
    text = (duck_type or "TEXT").upper().strip()
    if text.startswith("DECIMAL") or text.startswith("NUMERIC"):
        return "REAL"
    if "[]" in text:
        return "TEXT"
    return TYPE_MAP.get(text, "TEXT")


def duck_ddl(ddl: str, table: str) -> list[str]:
    """把 SQLite 风格 DDL 翻成 DuckDB 能执行的语句序列。

    parser/*.json 与模板里写的都是 `id INTEGER PRIMARY KEY AUTOINCREMENT`，
    保持那一份来源不变，在这里补 sequence —— 换库不该要求用户改模板。

    另一个必改项：SQLite 的 INTEGER 是 64 位，DuckDB 的 INTEGER 是 32 位。
    ts 存的是毫秒（约 1.8e12），直接进 INTEGER 会溢出，必须抬成 BIGINT。
    """
    table = ident(table)
    has_autoinc = bool(AUTOINC_RE.search(ddl))
    stmts: list[str] = []
    if has_autoinc:
        seq = "seq_" + table
        stmts.append("CREATE SEQUENCE IF NOT EXISTS " + ident(seq))
        ddl = AUTOINC_RE.sub("id BIGINT DEFAULT nextval('" + seq + "')", ddl)
    # 顺序不能反：先把 AUTOINCREMENT 换掉，再统一抬宽，否则主键那行会被重复改写
    ddl = re.sub(r"\bINTEGER\b", "BIGINT", ddl, flags=re.I)
    stmts.append(ddl)
    return stmts


class Store:
    # 供规则引擎判断能否把条件下推成 SQL（regexp_matches / count(*) FILTER 只有 DuckDB 有）
    ENGINE = "duckdb"

    def __init__(self, root: Path | str | None = None):
        self.root = Path(root).resolve() if root else DATA_DIR
        # 与 SQLite 版并存时不能共用一个目录，否则 meta 会互相覆盖
        self.task_dir = self.root / "data-duck"
        self.meta_path = self.root / "meta.duckdb"
        self.task_dir.mkdir(parents=True, exist_ok=True)
        self.pool = ConnPool()
        # 首开建表/迁移的全局锁：ALTER TABLE ADD COLUMN 不幂等，
        # 两个线程同时首次打开同一任务库会撞出 duplicate column
        self._mig_lock = threading.Lock()
        self._init_meta()

    # --- 连接 ---------------------------------------------------------------
    def connect(self, path: Path) -> Conn:
        return self.pool.get(path)

    @property
    def meta(self) -> Conn:
        return self.pool.get(self.meta_path)

    def close(self) -> None:
        self.pool.close_all()

    def _init_meta(self) -> None:
        conn = self.meta
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS task (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              arch TEXT NOT NULL DEFAULT '自定义组合',
              template_id TEXT,
              components_json TEXT NOT NULL DEFAULT '[]',
              source_ids_json TEXT NOT NULL DEFAULT '[]',
              status TEXT NOT NULL DEFAULT 'active',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_task_status ON task(status, updated_at)
            """
        )

    def task_path(self, task_id: str) -> Path:
        return self.task_dir / ("task_" + valid_id(task_id) + ".duckdb")

    def task_connection(self, task_id: str) -> Conn:
        path = self.task_path(task_id)
        if not path.exists():
            raise FileNotFoundError("任务数据文件不存在")
        conn = self.pool.get(path)
        conn.acquire()   # 引用计数 +1；调用方 finally conn.close() 时 -1
        # 双检锁：迁移只允许一个线程执行，其余线程等它做完后直接复用结果
        with self._mig_lock:
            if not conn.ready:
                # 建表只在首次打开时跑；分页查询每次都跑一遍是纯浪费
                if not self._schema_ready(conn):
                    self._init_task_db(conn)
                else:
                    self._migrate_task_db(conn)
                conn.mark_ready()
        return conn

    SCHEMA_VERSION = 4
    TABLE_UPGRADES = {
        "raw_combined": {"xff": "TEXT", "host": "TEXT", "ext": "TEXT"},
        "import": {"nulls_json": "TEXT NOT NULL DEFAULT '{}'"},
        # v4：Windows 事件补两列——账号 SID 用于区分同名账号，
        # detail 存没映射成列的 EventData 字段（JSON），供详情面板展开
        "raw_evtx": {"sid": "TEXT", "detail": "TEXT"},
    }

    @classmethod
    def _migrate_task_db(cls, conn: Conn) -> None:
        # 老库可能只有表没有 schema_info（异常状态）：先补上，否则这里第一句就炸，
        # 任务从此所有接口 500
        if not Store._table_exists(conn, "schema_info"):
            conn.execute("CREATE TABLE schema_info (version INTEGER NOT NULL, created_at TEXT NOT NULL)")
        row = conn.execute("SELECT MAX(version) v FROM schema_info").fetchone()
        version = (row["v"] or 0) if row else 0
        if version >= cls.SCHEMA_VERSION:
            return
        for table, columns in cls.TABLE_UPGRADES.items():
            if not Store._table_exists(conn, table):
                continue
            have = {r["name"] for r in conn.execute("PRAGMA table_info(" + ident(table) + ")")}
            for name, ctype in columns.items():
                if name not in have:
                    conn.execute("ALTER TABLE " + ident(table) + " ADD COLUMN " + ident(name) + " " + ctype)
        conn.execute("INSERT INTO schema_info(version,created_at) VALUES(?,?)", (cls.SCHEMA_VERSION, now_iso()))

    @staticmethod
    def _schema_ready(conn: Conn) -> bool:
        return Store._table_exists(conn, "import")

    @staticmethod
    def _table_exists(conn: Conn, table: str) -> bool:
        # 只回答"表在不在"；查询本身出错（锁、IO、库损坏）必须向上抛，
        # 否则调用方会把它当"没有数据"返回空结果，取证现场直接失真
        row = conn.execute("SELECT 1 FROM duckdb_tables() WHERE table_name=?", (table,)).fetchone()
        return row is not None

    @staticmethod
    def _init_task_db(conn: Conn) -> None:
        # 这里的 INTEGER 全部写成 BIGINT：DuckDB 的 INTEGER 只有 32 位，
        # 毫秒时间戳放不进去。SQLite 那边写 INTEGER 本来就是 64 位语义。
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_info (
              version BIGINT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS import (
              id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              source_id TEXT NOT NULL,
              format TEXT NOT NULL,
              filename TEXT NOT NULL,
              size BIGINT NOT NULL DEFAULT 0,
              rows BIGINT NOT NULL DEFAULT 0,
              failed BIGINT NOT NULL DEFAULT 0,
              errors_json TEXT NOT NULL DEFAULT '[]',
              nulls_json TEXT NOT NULL DEFAULT '{}',
              first_ts BIGINT,
              last_ts BIGINT,
              status TEXT NOT NULL DEFAULT 'running',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_import_source ON import(task_id, source_id)
            """
        )
        # alert 表已废弃：告警全部实时计算（rule_engine），此表从未写入，不再创建。
        # 老库里已存在的 alert 表无害，留着不动

    # --- 任务 ---------------------------------------------------------------
    def create_task(self, data: dict[str, Any]) -> dict[str, Any]:
        task_id = new_id("t")
        ts = now_iso()
        name = str(data.get("name", "")).strip()
        if not name:
            raise ValueError("任务名称不能为空")
        components = data.get("components") or []
        source_ids = list(dict.fromkeys(data.get("source_ids") or []))
        path = self.task_path(task_id)
        try:
            conn = self.connect(path)
            self._init_task_db(conn)
            conn.execute("INSERT INTO schema_info(version,created_at) VALUES(?,?)", (self.SCHEMA_VERSION, ts))
            conn.mark_ready()
            self.meta.execute(
                "INSERT INTO task(id,name,arch,template_id,components_json,source_ids_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    task_id,
                    name,
                    str(data.get("arch") or "自定义组合"),
                    data.get("template_id"),
                    json.dumps(components, ensure_ascii=False),
                    json.dumps(source_ids, ensure_ascii=False),
                    ts,
                    ts,
                ),
            )
        except Exception:
            self.pool.drop(path)
            for suffix in ("", ".wal"):
                try:
                    Path(str(path) + suffix).unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        return self.get_task(task_id)

    @staticmethod
    def _task_dict(row: dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["components"] = json.loads(item.pop("components_json") or "[]")
        item["source_ids"] = json.loads(item.pop("source_ids_json") or "[]")
        return item

    def get_task(self, task_id: str) -> dict[str, Any]:
        row = self.meta.execute("SELECT * FROM task WHERE id=? AND status!='deleted'", (valid_id(task_id),)).fetchone()
        if not row:
            raise KeyError("任务不存在")
        item = self._task_dict(row)
        item["stats"] = self.task_stats(task_id)
        return item

    def list_tasks(self) -> list[dict[str, Any]]:
        rows = self.meta.execute("SELECT * FROM task WHERE status='active' ORDER BY updated_at DESC").fetchall()
        result = []
        for row in rows:
            item = self._task_dict(row)
            item["stats"] = self.task_stats(item["id"])
            result.append(item)
        return result

    def update_task_sources(self, task_id: str, source_ids: list[str]) -> None:
        self.meta.execute(
            "UPDATE task SET source_ids_json=?,updated_at=? WHERE id=?",
            (json.dumps(list(dict.fromkeys(source_ids)), ensure_ascii=False), now_iso(), valid_id(task_id)),
        )

    def delete_task(self, task_id: str, permanent: bool = False) -> None:
        valid_id(task_id)
        if not permanent:
            self.meta.execute("UPDATE task SET status='deleted',updated_at=? WHERE id=?", (now_iso(), task_id))
            return
        path = self.task_path(task_id)
        # Windows 上文件被连接占用就删不掉，必须先真关连接
        self.pool.drop(path)
        for suffix in ("", ".wal"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        self.meta.execute("DELETE FROM task WHERE id=?", (task_id,))

    def list_deleted_tasks(self) -> list[dict[str, Any]]:
        rows = self.meta.execute("SELECT * FROM task WHERE status='deleted' ORDER BY updated_at DESC").fetchall()
        return [self._task_dict(row) for row in rows]

    def restore_task(self, task_id: str) -> dict[str, Any]:
        valid_id(task_id)
        if not self.task_path(task_id).exists():
            raise KeyError("任务数据文件已不存在，无法恢复")
        self.meta.execute("UPDATE task SET status='active',updated_at=? WHERE id=? AND status='deleted'", (now_iso(), task_id))
        return self.get_task(task_id)

    def delete_import(self, task_id: str, import_id: str) -> dict[str, Any]:
        """删除一次导入及其写入的全部行。

        导入错误（选错源、选错格式、传错文件）只能整批回滚，逐行删没有意义。
        表内再无任何数据时直接 DROP —— 列存库删行不缩文件，留着会一直占盘。
        """
        valid_id(task_id)
        valid_id(import_id)
        conn = self.task_connection(task_id)
        try:
            record = conn.execute("SELECT * FROM import WHERE id=? AND task_id=?", (import_id, task_id)).fetchone()
            if not record:
                raise KeyError("导入记录不存在")
            if record["status"] == "running":
                # 导入线程还在往库里 flush，此刻删记录会留下无法再回滚的孤儿行
                raise ValueError("该导入正在进行中，请等它完成（或取消拉取）后再回滚")
            deleted = 0
            dropped: list[str] = []
            tables = [
                row["table_name"]
                for row in conn.execute(
                    "SELECT table_name FROM duckdb_tables() WHERE table_name LIKE 'raw\\_%' ESCAPE '\\'"
                )
            ]
            for name in tables:
                columns = {row["name"] for row in conn.execute("PRAGMA table_info(" + ident(name) + ")")}
                if "import_id" not in columns:
                    continue
                result = conn.execute("DELETE FROM " + ident(name) + " WHERE task_id=? AND import_id=?", (task_id, import_id))
                deleted += max(result.rowcount, 0)
                left = conn.execute("SELECT 1 FROM " + ident(name) + " LIMIT 1").fetchone()
                if left is None:
                    conn.execute("DROP TABLE " + ident(name))
                    dropped.append(name)
            conn.execute("DELETE FROM import WHERE id=? AND task_id=?", (import_id, task_id))
        finally:
            conn.close()
        return {
            "ok": True,
            "import_id": import_id,
            "source_id": record["source_id"],
            "filename": record["filename"],
            "deleted_rows": deleted,
            "dropped_tables": dropped,
        }

    def task_stats(self, task_id: str) -> dict[str, Any]:
        path = self.task_path(task_id)
        if not path.exists():
            return {"total": 0, "sources": 0, "first": None, "last": None, "source_counts": {}}
        conn = self.task_connection(task_id)
        try:
            row = conn.execute(
                "SELECT COALESCE(SUM(rows),0) total,COUNT(DISTINCT CASE WHEN rows>0 THEN source_id END) sources,MIN(first_ts) first,MAX(last_ts) last FROM import"
            ).fetchone()
            counts = {
                r["source_id"]: r["n"]
                for r in conn.execute("SELECT source_id,SUM(rows) n FROM import GROUP BY source_id")
            }
        finally:
            conn.close()
        return {"total": row["total"], "sources": row["sources"], "first": row["first"], "last": row["last"], "source_counts": counts}

    @staticmethod
    def field_warnings(fmt: str, rows: int, failed: int, nulls: dict[str, int] | None) -> list[dict[str, Any]]:
        total = rows + failed
        if rows < NULL_WARN_MIN_ROWS or not total or failed > total * NULL_WARN_MAX_FAILED:
            return []
        counts = nulls or {}
        found = []
        for field in KEY_FIELDS.get(fmt, ()):
            count = counts.get(field, 0)
            if count / rows >= NULL_WARN_RATIO:
                found.append({"field": field, "nulls": count, "ratio": round(count / rows, 3)})
        return found

    def list_imports(self, task_id: str) -> list[dict[str, Any]]:
        conn = self.task_connection(task_id)
        try:
            rows = conn.execute("SELECT * FROM import WHERE task_id=? ORDER BY created_at DESC", (task_id,)).fetchall()
        finally:
            conn.close()
        result = []
        for row in rows:
            item = dict(row)
            item["errors"] = json.loads(item.pop("errors_json") or "[]")
            item["nulls"] = json.loads(item.pop("nulls_json", "{}") or "{}")
            item["warnings"] = self.field_warnings(item.get("format", ""), item["rows"], item["failed"], item["nulls"])
            result.append(item)
        return result

    def begin_import(self, task_id: str, source_id: str, fmt: str, filename: str, size: int) -> str:
        import_id = new_id("i")
        conn = self.task_connection(task_id)
        try:
            conn.execute(
                "INSERT INTO import(id,task_id,source_id,format,filename,size,created_at) VALUES(?,?,?,?,?,?,?)",
                (import_id, task_id, source_id, fmt, filename, int(size or 0), now_iso()),
            )
        finally:
            conn.close()
        return import_id

    def finish_import(
        self,
        task_id: str,
        import_id: str,
        rows: int,
        failed: int,
        errors: list[dict[str, Any]],
        first_ts: int | None,
        last_ts: int | None,
        status: str = "done",
        nulls: dict[str, int] | None = None,
    ) -> None:
        conn = self.task_connection(task_id)
        try:
            conn.execute(
                "UPDATE import SET rows=?,failed=?,errors_json=?,nulls_json=?,first_ts=?,last_ts=?,status=? WHERE id=? AND task_id=?",
                (rows, failed, json.dumps(errors[:50], ensure_ascii=False), json.dumps(nulls or {}, ensure_ascii=False), first_ts, last_ts, status, import_id, task_id),
            )
        finally:
            conn.close()
        self.meta.execute("UPDATE task SET updated_at=? WHERE id=?", (now_iso(), task_id))

    # --- 表结构 -------------------------------------------------------------
    @staticmethod
    def table_schema(conn: Conn, table: str) -> list[dict[str, str]]:
        table = ident(table)
        if not Store._table_exists(conn, table):
            return []
        return [
            {"name": r["name"], "type": sqlite_type(r["type"])}
            for r in conn.execute("PRAGMA table_info(" + table + ")")
            if r["name"] not in INTERNAL_COLUMNS
        ]

    @staticmethod
    def table_columns(conn: Conn, table: str) -> list[str]:
        return [c["name"] for c in Store.table_schema(conn, table)]

    @staticmethod
    def ensure_columns(conn: Conn, table: str, columns: dict[str, str]) -> list[str]:
        """按模板声明的列补列。只增不删：删列会让已有数据消失。"""
        table = ident(table)
        if not columns:
            return []
        have = {r["name"] for r in conn.execute("PRAGMA table_info(" + table + ")")}
        added = []
        for name, ctype in columns.items():
            column = ident(name)
            if column in have:
                continue
            # 模板里写的 INTEGER 在 DuckDB 必须是 BIGINT，否则毫秒时间戳溢出
            safe_type = {"INTEGER": "BIGINT", "NUMERIC": "DECIMAL(18,4)"}.get(ctype, ctype)
            if safe_type not in ("TEXT", "BIGINT", "REAL", "BLOB", "DECIMAL(18,4)"):
                safe_type = "TEXT"
            conn.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + safe_type)
            added.append(column)
        return added

    def ensure_raw_table(self, conn: Conn, config: dict[str, Any]) -> None:
        table = ident(config["table"])
        if not table.startswith("raw_"):
            raise ValueError("解析器表名必须以 raw_ 开头")
        ddl = config.get("ddl")
        if not isinstance(ddl, str) or "CREATE TABLE" not in ddl.upper():
            raise ValueError("解析器缺少合法 DDL")
        for stmt in duck_ddl(ddl, table):
            conn.execute(stmt)
        # DuckDB 的 ART 索引只对等值查找有用，GROUP BY 靠 zonemap 扫描已经够快；
        # 只保留 (task_id, source_id) 这一条，避免导入时为多份索引付代价。
        conn.execute(
            "CREATE INDEX IF NOT EXISTS " + ident("idx_" + table[4:] + "_scan") + " ON " + table + "(task_id,source_id)"
        )

    @staticmethod
    def insert_batch(conn: Conn, table: str, fields: list[str], rows: Iterable[dict[str, Any]]) -> int:
        payload = list(rows)
        if not payload:
            return 0
        base = ["task_id", "import_id", "line_no", "raw"]
        columns = base + list(fields)
        tuples = [tuple(row.get(c) for c in columns) for row in payload]
        conn.append_batch(table, columns, tuples)
        return len(tuples)

    @staticmethod
    def table_exists(conn: Conn, table: str) -> bool:
        return Store._table_exists(conn, ident(table))

    def stream_rows(self, task_id: str, table: str, source_id: str, fields: list[str]):
        """整源顺扫，供规则引擎逐行匹配用。

        原来的 all_rows() 走游标分页，每页 500 行还带一次 COUNT(*)；
        50 万行就是 1000 次全表计数，告警一次要 80 秒。列存库没必要这么绕，
        一次顺序读到底，边读边匹配。
        """
        conn = self.task_connection(task_id)
        try:
            if not self.table_exists(conn, table):
                return
            columns = ["id", "line_no", "raw"] + [ident(f) for f in fields]
            sql = ("SELECT " + ",".join(ident(c) if c not in ("id", "line_no", "raw") else c for c in columns)
                   + " FROM " + ident(table) + " WHERE task_id=? AND source_id=? ORDER BY id")
            yield from conn.stream(sql, (task_id, source_id))
        finally:
            # 生成器被 close（含消费方中途放弃）时也会执行，refs 不会悬挂
            conn.close()

    # --- 查询 ---------------------------------------------------------------
    def query_rows(
        self,
        task_id: str,
        table: str,
        source_id: str,
        fields: list[str],
        options: dict[str, Any],
    ) -> dict[str, Any]:
        table = ident(table)
        allowed = set(fields) | {"id", "task_id", "import_id", "line_no", "raw"}
        # 历史误会高发点：请求体传 filters 会被整个忽略，用户以为筛选生效了
        if "filters" in options:
            raise ValueError('不支持的参数 "filters"：筛选请用 fk（字段=值）或 colf（列条件）')
        # omit 用于批量读取时裁掉 raw 这类大字段：列表页只需要结构化列，
        # 原文按需再取。27k 行时能让切源少传约 70% 的字节。
        om = options.get("omit") or []
        if not isinstance(om, (list, tuple, set)):
            raise ValueError("omit 必须是数组")
        omitted = {str(x) for x in om}
        fk = options.get("fk") or {}
        colf = options.get("colf") or {}
        if not isinstance(fk, dict) or not isinstance(colf, dict):
            raise ValueError("fk 与 colf 必须是对象")
        sort_opt = options.get("sort") or {}
        if not isinstance(sort_opt, dict):
            raise ValueError('sort 必须是对象，如 {"k":"ts","dir":-1}')
        base_cols = ["id", "line_no", "raw"] + list(fields)
        selected = [ident(c) for c in base_cols if c == "id" or c not in omitted]
        conn = self.task_connection(task_id)
        try:
            # size/page 的类型校验放在所有早退之前：空任务也该给出一致的 400，
            # 而不是「有数据才报错」这种看运气的行为
            try:
                size = max(1, min(2000, int(options.get("size") or 100)))
                page = max(1, int(options.get("page") or 1))
            except (TypeError, ValueError):
                raise ValueError("size 与 page 必须是整数")
            if not self.table_exists(conn, table):
                return {"rows": [], "total": 0, "page": 1, "pages": 1, "size": size}
            where = ["task_id=?", "source_id=?"]
            params: list[Any] = [task_id, source_id]

            def add(column: str, expr: str, values: Iterable[Any]) -> None:
                if column not in allowed:
                    raise ValueError("未知筛选字段: " + column)
                where.append(expr.format(c=ident(column)))
                params.extend(values)

            q = str(options.get("q") or "")
            if q:
                end = q.rfind("/")
                is_regex = len(q) > 2 and q.startswith("/") and end > 0 and q[end + 1:] in ("", "i")
                if is_regex:
                    pattern = q[1:end]
                    if len(pattern) > 256:
                        raise ValueError("正则最长 256 字符")
                    # DuckDB 底层是 RE2：lookaround/反向引用直接抛引擎错误变 500，
                    # 这里预检成 400 给出可读提示（规则引擎有同样的检查，查询侧补齐）
                    if any(m in pattern for m in ("(?=", "(?!", "(?<=", "(?<!")) or re.search(r"\\[1-9]", pattern):
                        raise ValueError("搜索正则不支持前后查找（lookaround）和反向引用，请改写后重试")
                    # 大小写用 (?i) 前缀表达，与原先 re.IGNORECASE 等价。
                    if q[end + 1:] == "i":
                        pattern = "(?i)" + pattern
                    where.append("regexp_matches(raw, ?)")
                    params.append(pattern)
                else:
                    where.append("raw LIKE ? ESCAPE '\\'")
                    params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
            status = str(options.get("status") or "")
            if status and "status" in allowed:
                add("status", "CAST({c} AS TEXT) LIKE ?", [status + "%"])
            if options.get("ex404") and "status" in allowed:
                where.append("status!=404")
            if options.get("exStatic") and "path" in allowed:
                # 原先写的是 NOT REGEXP '...'，DuckDB 没有 REGEXP 操作符，换成函数调用
                where.append("NOT regexp_matches(LOWER(path), ?)")
                params.append(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)(\?|$)")
            if options.get("exProbe") and "ua" in allowed:
                where.append("LOWER(COALESCE(ua,'')) NOT LIKE '%zabbix%' AND LOWER(COALESCE(ua,'')) NOT LIKE '%kube-probe%'")
            for key, value in (options.get("fk") or {}).items():
                if value not in (None, ""):
                    add(key, "CAST({c} AS TEXT)=?", [str(value)])
            for key, cond in (options.get("colf") or {}).items():
                if key == "ts":
                    if cond.get("from") is not None:
                        add(key, "{c}>=?", [int(cond["from"])])
                    if cond.get("to") is not None:
                        add(key, "{c}<=?", [int(cond["to"])])
                    continue
                vals = cond.get("vals") or []
                if vals:
                    marks = ",".join("?" for _ in vals)
                    add(key, "CAST({c} AS TEXT) IN (" + marks + ")", [str(v) for v in vals])
                if str(cond.get("q") or "").strip():
                    needle = str(cond["q"]).strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    add(key, "LOWER(CAST({c} AS TEXT)) LIKE ? ESCAPE '\\'", ["%" + needle + "%"])
            cursor = options.get("cursor")
            # 总数只看筛选条件，不能把游标也算进去，否则翻到第 N 页时 total 会缩成剩余条数
            filter_sql = " AND ".join(where)
            # 内部全量扫描（规则引擎逐页取行）不需要 total：55 页就白算 55 次 COUNT(*)
            need_total = options.get("count", True) is not False
            total = conn.execute("SELECT COUNT(*) n FROM " + table + " WHERE " + filter_sql, list(params)).fetchone()["n"] if need_total else None
            where_sql = filter_sql
            row_params = list(params)
            sort = sort_opt
            key = sort.get("k") if sort.get("k") in allowed else "id"
            if key != "id" and key in omitted:
                # 游标取 rows[-1][key]，omit 掉排序列会拿到 None，下一页直接跳过全部数据
                raise ValueError("排序字段 %s 不能同时在 omit 中" % key)
            direction = "DESC" if int(sort.get("dir") or 1) < 0 else "ASC"
            if cursor is not None:
                if key == "id":
                    where_sql += " AND id" + ("<" if direction == "DESC" else ">") + "?"
                    row_params.append(int(cursor.get("id") if isinstance(cursor, dict) else cursor))
                else:
                    if not isinstance(cursor, dict) or "id" not in cursor or "v" not in cursor:
                        raise ValueError("非 ID 排序的游标格式无效")
                    value, cid = cursor["v"], int(cursor["id"])
                    col = ident(key)
                    # 对齐 SQLite 的排序语义：NULL 当作最小值（ASC 最前、DESC 最后）。
                    # DuckDB 默认两个方向都 NULLS LAST，且 col>? / col<? 对 NULL 不匹配，
                    # 不显式处理时按可空列（ua/ref/xff 这类）排序会永远翻不到 NULL 行。
                    # `? IS NULL` 在 DuckDB 里要做参数类型推断，按值是否为空拆 SQL 更稳。
                    if direction == "ASC":
                        if value is None:
                            # NULL 组内推进；NULL 组翻完后，同一页由 LIMIT 按排序带出非 NULL 行
                            where_sql += " AND (" + col + " IS NULL AND id>? OR " + col + " IS NOT NULL)"
                            row_params.append(cid)
                        else:
                            where_sql += " AND (" + col + ">? OR (" + col + "=? AND id>?))"
                            row_params.extend([value, value, cid])
                    else:
                        if value is None:
                            # DESC 时 NULL 组在末尾，组内推进即最后几页
                            where_sql += " AND " + col + " IS NULL AND id<?"
                            row_params.append(cid)
                        else:
                            # 非 NULL 推进的同时放行 NULL 组：LIMIT 按排序取，NULL 行垫底补齐
                            where_sql += " AND (" + col + "<? OR (" + col + "=? AND id<?) OR " + col + " IS NULL)"
                            row_params.extend([value, value, cid])
            offset = 0 if cursor is not None else (page - 1) * size
            sql = "SELECT " + ",".join(selected) + " FROM " + table + " WHERE " + where_sql
            # NULLS FIRST/LAST 显式写死，不依赖引擎默认值；与游标条件配套
            sql += (" ORDER BY " + ident(key) + " " + direction + " "
                    + ("NULLS FIRST" if direction == "ASC" else "NULLS LAST") + ",id " + direction
                    + " LIMIT ? OFFSET ?")
            rows = conn.execute(sql, row_params + [size, offset]).fetchall()
            next_cursor = None
            if len(rows) == size and rows:
                next_cursor = rows[-1]["id"] if key == "id" else {"v": rows[-1].get(key), "id": rows[-1]["id"]}
            return {
                "rows": rows,
                "total": total,
                "page": page,
                "pages": max(1, (total + size - 1) // size) if total is not None else None,
                "size": size,
                "next_cursor": next_cursor,
            }

        finally:
            conn.close()
    def source_summary(self, task_id: str, table: str, source_id: str, fields: list[str]) -> dict[str, Any]:
        conn = self.task_connection(task_id)
        try:
            if not self.table_exists(conn, table):
                return {"total": 0, "first": None, "last": None, "hours": [], "distinct": {}}
            base = "FROM " + ident(table) + " WHERE task_id=? AND source_id=?"
            args = [task_id, source_id]
            row = conn.execute("SELECT COUNT(*) total,MIN(ts) first,MAX(ts) last " + base, args).fetchone()
            distinct = {}
            for field in fields:
                if field in ("ip", "srcip", "path", "host", "user"):
                    distinct[field] = conn.execute(
                        "SELECT COUNT(DISTINCT " + ident(field) + ") n " + base + " AND " + ident(field) + " IS NOT NULL AND " + ident(field) + "!='-'",
                        args,
                    ).fetchone()["n"]
            hours = [0] * 24
            if "ts" in fields:
                # ts 是毫秒：to_timestamp 收秒，所以除 1000.0；session 时区默认跟随系统，
                # 与 SQLite 的 'localtime' 修饰符等价。
                # 本地小时用纯算术：ts 是 UTC 毫秒，加本机偏移后对 86400 取模。
                # 不用 EXTRACT(hour FROM to_timestamp(...)) 是因为它依赖 session 时区
                # （ICU 扩展没加载时默认 UTC，直方图会整体偏移几小时）
                gmtoff = int(time.localtime().tm_gmtoff or 0)
                hour_rows = conn.execute(
                    "SELECT CAST(((ts/1000 + %d) %% 86400) / 3600 AS INTEGER) h,COUNT(*) n "
                    % gmtoff + base + " AND ts IS NOT NULL GROUP BY h",
                    args,
                ).fetchall()
                for r in hour_rows:
                    if r["h"] is not None:
                        hours[int(r["h"])] = r["n"]
            summary = {"total": row["total"], "first": row["first"], "last": row["last"], "hours": hours, "distinct": distinct}
            if "status" in fields:
                summary["errors"] = conn.execute("SELECT COUNT(*) n " + base + " AND status>=400", args).fetchone()["n"]
            if "bytes" in fields:
                summary["avg_bytes"] = round(conn.execute("SELECT AVG(bytes) n " + base, args).fetchone()["n"] or 0)
                summary["total_bytes"] = conn.execute("SELECT SUM(bytes) n " + base, args).fetchone()["n"] or 0
            return summary

        finally:
            conn.close()
    def rank(self, task_id: str, table: str, source_id: str, field: str, fields: list[str], sort: str = "cnt", limit: int = 500) -> list[dict[str, Any]]:
        if field not in fields:
            raise ValueError("该日志源没有此统计维度")
        conn = self.task_connection(task_id)
        try:
            if not self.table_exists(conn, table):
                return []
            select = "COALESCE(CAST(" + ident(field) + " AS TEXT),'') k,COUNT(*) cnt"
            if "bytes" in fields:
                select += ",COALESCE(SUM(bytes),0) bytes"
            else:
                select += ",0 bytes"
            # 首末见时间：应急排查第一问"这个 IP 什么时候第一次出现"
            if "ts" in fields:
                select += ",MIN(ts) first_seen,MAX(ts) last_seen"
            # 错误计数：status 列可能是 VARCHAR，用 TRY_CAST 避免 BinderException
            if "status" in fields:
                select += ",SUM(CASE WHEN TRY_CAST(status AS INTEGER)>=400 THEN 1 ELSE 0 END) errs"
            sql = "SELECT " + select + " FROM " + ident(table) + " WHERE task_id=? AND source_id=? GROUP BY " + ident(field)
            sql += " ORDER BY " + ("bytes" if sort == "bytes" else "cnt") + " DESC,k ASC"
            # 无 LIMIT 时百万基数会物化 640MB dict；默认 500，上限 10000
            sql += " LIMIT " + str(max(1, min(int(limit), 10000)))
            return conn.execute(sql, (task_id, source_id)).fetchall()

        finally:
            conn.close()
    def frequency(self, task_id: str, table: str, source_id: str, group_field: str, fields: list[str], window_ms: int = 60000, scan_shape: bool = True) -> list[dict[str, Any]]:
        """Streaming sliding-window peak, grouped by an allowed field.

        scan_shape 只对 web 源开：那边的 target 是请求路径，「路径多且不重复」才算扫描。
        非 web 源的 target 混着 user / eventId，用同一判据会把用户枚举说成目录扫描。
        """
        from collections import Counter, deque

        if group_field not in fields:
            raise ValueError("该日志源没有此频次维度")
        conn = self.task_connection(task_id)
        try:
            if not self.table_exists(conn, table) or "ts" not in fields:
                return []
            target = "path" if "path" in fields else ("user" if "user" in fields else ("eventId" if "eventId" in fields else "raw"))
            sql = "SELECT " + ident(group_field) + " g,ts," + ident(target) + " target FROM " + ident(table)
            sql += " WHERE task_id=? AND source_id=? AND ts IS NOT NULL ORDER BY " + ident(group_field) + ",ts"
            output = []
            current = None
            queue = deque()
            path_counts = Counter()
            totals = Counter()
            best: dict[str, Any] = {}

            def finish() -> None:
                if current is None:
                    return
                top_target, top_count = (totals.most_common(1)[0] if totals else ("-", 0))
                count = best.get("cnt", 0)
                paths = best.get("paths", 0)
                # 阈值按次/分钟折算：窗口改成 5 分钟时，同样 30 次已不是「高频」。
                rate = count * 60.0 / max(1, window_ms / 1000)
                judge = "正常"
                if scan_shape and paths >= 20 and count <= paths * 2:
                    # 大量不同路径、每个基本只打一次，是扫描器的形状，与窗口大小无关
                    judge = "目录扫描"
                elif count >= 3:                   # 样本太小，任何速率都不足以下结论
                    if rate > 100 and paths > 20:
                        judge = "目录扫描"
                    elif rate > 30:
                        judge = "高频突发"
                    elif rate > 12:
                        judge = "中度集中"
                output.append({"key": current, "cnt": count, "paths": paths, "start": best.get("start"), "top": top_target, "top_count": top_count, "total": sum(totals.values()), "judge": judge, "window_sec": round(window_ms / 1000)})

            for row in conn.stream(sql, (task_id, source_id)):
                group = str(row["g"] if row["g"] is not None else "-")
                if group != current:
                    finish()
                    current = group
                    queue.clear()
                    path_counts.clear()
                    totals.clear()
                    best = {"cnt": 0, "paths": 0, "start": row["ts"]}
                ts = row["ts"]
                target_value = str(row["target"] or "-")
                totals[target_value] += 1
                queue.append((ts, target_value))
                path_counts[target_value] += 1
                while queue and ts - queue[0][0] > window_ms:
                    _, old_target = queue.popleft()
                    path_counts[old_target] -= 1
                    if path_counts[old_target] <= 0:
                        del path_counts[old_target]
                # 窗口选择不能只看次数：扫描器 60 秒打 23 个路径，放大到 5 分钟后
                # 「次数最多」的那段可能只是某个接口被反复请求，扫描特征整段被盖掉。
                # 按 次数 + 路径数×3 打分，路径多样性优先。
                score = len(queue) + len(path_counts) * 3
                if score > best.get("score", -1):
                    best = {"cnt": len(queue), "paths": len(path_counts), "start": queue[0][0], "score": score}
            finish()
            return sorted(output, key=lambda x: x["cnt"], reverse=True)

        finally:
            conn.close()
    def path_baseline(self, task_id: str, table: str, source_id: str) -> list[dict[str, Any]]:
        conn = self.task_connection(task_id)
        try:
            if not self.table_exists(conn, table):
                return []
            output = []
            current = None
            values: list[int] = []
            # 跟踪每个 base path 下有多少种不同的完整 URL（含 query）。
            # query 多样性高 = 参数投毒/扫描信号；砍掉 query 后这个维度就不可见了。
            query_set: set[str] = set()
            QUERY_CAP = 10_000  # 防止热点路径把 set 撑爆

            def finish() -> None:
                if current is None or not values:
                    return
                count = n_seen[current]
                avg = round(total[current] / count)
                p95 = values[min(len(values) - 1, int(len(values) * 0.95))]
                # max 不能用 values[-1]：bytes 升序流入、values 超过窗口被截断后，
                # values[-1] 只是「第 N 小的值」，会把超大响应（数据外带信号）抹掉
                output.append({"path": current, "count": count, "avg": avg, "p95": p95, "min": values[0], "max": max_seen[current], "queries": len(query_set)})

            # 单路径值序列只留前 20 万个：热点路径（探针/CDN 回源）千万行时
            # 全量驻留会吃掉数 GB。窗口内的 p95/min 是近似值，count/avg/max 全量。
            BASELINE_WINDOW = 200_000
            n_seen: dict[str, int] = {}
            total: dict[str, int] = {}
            max_seen: dict[str, int] = {}
            for row in conn.stream(
                "SELECT path,bytes FROM " + ident(table) + " WHERE task_id=? AND source_id=? AND path IS NOT NULL ORDER BY path,bytes",
                (task_id, source_id),
            ):
                full_path = str(row["path"] or "-")
                path = full_path.split("?", 1)[0]
                if path != current:
                    finish()
                    current = path
                    values = []
                    query_set = set()
                    n_seen[current] = 0
                    total[current] = 0
                    max_seen[current] = 0
                if len(query_set) < QUERY_CAP:
                    query_set.add(full_path)
                b = int(row["bytes"] or 0)
                n_seen[current] += 1
                total[current] += b
                if b > max_seen[current]:
                    max_seen[current] = b
                if len(values) < BASELINE_WINDOW:
                    values.append(b)
            finish()
            return sorted(output, key=lambda x: x["count"], reverse=True)

        finally:
            conn.close()