from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from storage import Store
from services.importer import Importer
from services.parsing import LogParser
from services.query import QueryService
from services.rule_engine import RuleEngine, RuleStore, matches


WEB = """10.20.31.15 - - [04/Nov/2026:09:00:00 +0800] \"GET /index.html HTTP/1.1\" 200 8432 \"-\" \"Mozilla/5.0\"
103.91.208.11 - - [04/Nov/2026:09:01:00 +0800] \"GET /.git/config HTTP/1.1\" 404 153 \"-\" \"sqlmap/1.7.2\"
103.91.208.11 - - [04/Nov/2026:09:02:00 +0800] \"POST /upload/shell.php HTTP/1.1\" 200 42 \"-\" \"Mozilla/5.0\"
"""
AUTH = """Nov  4 09:00:00 web01 sshd[2100]: Failed password for invalid user admin from 103.91.208.11 port 40000 ssh2
Nov  4 09:01:00 web01 sshd[2101]: Accepted publickey for ops from 10.20.31.15 port 47812 ssh2
"""


class BackendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = Store(root)
        self.queries = QueryService(self.store)
        self.importer = Importer(self.store, self.queries)
        self.rules = RuleStore(root / "custom")
        self.engine = RuleEngine(self.store, self.queries, self.rules)
        self.task = self.store.create_task({"name": "接口测试", "components": ["nginx", "ubuntu"], "source_ids": ["nginx_access", "ubuntu_auth"]})
        self.task_id = self.task["id"]
        # 模板目录是模块级状态，测试结束必须还原，否则会写进真实的 formats/
        from services import web_format
        self._format_dir = web_format.FORMAT_DIR

    def tearDown(self):
        from services import web_format
        web_format.FORMAT_DIR = self._format_dir
        self.store.close()
        self.tmp.cleanup()

    def test_update_task_sources_preserves_data_and_updates_views(self):
        """证据清单抽屉勾选增删：摘掉的源从视图/证据消失但数据保留，重新勾上原样恢复。"""
        self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        self.importer.import_text(self.task_id, "ubuntu_auth", "syslog", AUTH)

        self.store.update_task_sources(self.task_id, ["nginx_access"])
        view = self.queries.task_view(self.task_id)
        self.assertEqual(view["source_ids"], ["nginx_access"])
        self.assertNotIn("ubuntu_auth", {s["id"] for s in view["sources"]})
        # 总行数是库内存量口径：取消勾选不删数据，total 不变；清单范围由证据分母表达
        self.assertEqual(view["stats"]["total"], 5)
        all_logs = {l["id"] for c in view["evidence"] for l in c["logs"]}
        self.assertNotIn("ubuntu_auth", all_logs)

        self.store.update_task_sources(self.task_id, ["nginx_access", "ubuntu_auth"])
        view = self.queries.task_view(self.task_id)
        self.assertEqual(view["stats"]["total"], 5)
        self.assertIn("ubuntu_auth", {s["id"] for s in view["sources"]})

    def test_import_query_stats_alerts_and_delete(self):
        result = self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        self.assertEqual(result["rows"], 3)
        self.assertEqual(result["failed"], 0)
        self.importer.import_text(self.task_id, "ubuntu_auth", "syslog", AUTH)

        view = self.queries.task_view(self.task_id)
        self.assertEqual(view["stats"]["total"], 5)
        self.assertEqual(view["stats"]["sources"], 2)
        self.assertEqual(view["stats"]["source_counts"]["nginx_access"], 3)

        query = self.queries.query(self.task_id, "nginx_access", {"q": "/sqlmap/i", "size": 100})
        self.assertEqual(query["total"], 1)
        self.assertEqual(query["rows"][0]["ip"], "103.91.208.11")
        filtered = self.queries.query(self.task_id, "nginx_access", {"colf": {"status": {"vals": ["200"]}}})
        self.assertEqual(filtered["total"], 2)

        stats = self.queries.stats(self.task_id, "nginx_access")
        self.assertEqual(stats["summary"]["total"], 3)
        self.assertEqual(stats["summary"]["errors"], 1)
        self.assertEqual(stats["ranking"][0]["cnt"], 2)
        self.assertEqual(len(stats["baseline"]), 3)

        alerts = self.engine.alerts(self.task_id, "nginx_access")
        self.assertGreater(alerts["total"], 0)
        self.assertTrue(any(x["rule"]["id"] == "sensitive_file" and x["count"] == 1 for x in alerts["rules"]))
        auth_alerts = self.engine.alerts(self.task_id, "ubuntu_auth")
        self.assertGreaterEqual(auth_alerts["total"], 0)

        self.store.delete_task(self.task_id, permanent=True)
        self.assertFalse(self.store.task_path(self.task_id).exists())

    def _web_lines(self, count: int, paths: int = 1, start: int = 0, ip: str = "203.0.113.9") -> str:
        """造 count 行同 IP 日志；paths>1 时同一秒内并排多个路径，用来压出目录扫描。"""
        out = []
        for i in range(count):
            sec = start + i // max(1, paths)
            path = "/p%d" % (i % paths) if paths > 1 else "/login"
            out.append(
                '%s - - [04/Nov/2026:%02d:%02d:%02d +0800] "GET %s HTTP/1.1" 200 120 "-" "sqlmap/1.7"'
                % (ip, 9 + sec // 3600, (sec // 60) % 60, sec % 60, path)
            )
        return "\n".join(out) + "\n"

    def test_frequency_scan_shape_survives_window_change(self):
        """扫描器的形状是「大量不同路径、每个只打一次」，换多大窗口都不该改判。"""
        self.importer.import_text(self.task_id, "nginx_access", "combined", self._web_lines(120, paths=120))
        for sec in (60, 300, 900):
            item = self.queries.stats(self.task_id, "nginx_access", window_sec=sec)["frequency"][0]
            self.assertEqual(item["cnt"], 120)
            self.assertEqual(item["paths"], 120)
            self.assertEqual(item["judge"], "目录扫描", "%s 秒窗口下结论应保持一致" % sec)
            self.assertEqual(item["window_sec"], sec)

        self.assertEqual(self.queries.stats(self.task_id, "nginx_access", window_sec=0)["window_sec"], 60)
        self.assertEqual(self.queries.stats(self.task_id, "nginx_access", window_sec=999999)["window_sec"], 86400)

    def test_frequency_density_drops_with_window(self):
        """同一接口被反复请求：60 秒看是高频，摊到 5 分钟就该降档，而不是一直喊高危。"""
        self.importer.import_text(self.task_id, "nginx_access", "combined", self._web_lines(120))
        fast = self.queries.stats(self.task_id, "nginx_access", window_sec=60)["frequency"][0]
        self.assertGreaterEqual(fast["cnt"], 60)
        self.assertEqual(fast["judge"], "高频突发")

        slow = self.queries.stats(self.task_id, "nginx_access", window_sec=300)["frequency"][0]
        self.assertEqual(slow["cnt"], 120)
        self.assertEqual(slow["judge"], "中度集中", "120 次 / 5 分钟 = 24 次/分，降一档")

    def test_frequency_ignores_tiny_samples(self):
        """2 条挤在 5 秒里折算是 24 次/分，但样本不足 3 条时不下结论。"""
        self.importer.import_text(self.task_id, "nginx_access", "combined", self._web_lines(2))
        item = self.queries.stats(self.task_id, "nginx_access", window_sec=5)["frequency"][0]
        self.assertEqual(item["cnt"], 2)
        self.assertEqual(item["judge"], "正常")

    def test_frequency_does_not_call_user_enumeration_scan(self):
        """20 个用户名各失败一次是撞库形状，不能被「路径多且不重复」那条判成目录扫描。"""
        lines = [
            "Nov  4 09:00:%02d web01 sshd[%d]: Failed password for invalid user u%d from 203.0.113.7 port %d ssh2"
            % (i, 3000 + i, i, 40000 + i)
            for i in range(20)
        ]
        self.importer.import_text(self.task_id, "ubuntu_auth", "syslog", "\n".join(lines) + "\n")
        item = self.queries.stats(self.task_id, "ubuntu_auth", window_sec=60)["frequency"][0]
        self.assertEqual(item["cnt"], 20)
        self.assertEqual(item["judge"], "中度集中")
        self.assertNotEqual(item["judge"], "目录扫描")

    def test_baseline_rule_threshold_is_editable(self):
        """体积突变阈值写在规则 agg 里，改规则后引擎必须立即跟着变。"""
        rows = []
        for i in range(25):
            size = 300 if i == 0 else 5000
            rows.append(
                '10.0.0.9 - - [04/Nov/2026:09:00:%02d +0800] "GET /api/order HTTP/1.1" 200 %d "-" "curl/8"' % (i, size)
            )
        self.importer.import_text(self.task_id, "nginx_access", "combined", "\n".join(rows) + "\n")

        def hits() -> int:
            data = self.engine.alerts(self.task_id, "nginx_access")
            return sum(x["count"] for x in data["rules"] if x["rule"]["id"] == "ws_size_shift")

        self.assertGreater(hits(), 0, "1 次 300B 混在 24 次 5000B 里，应判体积突变")

        rule = next(x for x in self.rules.load() if x["id"] == "ws_size_shift")
        tightened = dict(rule)
        tightened["match"] = {"agg": dict(rule["match"]["agg"], ratio_lt=0.05)}
        self.rules.save(tightened)
        self.assertEqual(hits(), 0, "阈值收紧到 5% 后不应再命中")

        relaxed = dict(rule)
        relaxed["match"] = {"agg": dict(rule["match"]["agg"], ratio_lt=0.2)}
        self.rules.save(relaxed)
        self.assertGreater(hits(), 0, "阈值放宽回 20% 后应恢复命中")

    def test_old_task_db_is_migrated_for_new_columns(self):
        """v1 旧库没有 xff/host/ext，打开时要自动补列，不能要求用户重导数据。"""
        self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)   # 先让 raw 表存在
        path = self.store.task_path(self.task_id)
        # DuckDB 单文件单写者，改库前必须先释放 Store 缓存的连接
        self.store.pool.drop(path)
        conn = duckdb.connect(str(path))
        try:
            conn.execute("DROP TABLE raw_combined")
            conn.execute("CREATE SEQUENCE IF NOT EXISTS seq_raw_combined")
            conn.execute(
                "CREATE TABLE raw_combined (id BIGINT DEFAULT nextval('seq_raw_combined'),task_id VARCHAR NOT NULL,"
                "import_id VARCHAR NOT NULL,line_no BIGINT NOT NULL,raw VARCHAR NOT NULL,source_id VARCHAR NOT NULL,"
                "ts BIGINT,ip VARCHAR,method VARCHAR,path VARCHAR,status BIGINT,bytes BIGINT,ua VARCHAR,ref VARCHAR)"
            )
            conn.execute("DELETE FROM schema_info")
            conn.execute("INSERT INTO schema_info(version,created_at) VALUES(1,'2026-01-01T00:00:00+00:00')")
        finally:
            conn.close()

        result = self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        self.assertEqual(result["rows"], 3)

        conn = self.store.task_connection(self.task_id)
        try:
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(raw_combined)")}
            self.assertTrue({"xff", "host", "ext"} <= columns, "旧库必须补上新增列")
            version = conn.execute("SELECT MAX(version) v FROM schema_info").fetchone()["v"]
            self.assertEqual(version, self.store.SCHEMA_VERSION)
            import_columns = {r["name"] for r in conn.execute("PRAGMA table_info(import)")}
            self.assertIn("nulls_json", import_columns, "旧库的 import 表也要补 nulls_json")
        finally:
            conn.close()

    def test_field_warnings_flags_whole_column_missing(self):
        """格式没对上时不会报错，只会整列空；这种静默失败必须转成明确提示。"""
        self.assertEqual(
            self.store.field_warnings("json", 100, 0, {"ts": 100, "msg": 0}),
            [{"field": "ts", "nulls": 100, "ratio": 1.0}],
        )

    def test_field_warnings_needs_enough_rows(self):
        """几行数据空着可能只是恰好没有该字段，不能当格式错误报出来。"""
        self.assertEqual(self.store.field_warnings("json", 5, 0, {"ts": 5}), [])

    def test_field_warnings_skips_when_parse_mostly_failed(self):
        """整行大面积失败时，字段空值是次要问题，先修解析失败。"""
        self.assertEqual(self.store.field_warnings("json", 100, 50, {"ts": 100}), [])

    def test_field_warnings_ignores_derived_fields(self):
        """result/level 这类派生字段为空是正常的，不在关键字段表里就不该告警。"""
        self.assertEqual(self.store.field_warnings("syslog", 500, 0, {"level": 500, "result": 500}), [])

    def test_json_import_without_time_field_raises_warning(self):
        """端到端：25 行没有时间字段的 JSON，导入后必须带 ts 告警。"""
        task = self.store.create_task({"name": "JSON 缺时间", "components": ["docker"], "source_ids": ["docker_json"]})
        lines = "\n".join('{"foo":"bar%d"}' % i for i in range(25))
        result = self.importer.import_text(task["id"], "docker_json", "json", lines)
        self.assertEqual(result["rows"], 25)
        self.assertEqual([w["field"] for w in result["warnings"]], ["ts"])
        self.assertEqual(result["nulls"]["ts"], 25)

        listed = self.store.list_imports(task["id"])[0]
        self.assertEqual([w["field"] for w in listed["warnings"]], ["ts"], "回看历史导入也要能复现告警")

    def test_clean_syslog_import_has_no_warning(self):
        result = self.importer.import_text(self.task_id, "ubuntu_auth", "syslog", AUTH)
        self.assertEqual(result["warnings"], [])

    def _bind_template(self, root, template):
        """把模板目录指到临时路径，别污染真实的 formats/。"""
        from services import web_format

        web_format.FORMAT_DIR = Path(root) / "formats"
        web_format.FORMAT_DIR.mkdir(parents=True, exist_ok=True)
        web_format.save_format("main", template, ["nginx_access"])

    def test_template_variables_become_queryable_columns(self):
        """模板里多写的变量要落成真实列：能查、能筛、能统计，而不是塞进一个 JSON 字段。"""
        self._bind_template(self.tmp.name, 'log_format main \'$remote_addr [$time_local] "$request" $status '
                                         '$request_time $upstream_addr $upstream_status\';')
        lines = "\n".join(
            '10.0.0.%d [04/Nov/2026:09:%02d:00 +0800] "GET /a%d HTTP/1.1" 200 0.0%d "172.16.0.1:8080" 200' % (i, i, i, i % 10)
            for i in range(1, 26)
        )
        result = self.importer.import_text(self.task_id, "nginx_access", "combined", lines)
        self.assertEqual(result["rows"], 25)

        view = self.queries.query(self.task_id, "nginx_access", {"size": 5})
        names = [c["name"] for c in view["schema"]]
        for column in ("request_time", "upstream_addr", "upstream_status"):
            self.assertIn(column, names, "模板变量必须变成表里的列")
        self.assertNotIn("source_id", names, "内部列不该出现在表格 schema 里")

        first = view["rows"][0]
        self.assertEqual(first["upstream_addr"], "172.16.0.1:8080")
        self.assertAlmostEqual(float(first["request_time"]), 0.01, places=3)

        ranked = self.queries.stats(self.task_id, "nginx_access", dimension="upstream_status")["ranking"]
        self.assertEqual(ranked[0]["k"], "200")
        self.assertEqual(ranked[0]["cnt"], 25)

        by_account = self.queries.stats(self.task_id, "nginx_access", dimension="request_time")["ranking"]
        self.assertEqual(len(by_account), 10, "请求耗时 0.00–0.09 共 10 个不同取值")

    def test_switching_template_keeps_previous_columns(self):
        """换模板不能把上一版建出来的列弄丢，旧数据还在用它们。"""
        from services import web_format

        self._bind_template(self.tmp.name, 'log_format main \'$remote_addr "$request" $status $http_cookie\';')
        self.importer.import_text(self.task_id, "nginx_access", "combined",
                                  '1.2.3.4 "GET /a HTTP/1.1" 200 "sid=abc"\n')

        web_format.FORMAT_DIR = Path(self.tmp.name) / "formats"
        web_format.save_format("main", 'log_format main \'$remote_addr "$request" $status\';', ["nginx_access"])
        self.importer.import_text(self.task_id, "nginx_access", "combined",
                                  '5.6.7.8 "GET /b HTTP/1.1" 200\n')

        names = [c["name"] for c in self.queries.query(self.task_id, "nginx_access", {"size": 5})["schema"]]
        self.assertIn("http_cookie", names, "旧列必须保留")
        rows = self.queries.query(self.task_id, "nginx_access", {"size": 10})["rows"]
        old = [r for r in rows if r["ip"] == "1.2.3.4"][0]
        new = [r for r in rows if r["ip"] == "5.6.7.8"][0]
        self.assertEqual(old["http_cookie"], "sid=abc")
        self.assertIsNone(new["http_cookie"], "新模板没有这个变量，值为 NULL 而不是空串")

    def test_plain_source_schema_has_no_template_columns(self):
        """没有模板就只用内置列，不能凭空多出字段。"""
        self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        names = [c["name"] for c in self.queries.query(self.task_id, "nginx_access", {"size": 5})["schema"]]
        self.assertEqual(sorted(names), sorted(["ts", "ip", "method", "path", "status", "bytes", "ua", "ref", "xff", "host"]))

    def test_soft_delete_keeps_data_and_can_restore(self):
        """「仅移出列表」必须保留数据文件，且能从归档恢复，否则就是看不见的僵尸数据。"""
        self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        self.store.delete_task(self.task_id)
        with self.assertRaises(KeyError):
            self.store.get_task(self.task_id)
        self.assertEqual([t["id"] for t in self.store.list_deleted_tasks()], [self.task_id])
        self.assertTrue(self.store.task_path(self.task_id).exists())

        self.store.restore_task(self.task_id)
        self.assertEqual(self.store.get_task(self.task_id)["stats"]["total"], 3)
        self.assertEqual(self.store.list_deleted_tasks(), [])

        self.store.task_path(self.task_id).unlink()
        self.store.delete_task(self.task_id)
        with self.assertRaises(KeyError):
            self.store.restore_task(self.task_id)

    def test_delete_import_rolls_back_one_batch(self):
        """导错源/导错格式只能整批回滚：删的必须正好是这批行，其它批次不受影响。"""
        first = self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        second = self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        self.assertEqual(self.queries.task_view(self.task_id)["stats"]["total"], 6)

        result = self.store.delete_import(self.task_id, second["id"])
        self.assertEqual(result["deleted_rows"], 3)
        view = self.queries.task_view(self.task_id)
        self.assertEqual(view["stats"]["total"], 3)
        self.assertEqual(len(view["imports"]), 1)
        self.assertEqual(view["imports"][0]["id"], first["id"])
        self.assertEqual(view["stats"]["source_counts"]["nginx_access"], 3)

        deleted = self.store.delete_import(self.task_id, first["id"])
        self.assertTrue(deleted["dropped_tables"], "最后一个批次删完后表应被 DROP，否则磁盘占用不下降")
        self.assertEqual(self.queries.task_view(self.task_id)["stats"]["total"], 0)
        self.assertEqual(self.queries.query(self.task_id, "nginx_access", {"size": 10})["total"], 0)

        again = self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        self.assertEqual(again["rows"], 3, "表被 DROP 后重新导入要能自动重建")
        self.assertEqual(self.queries.task_view(self.task_id)["stats"]["total"], 3)

    def test_delete_import_rejects_unknown_id(self):
        self.importer.import_text(self.task_id, "nginx_access", "combined", WEB)
        with self.assertRaises(KeyError):
            self.store.delete_import(self.task_id, "i_doesnotexist")
        with self.assertRaises(ValueError):
            self.store.delete_import(self.task_id, "../../meta")

    def test_other_parsers(self):
        w3c = LogParser("w3c")
        w3c.parse_line("#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)", 1)
        row = w3c.parse_line("2026-11-04 01:00:00 10.0.0.1 GET /a.php - 200 42 curl/8", 2)[0]
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["path"], "/a.php")

        audit = LogParser("audit").parse_line('type=EXECVE msg=audit(1762254000.123:9): argc=2 a0="curl" a1="http://example.test/a" comm="curl" exe="/usr/bin/curl" key="download"', 1)[0]
        self.assertEqual(audit["comm"], "curl")
        self.assertEqual(audit["key"], "download")

        shell = LogParser("shell")
        shell.parse_line("#1762254000", 1)
        self.assertEqual(shell.parse_line("cat /etc/shadow", 2)[0]["cmd"], "cat /etc/shadow")

        windows = LogParser("windows_event").parse_line('{"EventID":4625,"Computer":"WIN01","IpAddress":"10.0.0.2","TimeCreated":"2026-11-04T01:00:00Z"}', 1)[0]
        self.assertEqual(windows["eventId"], 4625)
        self.assertEqual(windows["host"], "WIN01")

        csv_parser = LogParser("windows_event")
        csv_parser.parse_line("EventID,Computer,IpAddress", 1)
        self.assertEqual(csv_parser.parse_line("4624,WIN02,10.0.0.3", 2)[0]["eventId"], 4624)

    def test_custom_rule_override_and_test(self):
        rule = {
            "id": "custom_test",
            "name": "测试路径",
            "severity": "high",
            "kind": "row",
            "scope": "web",
            "match": {"path": {"iregex": "shell\\.php"}},
            "explain": "测试",
            "false_positive": "测试误报",
            "enabled": True,
        }
        self.rules.save(rule)
        self.assertTrue(any(x["id"] == "custom_test" for x in self.rules.load()))
        self.assertTrue(matches(rule, {"path": "/upload/SHELL.PHP"}))
        tested = self.engine.test({"path": "/shell.php", "raw": "/shell.php"}, "web")
        self.assertTrue(any(x["id"] == "custom_test" and x["hit"] for x in tested))
        self.rules.delete("custom_test")
        self.assertFalse(any(x["id"] == "custom_test" for x in self.rules.load()))

    def test_distro_sources_stay_separate(self):
        task = self.store.create_task({"name": "双发行版", "components": ["centos", "ubuntu"], "source_ids": ["centos_auth", "ubuntu_auth"]})
        line = "Nov  4 09:00:00 host sshd[21]: Failed password for root from 10.0.0.9 port 4000 ssh2\n"
        self.importer.import_text(task["id"], "centos_auth", "syslog", line)
        self.importer.import_text(task["id"], "ubuntu_auth", "syslog", line)
        view = self.queries.task_view(task["id"])
        self.assertEqual(view["stats"]["source_counts"], {"centos_auth": 1, "ubuntu_auth": 1})
        self.assertEqual(self.queries.kind(self.queries.source("centos_auth")), "auth")
        self.assertEqual(self.queries.kind(self.queries.source("ubuntu_auth")), "auth")
        self.assertNotEqual(self.queries.source("centos_auth")["paths"][0], self.queries.source("ubuntu_auth")["paths"][0])
        self.assertEqual(self.queries.kind(self.queries.source("centos_audit")), "audit")
        self.assertEqual(self.queries.kind(self.queries.source("ubuntu_audit")), "audit")

    def test_firewall_import_stats_and_rule(self):
        task = self.store.create_task({"name": "防火墙", "components": ["firewall"], "source_ids": ["firewall_traffic"]})
        line = 'Nov  4 09:03:00 FW-EDGE-01 firewall: vendor=Huawei action=permit proto=tcp src=203.0.113.8 spt=52344 dst=10.0.0.8 dpt=3389 rule="Ops-Temp"\n'
        result = self.importer.import_text(task["id"], "firewall_traffic", "firewall", line)
        self.assertEqual(result["rows"], 1)
        query = self.queries.query(task["id"], "firewall_traffic", {})
        row = query["rows"][0]
        self.assertEqual(row["action"], "accept")
        self.assertEqual(row["dstport"], 3389)
        self.assertEqual(row["rule"], "Ops-Temp")
        stats = self.queries.stats(task["id"], "firewall_traffic", "action")
        self.assertEqual(stats["ranking"][0]["k"], "accept")
        alerts = self.engine.alerts(task["id"], "firewall_traffic")
        self.assertTrue(any(x["rule"]["id"] == "fw_management_allowed" and x["count"] == 1 for x in alerts["rules"]))

    def test_catalog_and_template_references(self):
        source_ids = set(self.queries.sources)
        for component in self.queries.components.values():
            for sid in component["sources"]:
                self.assertIn(sid, source_ids, component["id"] + " 引用了不存在的日志源")
        self.assertIn("centos", self.queries.components)
        self.assertIn("ubuntu", self.queries.components)
        self.assertIn("firewall", self.queries.components)
        for template in self.queries.templates.values():
            for cid in template["components"]:
                self.assertIn(cid, self.queries.components, template["id"] + " 引用了不存在的组件")
        for filename in ("web-single.json", "web-split.json", "oracle-system.json", "k8s.json", "mixed.json", "linux-host.json", "ubuntu-host.json"):
            json.loads((ROOT / "templates" / filename).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
