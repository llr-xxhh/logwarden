from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from storage import Store
from services import evtx_reader
from services import sql_rules
from services.importer import Importer
from services.parsing import LogParser, parser_config
from services.query import QueryService
from services.rule_engine import RuleStore, aggregate_fail_then_success, matches, regex_prefixes, validate_rule


class RegressionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.queries = QueryService(self.store)
        self.importer = Importer(self.store, self.queries)
        self.task = self.store.create_task({"name": "回归", "components": ["nginx"], "source_ids": ["nginx_access"]})
        self.task_id = self.task["id"]

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_format_and_task_source_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "格式与日志源不匹配"):
            self.importer.import_text(self.task_id, "nginx_access", "text", "2026-01-01 INFO hello\n")
        with self.assertRaisesRegex(ValueError, "未加入当前任务"):
            self.importer.import_text(self.task_id, "ubuntu_auth", "syslog", "Nov 4 01:00:00 host sshd: test\n")
        with self.assertRaisesRegex(ValueError, "未加入当前任务"):
            self.queries.query(self.task_id, "ubuntu_auth", {})

    def test_every_catalog_format_has_parser(self):
        for source in self.queries.sources.values():
            config = parser_config(source.get("format", "text"))
            self.assertTrue(config["table"].startswith("raw_"), source["id"])
            self.assertTrue(config["fields"], source["id"])

    def test_json_docker_and_k8s(self):
        docker = LogParser("json", "docker_json").parse_line('{"log":"GET / HTTP/1.1\\n","stream":"stdout","time":"2026-11-04T01:00:00Z"}', 1)[0]
        self.assertEqual(docker["proc"], "stdout")
        self.assertIn("GET /", docker["msg"])
        audit = LogParser("json", "k8s_audit").parse_line('{"verb":"create","objectRef":{"resource":"pods"},"stageTimestamp":"2026-11-04T01:00:00Z"}', 1)[0]
        self.assertEqual(audit["proc"], "create")
        self.assertIsNotNone(audit["ts"])

    def test_windows_streaming_eof_and_level(self):
        truncated = LogParser("windows_event")
        truncated.parse_line("<Event><System><EventID>4624</EventID>", 1)
        with self.assertRaises(Exception):
            truncated.finalize()
        csv_parser = LogParser("windows_event")
        csv_parser.parse_line("EventID,Computer,Message", 1)
        self.assertEqual(csv_parser.parse_line('4624,WIN01,"first line\n', 2), [])
        row = csv_parser.parse_line('second line"', 3)[0]
        self.assertEqual(row["eventId"], 4624)
        self.assertEqual(row["msg"], "first line\nsecond line")
        self.assertEqual(LogParser("windows_event").parse_line('{"EventID":1,"Level":"2"}', 1)[0]["level"], "错误")
        self.assertEqual(LogParser("windows_event").parse_line('{"EventID":1,"Level":"4"}', 1)[0]["level"], "信息")

    def test_windows_xml_stream_multiple_events(self):
        """wevtutil / Get-WinEvent ToXml 的输出是多个 <Event> 根元素平铺，必须能整流解析。"""
        parser = LogParser("windows_event")
        stream = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>4624</EventID><Computer>WIN01</Computer>"
            "<TimeCreated SystemTime='2026-11-04T01:00:00.000Z'/></System>"
            "<EventData><Data Name='IpAddress'>10.0.0.2</Data></EventData></Event>\n"
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>4625</EventID><Computer>WIN01</Computer>"
            "<TimeCreated SystemTime='2026-11-04T01:05:00.000Z'/></System></Event>"
        )
        rows = []
        for i, line in enumerate(stream.splitlines(), 1):
            rows.extend(parser.parse_line(line, i))
        rows.extend(parser.finalize())
        self.assertEqual([r["eventId"] for r in rows], [4624, 4625])
        self.assertEqual(rows[0]["srcip"], "10.0.0.2")
        self.assertIsNotNone(rows[0]["ts"])

    def test_w3c_rejects_missing_columns(self):
        parser = LogParser("w3c")
        parser.parse_line("#Fields: date time c-ip sc-status", 1)
        with self.assertRaisesRegex(ValueError, "列数"):
            parser.parse_line("2026-11-04 01:00:00 10.0.0.1", 2)

    def test_rsyslog_mark_is_skipped_not_failed(self):
        """rsyslog 每 20 分钟一条 -- MARK -- 心跳，不含事件，不能算解析失败。

        真机（Ubuntu 24.04 的 syslog）一天攒 72 条假错误，把真正的坏行淹掉。
        """
        parser = LogParser("syslog")
        self.assertEqual(parser.parse_line("Aug 20 19:00:50 ai -- MARK --", 1), [])
        self.assertEqual(parser.parse_line("2026-08-20T19:00:50+08:00 ai -- MARK --", 2), [])
        # 带 PRI 前缀的中继日志同样要认
        self.assertEqual(parser.parse_line("<13>Aug 20 19:00:50 ai -- MARK --", 3), [])
        # 但同一行位置上真有内容的不能误伤
        self.assertTrue(parser.parse_line("Aug 20 19:00:50 ai CRON[1]: (root) CMD (ls)", 4))

    def test_syslog_repeat_collapse_keeps_line(self):
        """rsyslog 的 "last message repeated N times" 没有 proc: 段，但本身是有效信息。"""
        parser = LogParser("syslog")
        row = parser.parse_line("Oct 12 12:06:07 ai last message repeated 2 times", 1)[0]
        self.assertEqual(row["host"], "ai")
        self.assertEqual(row["proc"], "-")
        self.assertIn("repeated 2 times", row["msg"])
        self.assertIsNotNone(row["ts"])

    def test_syslog_proc_allows_parenthesized_version(self):
        """Debian 的 syslogd 会写成 "syslogd (GNU inetutils 2.5): restart"。"""
        parser = LogParser("syslog")
        row = parser.parse_line("Aug 20 18:26:04 ai syslogd (GNU inetutils 2.5): restart", 1)[0]
        self.assertEqual(row["proc"], "syslogd (GNU inetutils 2.5)")
        self.assertEqual(row["msg"], "restart")
        self.assertEqual(row["host"], "ai")
        # 普通 proc 仍然只到冒号为止，不会把消息里的空格吃进来
        row = parser.parse_line("Aug 20 18:27:02 ai CRON[2101]: (root) CMD (cmd)", 2)[0]
        self.assertEqual(row["proc"], "CRON")
        self.assertEqual(row["pid"], 2101)

    def test_cursor_respects_sort_and_never_repeats(self):
        lines = []
        for i in range(7):
            lines.append('10.0.0.%d - - [04/Nov/2026:09:00:0%d +0800] "GET /%s HTTP/1.1" 200 %d "-" "UA"' % (i, i, "ab"[i % 2], 100 + i))
        self.importer.import_text(self.task_id, "nginx_access", "combined", "\n".join(lines))
        for key, direction in (("id", -1), ("bytes", 1), ("bytes", -1), ("path", 1)):
            cursor = None
            seen = []
            while True:
                options = {"size": 3, "sort": {"k": key, "dir": direction}}
                if cursor is not None:
                    options["cursor"] = cursor
                page = self.queries.query(self.task_id, "nginx_access", options)
                self.assertEqual(page["total"], 7)
                seen.extend(row["id"] for row in page["rows"])
                cursor = page["next_cursor"]
                if cursor is None:
                    break
            self.assertEqual(len(seen), 7, (key, direction, seen))
            self.assertEqual(len(set(seen)), 7, (key, direction, seen))

    def test_literal_path_and_like_wildcards(self):
        line = '10.0.0.1 - - [04/Nov/2026:09:00:00 +0800] "GET /upload/shell.php?x=100%25 HTTP/1.1" 200 10 "-" "UA"'
        self.importer.import_text(self.task_id, "nginx_access", "combined", line)
        self.assertEqual(self.queries.query(self.task_id, "nginx_access", {"q": "/upload/shell.php"})["total"], 1)
        self.assertEqual(self.queries.query(self.task_id, "nginx_access", {"q": "/upload/other"})["total"], 0)
        self.assertEqual(self.queries.query(self.task_id, "nginx_access", {"colf": {"path": {"q": "%"}}})["total"], 1)
        self.assertEqual(self.queries.query(self.task_id, "nginx_access", {"colf": {"path": {"q": "_"}}})["total"], 0)

    def test_rule_validation_and_delete_id(self):
        base = {"name": "bad", "severity": "high", "kind": "row", "scope": "web", "false_positive": "test"}
        for match in ({}, {"path": {"regexp": "shell"}}, {"path": {}}):
            with self.assertRaises(ValueError):
                validate_rule(dict(base, match=match))
        with self.assertRaises(ValueError):
            validate_rule(dict(base, match={"path": {"contains": "x"}}, scope="all"))
        rules = RuleStore(Path(self.tmp.name) / "custom")
        with self.assertRaisesRegex(ValueError, "非法规则 ID"):
            rules.delete("..\\..\\parsers\\combined")

    def test_failed_second_batch_keeps_committed_statistics_consistent(self):
        lines = []
        for i in range(1001):
            lines.append('10.0.0.1 - - [04/Nov/2026:09:00:00 +0800] "GET /%d HTTP/1.1" 200 10 "-" "UA"' % i)
        original = self.store.insert_batch
        calls = {"n": 0}
        def fail_second(*args):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("injected batch failure")
            return original(*args)
        self.store.insert_batch = fail_second
        with self.assertRaisesRegex(OSError, "injected"):
            self.importer.import_text(self.task_id, "nginx_access", "combined", "\n".join(lines))
        self.assertEqual(self.store.task_stats(self.task_id)["total"], 1000)
        self.assertEqual(self.queries.query(self.task_id, "nginx_access", {})["total"], 1000)
        record = self.store.list_imports(self.task_id)[0]
        self.assertEqual(record["rows"], 1000)
        self.assertEqual(record["status"], "failed")
        self.assertGreaterEqual(record["failed"], 1)

    def test_success_consumes_failure_sequence(self):
        rule = {"match": {"agg": {"type": "fail_then_success", "group_by": "srcip", "window_sec": 300, "min_failures": 2, "fail": {"result": {"eq": "失败"}}, "success": {"result": {"eq": "成功"}}}}}
        rows = [
            {"ts": 1000, "srcip": "1.1.1.1", "result": "失败"},
            {"ts": 2000, "srcip": "1.1.1.1", "result": "失败"},
            {"ts": 3000, "srcip": "1.1.1.1", "result": "成功"},
            {"ts": 4000, "srcip": "1.1.1.1", "result": "成功"},
        ]
        self.assertEqual(len(aggregate_fail_then_success(rows, rule)), 1)


class RuleMatchTest(unittest.TestCase):
    """规则预筛：只允许「必然不匹配」时跳过，不能改变任何命中结果。"""

    def test_regex_prefix_extraction_is_conservative(self):
        self.assertEqual(regex_prefixes("(useradd|adduser)", True), ["useradd", "adduser"])
        # 前瞻、. * 、单字符前缀都提不出可靠字面量，必须放弃预筛
        self.assertIsNone(regex_prefixes("(?=config)(?=authorized)", True))
        self.assertIsNone(regex_prefixes(".*foo", True))
        self.assertIsNone(regex_prefixes("(a|b)", True))
        self.assertIsNone(regex_prefixes("(foo|bar)baz", True))

    def test_prefilter_keeps_matches(self):
        rule = {"match": {"raw": {"iregex": "(useradd|adduser)"}}}
        self.assertTrue(matches(rule, {"raw": "x useradd bob"}))
        self.assertTrue(matches(rule, {"raw": "USERADD bob"}))  # iregex 大小写不敏感
        self.assertFalse(matches(rule, {"raw": "nothing here"}))
        self.assertFalse(matches(rule, {"raw": ""}))

    def test_prefilter_respects_not_regex(self):
        rule = {"match": {"raw": {"not_regex": "(useradd|adduser)"}}}
        self.assertTrue(matches(rule, {"raw": "normal log line"}))
        self.assertFalse(matches(rule, {"raw": "useradd bob"}))

    def test_text_scope_rules_skip_windows_sources(self):
        self.assertFalse(RuleStore.applies({"scope": "text"}, "win"))
        self.assertTrue(RuleStore.applies({"scope": ["win", "ps"]}, "win"))


class EvtxTest(unittest.TestCase):
    """EVTX 直读：只测结构转换，不依赖具体机器上的日志文件。"""

    def test_nested_event_json_is_unwrapped(self):
        line = json.dumps({"Event": {"System": {"EventID": 4624, "Computer": "PC-1", "TimeCreated": "2026-11-06T01:02:03.000Z", "Level": 0}, "EventData": {"Data": [{"#attributes": {"Name": "TargetUserName"}, "#text": "alice"}]}}})
        record = LogParser("windows_event").parse_line(line, 1)[0]
        self.assertEqual(record["eventId"], 4624)
        self.assertEqual(record["host"], "PC-1")
        self.assertEqual(record["user"], "alice")
        self.assertEqual(record["event"], "登录成功")

    def test_evtx_record_flattens_system_and_eventdata(self):
        event = {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": 4625,
                "Level": 0,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-06T01:02:03.500Z"}},
                "Computer": "PC-1",
                "Channel": "Security",
            },
            "EventData": {"Data": [
                {"#attributes": {"Name": "TargetUserName"}, "#text": "bob"},
                {"#attributes": {"Name": "IpAddress"}, "#text": "10.0.0.9"},
                {"#attributes": {"Name": "LogonType"}, "#text": "3"},
                {"#attributes": {"Name": "Status"}, "#text": "0xc000006d"},
            ]},
        }
        record = evtx_reader.to_record(event)
        self.assertEqual(record["eventId"], 4625)
        self.assertEqual(record["level"], "信息")  # Level 0 在 Windows 语义里是 LogAlways，落到默认值
        self.assertEqual(record["host"], "PC-1")
        self.assertEqual(record["user"], "bob")
        self.assertEqual(record["srcip"], "10.0.0.9")
        self.assertEqual(record["logonType"], "3")
        self.assertEqual(record["event"], "登录失败")
        self.assertIsNotNone(record["ts"])

    def test_evtx_magic_detection(self):
        self.assertTrue(evtx_reader.is_evtx_file("Security.evtx"))
        self.assertTrue(evtx_reader.is_evtx_file("renamed.bin", b"ElfFile\x00rest"))
        self.assertFalse(evtx_reader.is_evtx_file("Security.xml", b"<?xml ver"))
        self.assertFalse(evtx_reader.is_evtx_file("nginx.log", b"1.2.3.4 - -"))

    def test_eventid_with_qualifiers_and_channel_aware_names(self):
        # System.evtx 里 EventID 常带 Qualifiers，JSON 里是对象而不是纯值
        event = {
            "System": {
                "EventID": {"#attributes": {"Qualifiers": "16384"}, "#text": "1074"},
                "Channel": "System",
                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-06T01:02:03.000Z"}},
            }
        }
        record = evtx_reader.to_record(event)
        self.assertEqual(record["eventId"], 1074)
        self.assertEqual(record["event"], "关机/重启")
        # 22 只在 Sysmon 通道是 DNS 查询，RDP 通道必须退回泛称
        rdp = {"System": {"EventID": 22, "Channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"}}
        self.assertEqual(evtx_reader.to_record(rdp)["event"], "Windows 事件")
        sysmon = {"System": {"EventID": 22, "Channel": "Microsoft-Windows-Sysmon/Operational"}}
        self.assertEqual(evtx_reader.to_record(sysmon)["event"], "DNS 查询")


try:
    import duckdb
except ImportError:  # 没装 duckdb 时整组跳过（SQLite 版没有这个依赖）
    duckdb = None


@unittest.skipIf(duckdb is None, "需要 duckdb")
class SqlRulesTest(unittest.TestCase):
    """规则下推：翻译出的 SQL 必须与 Python matches() 逐行判断给出相同计数。

    这是下推功能唯一的正确性保障——语义一旦偏了，告警会静默漏报/误报。
    """

    ROWS = [
        {"id": 1, "eventId": 4624, "msg": "登录成功 admin", "raw": '{"a":1}', "srcip": "10.0.0.1", "user": "admin"},
        {"id": 2, "eventId": 4625, "msg": "登录失败 admin", "raw": '{"b":2}', "srcip": "8.8.8.8", "user": "admin"},
        {"id": 3, "eventId": 4625, "msg": "登录失败 guest", "raw": '{"c":3}', "srcip": "8.8.8.8", "user": "guest"},
        {"id": 4, "eventId": 7045, "msg": "安装服务 C:\\temp\\evil.exe", "raw": '{"d":4}', "srcip": "-", "user": "SYSTEM"},
        {"id": 5, "eventId": 7045, "msg": "安装服务 C:\\Windows\\svc.exe", "raw": '{"e":5}', "srcip": "-", "user": "SYSTEM"},
        {"id": 6, "eventId": 1, "msg": "powershell -enc abc", "raw": '{"f":6}', "srcip": "-", "user": "admin"},
    ]

    @classmethod
    def setUpClass(cls):
        cls.con = duckdb.connect()
        cls.con.execute(
            "CREATE TABLE t (task_id VARCHAR, source_id VARCHAR, id BIGINT, "
            "eventId BIGINT, msg VARCHAR, raw VARCHAR, srcip VARCHAR, \"user\" VARCHAR)")
        cls.con.executemany(
            "INSERT INTO t VALUES ('t1','s1',?,?,?,?,?,?)",
            [(r["id"], r["eventId"], r["msg"], r["raw"], r["srcip"], r["user"]) for r in cls.ROWS])

    @classmethod
    def tearDownClass(cls):
        cls.con.close()

    def _sql_count(self, rule):
        sql, params = sql_rules.counts_sql("t", [rule], "t1", "s1")
        value = self.con.execute(sql, params).fetchone()[0]
        return int(value or 0)

    def _py_count(self, rule):
        return sum(1 for row in self.ROWS if matches(rule, row))

    def _rule(self, match):
        return {"id": "r", "name": "r", "severity": "high", "kind": "row", "match": match}

    def test_scalar_and_list_conditions(self):
        cases = [
            {"eventId": {"eq": 4625}},
            {"eventId": {"in": [4624, 4625]}},
            {"eventId": {"ne": 4625}},
            {"eventId": {"gte": 4625}},
            {"msg": {"contains": "登录"}},
            {"msg": {"icontains": "EVIL"}},
            {"msg": {"starts_with": "登录"}},
            {"srcip": {"in": ["8.8.8.8", "-"]}},
        ]
        for match in cases:
            rule = self._rule(match)
            self.assertEqual(self._sql_count(rule), self._py_count(rule), match)

    def test_regex_conditions(self):
        cases = [
            {"eventId": {"eq": 7045}, "msg": {"iregex": r"\.exe"}},
            {"msg": {"iregex": "POWERSHELL"}},
            {"msg": {"regex": "powershell"}},
            {"msg": {"not_regex": r"^登录"}},
            {"eventId": {"eq": 4625}, "msg": {"iregex": "失败\\s+\\w+"}},
        ]
        for match in cases:
            rule = self._rule(match)
            self.assertEqual(self._sql_count(rule), self._py_count(rule), match)

    def test_logical_groups(self):
        cases = [
            {"any": [{"msg": {"contains": "evil"}}, {"msg": {"contains": "guest"}}]},
            {"eventId": {"eq": 4625}, "not": {"user": {"eq": "admin"}}},
            {"any": [{"eventId": {"in": [4624, 1]}}, {"msg": {"icontains": "SVC"}}]},
        ]
        for match in cases:
            rule = self._rule(match)
            self.assertEqual(self._sql_count(rule), self._py_count(rule), match)

    def test_multiple_rules_single_query(self):
        """一条 SQL 里的多个 FILTER 各自独立，不能串味。"""
        rules = [
            self._rule({"eventId": {"eq": 4625}}),
            self._rule({"eventId": {"eq": 7045}}),
            self._rule({"eventId": {"eq": 1}}),
        ]
        sql, params = sql_rules.counts_sql("t", rules, "t1", "s1")
        row = self.con.execute(sql, params).fetchone()
        self.assertEqual([int(x or 0) for x in row], [2, 2, 1])

    def test_unsupported_patterns_fall_back(self):
        """RE2 不支持 lookaround / 反向引用，必须抛 Unsupported 交给 Python 兜底。"""
        for pattern in ["(?=[\\s\\S]*config)(?=[\\s\\S]*ssh)", "(a)\\1", "x(?!y)"]:
            with self.assertRaises(sql_rules.Unsupported, msg=pattern):
                sql_rules.translate(self._rule({"msg": {"iregex": pattern}}))
        with self.assertRaises(sql_rules.Unsupported):
            sql_rules.translate({"match": {"msg": {"unknown_op": "x"}}})
        # matches() 不认 all，翻译层必须同样拒绝，否则 SQL 能跑、Python 跑不了
        with self.assertRaises(sql_rules.Unsupported):
            sql_rules.translate({"match": {"all": [{"eventId": {"eq": 4625}}]}})

    def test_hits_sql_respects_limit(self):
        rule = self._rule({"eventId": {"eq": 4625}})
        sql, params = sql_rules.hits_sql("t", rule, "t1", "s1", limit=1)
        rows = self.con.execute(sql, params).fetchall()
        self.assertEqual(len(rows), 1)

    def test_needs_raw(self):
        self.assertTrue(sql_rules.needs_raw(self._rule({"raw": {"iregex": "x"}})))
        self.assertTrue(sql_rules.needs_raw(self._rule({"any": [{"raw": {"contains": "x"}}]})))
        self.assertFalse(sql_rules.needs_raw(self._rule({"msg": {"iregex": "x"}})))

    def test_engine_gate(self):
        class Fake:
            pass

        self.assertFalse(sql_rules.available(Fake()))
        self.assertTrue(sql_rules.available(type("S", (), {"ENGINE": "duckdb"})()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
