from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.parsing import LogParser
from services.web_format import compile_format, normalize_format, parse_line, preview, preview_spec

# 真实环境实际使用的 log_format：配置里跨行用相邻单引号拼接
MAIN_FORMAT = """log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
'$status $body_bytes_sent "$http_referer" '
'"$http_user_agent" "$http_x_forwarded_for"'
'"$scheme://$host"';"""

MAIN_LINE = (
    '1.2.3.4 - - [04/Nov/2026:09:00:00 +0800] "GET /a HTTP/1.1" 200 123 "-" "curl/8" '
    '"-""https://shop.example.com"'
)


class FormatCompileTest(unittest.TestCase):
    def test_multiline_config_is_joined(self):
        template = normalize_format(MAIN_FORMAT)
        self.assertTrue(template.startswith("$remote_addr - $remote_user [$time_local]"))
        self.assertIn('"$http_user_agent" "$http_x_forwarded_for"', template)
        self.assertTrue(template.endswith('"$scheme://$host"'))
        self.assertNotIn("log_format", template)

    def test_main_format_extracts_xff_and_host(self):
        """XFF 和 vhost 在 UA 之后，内置 combined 正则会漏掉，模板必须取到。"""
        rows = preview(MAIN_FORMAT, [MAIN_LINE])["rows"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["xff"], "-")
        self.assertEqual(row["host"], "shop.example.com")
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["bytes"], 123)
        self.assertEqual(row["path"], "/a")
        self.assertEqual(row["ua"], "curl/8")

    def test_xff_with_real_client(self):
        line = MAIN_LINE.replace('"-""https://', '"203.0.113.9""https://')
        row = preview(MAIN_FORMAT, [line])["rows"][0]
        self.assertEqual(row["xff"], "203.0.113.9")

    def test_fewer_fields_are_fine(self):
        """模板只写三个字段时，其余字段不出现，交给下游按空值处理。"""
        row = preview('$remote_addr "$request" $status', ['1.2.3.4 "GET /a HTTP/1.1" 200'])["rows"][0]
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["status"], 200)
        for missing in ("ua", "ref", "bytes", "xff", "host"):
            self.assertNotIn(missing, row, "模板没有的字段不该凭空出现")

    def test_order_does_not_matter(self):
        row = preview('$status $body_bytes_sent "$request" $remote_addr', ['200 55 "GET /a HTTP/1.1" 1.2.3.4'])["rows"][0]
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["bytes"], 55)
        self.assertEqual(row["path"], "/a")
        self.assertEqual(row["ip"], "1.2.3.4")

    def test_extra_variables_become_columns(self):
        """$scheme 没有语义槽位，但它是真实字段：建列而不是塞进 ext，才能统计和筛选。"""
        compiled = compile_format("$remote_addr $scheme $request_time")
        self.assertEqual(compiled["columns"]["scheme"], "TEXT")
        self.assertEqual(compiled["columns"]["request_time"], "REAL")
        row = preview("$remote_addr $scheme $request_time", ["1.2.3.4 https 0.023"])["rows"][0]
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["scheme"], "https")
        self.assertEqual(row["request_time"], "0.023")
        self.assertNotIn("ext", row)

    def test_rejects_empty_or_unknown(self):
        with self.assertRaises(ValueError):
            compile_format("")
        with self.assertRaises(ValueError):
            compile_format("plain text without variables")

    def test_parser_uses_bound_format(self):
        """源上挂了模板，LogParser 就该走模板，不走内置 combined。"""
        from services import web_format

        parser = LogParser("combined")
        self.assertIsNone(parser.web_format)
        fmt = compile_format("$remote_addr [$time_local] \"$request\" $status")
        self.assertEqual([f for _, f in fmt["groups"]], ["ip", "ts", "request", "status"])
        self.assertIsNotNone(web_format.normalize_format(MAIN_FORMAT))


class ColumnDeriveTest(unittest.TestCase):
    """模板变量 → 数据库列。列名和类型决定这张表能不能统计、能不能筛选。"""

    def test_known_variables_keep_semantic_slots(self):
        columns = compile_format(MAIN_FORMAT)["columns"]
        self.assertEqual(columns["ip"], "TEXT")
        self.assertEqual(columns["status"], "INTEGER")
        self.assertEqual(columns["bytes"], "INTEGER")
        self.assertEqual(columns["ts"], "INTEGER")
        self.assertNotIn("request", columns, "$request 拆成 method + path，不单独建列")

    def test_alias_variables_share_one_column(self):
        """$uri 和 $request_uri 是同一个语义，不能建出两列。"""
        columns = compile_format("$uri $request_uri $remote_addr")["columns"]
        self.assertEqual([c for c in columns if c == "path"], ["path"])
        self.assertEqual(columns["path"], "TEXT")

    def test_unknown_variable_uses_its_own_name(self):
        columns = compile_format("$remote_addr $http_cookie $server_protocol")["columns"]
        self.assertIn("http_cookie", columns)
        self.assertIn("server_protocol", columns)
        self.assertEqual(columns["http_cookie"], "TEXT")

    def test_numeric_variables_get_numeric_type(self):
        compiled = compile_format("$remote_addr $request_time $request_length")
        self.assertEqual(compiled["columns"]["request_time"], "REAL")
        self.assertEqual(compiled["columns"]["request_length"], "INTEGER")
        row = parse_line(compiled, "1.2.3.4 0.023 512")
        self.assertEqual(row["request_time"], "0.023")

    def test_reserved_names_are_moved_aside(self):
        """变量名撞上内部列（raw/task_id）时不能直接占用，否则插入会被覆盖。"""
        columns = compile_format("$remote_addr $raw")["columns"]
        self.assertIn("x_raw", columns)
        self.assertNotIn("raw", columns)

    def test_missing_value_becomes_none(self):
        """日志里是 "-" 就存 NULL，不要存字面量，否则统计里会多出一个 "-" 分组。"""
        row = parse_line(compile_format("$remote_addr $http_cookie"), "1.2.3.4 -")
        self.assertIsNone(row["http_cookie"])


class FormatStoreTest(unittest.TestCase):
    """模板的增删改与绑定冲突。管理页要靠这些接口说清楚"谁被摘掉了"。"""

    def setUp(self):
        import tempfile
        from services import web_format

        self.tmp = tempfile.TemporaryDirectory()
        self.wf = web_format
        self._old = web_format.FORMAT_DIR
        web_format.FORMAT_DIR = Path(self.tmp.name) / "formats"

    def tearDown(self):
        self.wf.FORMAT_DIR = self._old
        self.tmp.cleanup()

    def test_edit_keeps_id_and_created_at(self):
        first = self.wf.save_format("main", "$remote_addr $status", ["nginx_access"])
        second = self.wf.save_format("main v2", "$remote_addr $status $request_time", ["nginx_access"], first["id"])
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(second["created_at"], first["created_at"])
        self.assertEqual(len(self.wf.list_formats()), 1, "编辑不该多出一个模板")

    def test_taking_over_source_reports_detached(self):
        """同一个源不能挂两份模板，被摘掉的一方必须报出来，否则是静默丢配置。"""
        self.wf.save_format("old", "$remote_addr $status", ["nginx_access"])
        result = self.wf.save_format("new", "$remote_addr $status", ["nginx_access"])
        self.assertEqual(result["detached"], [{"name": "old", "sources": ["nginx_access"]}])
        self.assertEqual([f["name"] for f in self.wf.list_formats()], ["new"])

    def test_shared_source_keeps_other_bindings(self):
        """一个模板挂多个源，被抢走一个时另一个要留下。"""
        self.wf.save_format("shared", "$remote_addr $status", ["nginx_access", "apache_access"])
        self.wf.save_format("new", "$remote_addr $status", ["nginx_access"])
        remain = {f["name"]: f["source_ids"] for f in self.wf.list_formats()}
        self.assertEqual(remain["shared"], ["apache_access"])
        self.assertEqual(remain["new"], ["nginx_access"])

    def test_edit_unknown_id_rejected(self):
        with self.assertRaises(KeyError):
            self.wf.save_format("x", "$remote_addr", ["nginx_access"], "fmt_not_exist")

    def test_delete_missing_rejected(self):
        with self.assertRaises(KeyError):
            self.wf.delete_format("fmt_nope")


class RegexTemplateTest(unittest.TestCase):
    """kind=regex：各家变量名不一样，靠正则和命名组兜底。"""

    APACHE = (
        r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
    )
    LINE = '192.168.1.5 - frank [04/Nov/2026:09:00:00 +0800] "GET /a.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0"'

    def test_parses_apache_with_time_format(self):
        out = preview_spec(
            {"kind": "regex", "pattern": self.APACHE, "time_format": "%d/%b/%Y:%H:%M:%S %z"},
            [self.LINE],
        )
        self.assertEqual(out["errors"], [])
        row = out["rows"][0]
        self.assertEqual(row["ip"], "192.168.1.5")
        self.assertEqual(row["user"], "frank")
        self.assertEqual(row["method"], "GET")
        self.assertEqual(row["path"], "/a.gif")
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["bytes"], 2326)
        self.assertIsInstance(row["ts"], int)

    def test_custom_field_becomes_column(self):
        """命名组不叫标准名也照样建列，能筛选能统计。"""
        out = preview_spec(
            {"kind": "regex", "pattern": r'^(?P<ip>\S+) (?P<cost_ms>\d+)', "types": {"cost_ms": "INTEGER"}},
            ["10.0.0.1 87"],
        )
        self.assertIn("cost_ms", out["fields"])
        self.assertEqual(out["rows"][0]["cost_ms"], "87")   # 非语义字段按文本落库

    def test_time_format_is_required_for_odd_formats(self):
        """不认的时间格式解析成 None，而不是抛错中断整批导入。"""
        out = preview_spec({"kind": "regex", "pattern": r'^(?P<ts>\S+) (?P<ip>\S+)'}, ["06/11/2026|10:00 1.2.3.4"])
        self.assertEqual(out["errors"], [])
        self.assertIsNone(out["rows"][0]["ts"])

    def test_rejects_reserved_column(self):
        with self.assertRaises(ValueError) as ctx:
            preview_spec({"kind": "regex", "pattern": r'^(?P<source_id>\S+) (?P<ip>\S+)'}, ["x 1.2.3.4"])
        self.assertIn("保留列", str(ctx.exception))

    def test_rejects_pattern_without_named_group(self):
        with self.assertRaises(ValueError) as ctx:
            preview_spec({"kind": "regex", "pattern": r"^(\S+) (\S+)"}, ["a b"])
        self.assertIn("命名捕获组", str(ctx.exception))

    def test_rejects_broken_pattern(self):
        with self.assertRaises(ValueError) as ctx:
            preview_spec({"kind": "regex", "pattern": r"^(?P<ip>\S+"}, ["1.2.3.4"])
        self.assertIn("正则写法", str(ctx.exception))


class DetectTest(unittest.TestCase):
    """粘一行日志就能认出是哪家，省得用户自己写正则。"""

    def test_detects_apache_combined(self):
        from services.web_format import detect_format

        r = detect_format('192.168.1.5 - frank [04/Nov/2026:09:00:00 +0800] "GET /a.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0"')
        self.assertEqual(r["kind"], "regex")
        self.assertIn("Apache", r["vendor"])
        self.assertIn("ip", r["fields"])
        self.assertEqual(r["sample"]["ip"], "192.168.1.5")

    def test_detects_vhost_prefix(self):
        from services.web_format import detect_format

        r = detect_format('shop.example.com 1.2.3.4 - - [04/Nov/2026:09:00:00 +0800] "GET /a HTTP/1.1" 200 1 "-" "c"')
        self.assertIn("vhost", r["vendor"])
        self.assertEqual(r["sample"]["host"], "shop.example.com")

    def test_json_says_use_json_parser(self):
        from services.web_format import detect_format

        r = detect_format('{"@timestamp":"2026-11-04T09:00:00Z","message":"ok"}')
        self.assertEqual(r["kind"], "none")
        self.assertIn("json", r["note"].lower())

    def test_iis_says_use_w3c_parser(self):
        from services.web_format import detect_format

        r = detect_format("#Fields: date time s-ip cs-method")
        self.assertEqual(r["kind"], "none")
        self.assertIn("w3c", r["note"].lower())

    def test_unknown_gives_guidance(self):
        from services.web_format import detect_format

        r = detect_format("Nov 04 09:00:00 web01 sshd[1]: Accepted password")
        self.assertEqual(r["kind"], "unknown")
        self.assertIn("正则", r["note"])


class SpecStoreTest(unittest.TestCase):
    """存 JSON 模板：kind 原样保留，重新读出来还能编译。"""

    def setUp(self):
        import tempfile
        from services import web_format

        self.wf = web_format
        self.tmp = tempfile.TemporaryDirectory()
        self.old = web_format.FORMAT_DIR
        web_format.FORMAT_DIR = Path(self.tmp.name)

    def tearDown(self):
        self.wf.FORMAT_DIR = self.old
        self.tmp.cleanup()

    def test_saves_regex_spec(self):
        item = self.wf.save_format({
            "name": "apache",
            "kind": "regex",
            "pattern": RegexTemplateTest.APACHE,
            "time_format": "%d/%b/%Y:%H:%M:%S %z",
            "types": {"cost_ms": "integer"},
            "note": "线上 apache",
            "source_ids": ["apache_access"],
        })
        self.assertEqual(item["kind"], "regex")
        stored = self.wf.list_formats()[0]
        self.assertEqual(stored["kind"], "regex")
        self.assertEqual(stored["note"], "线上 apache")
        self.assertEqual(stored["types"]["cost_ms"], "INTEGER")
        # 存进去的 JSON 要能重新编译
        self.assertEqual(self.wf.compile_item(stored)["kind"], "regex")

    def test_nginx_spec_still_works(self):
        item = self.wf.save_format({"name": "main", "kind": "nginx", "template": MAIN_FORMAT, "source_ids": ["nginx_access"]})
        self.assertEqual(item["kind"], "nginx")
        self.assertIn("$remote_addr", item["template"])

    def test_missing_name_or_sources_rejected(self):
        with self.assertRaises(ValueError):
            self.wf.save_format({"kind": "regex", "pattern": RegexTemplateTest.APACHE, "source_ids": ["a"]})
        with self.assertRaises(ValueError):
            self.wf.save_format({"name": "x", "kind": "regex", "pattern": RegexTemplateTest.APACHE, "source_ids": []})


    def test_dstip_and_port_are_semantic(self):
        """出站日志的目的 IP / 端口必须按标准字段走，端口要能按数值排。"""
        from services import web_format

        spec = {
            "kind": "regex",
            "pattern": r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<ip>\S+) -> (?P<dstip>\S+):(?P<dstport>\d+) (?P<status>\d{3})',
            "time_format": "%Y-%m-%d %H:%M:%S",
        }
        out = preview_spec(spec, ["2026-11-04 09:00:00 10.0.0.21 -> 93.184.216.34:443 200"])
        self.assertEqual(out["errors"], [])
        row = out["rows"][0]
        self.assertEqual(row["ip"], "10.0.0.21")
        self.assertEqual(row["dstip"], "93.184.216.34")
        self.assertEqual(row["dstport"], 443)          # 整数，不是 "443"
        self.assertNotIn("dstport", out["extra"], "端口是标准字段，不该算额外列")
        self.assertEqual(web_format.compile_spec(spec)["columns"]["dstport"], "INTEGER")

    def test_src_port_dash_becomes_null(self):
        spec = {"kind": "regex", "pattern": r'^(?P<ip>\S+) (?P<srcport>\d+|-)$'}
        out = preview_spec(spec, ["1.2.3.4 -"])
        self.assertIsNone(out["rows"][0]["srcport"])


class PresetsTest(unittest.TestCase):
    """内置格式参考：页面上列出来的每条，示例日志必须真能被自己的模板解析。"""

    def setUp(self):
        from services import web_format

        self.wf = web_format
        self.items = web_format.presets()

    def test_every_preset_has_key_and_vendor(self):
        self.assertGreaterEqual(len(self.items), 6)
        keys = [x["key"] for x in self.items]
        self.assertEqual(len(keys), len(set(keys)), "key 不能重复，前端靠它找条目")
        for item in self.items:
            self.assertTrue(item.get("vendor"))
            self.assertIn(item["kind"], ("nginx", "regex", "none"))

    def test_sample_matches_own_template(self):
        for item in self.items:
            if item["kind"] == "none":
                self.assertEqual(item["fields"], [], "无需模板的条目不报字段")
                continue
            with self.subTest(preset=item["key"]):
                compiled = self.wf.compile_spec(item)
                row = self.wf.parse_line(compiled, item["sample"].splitlines()[0])
                self.assertTrue(row.get("ip") or row.get("ts"), "示例解析不出 IP 或时间，说明模板和示例对不上")

    def test_fields_listed_for_each_preset(self):
        for item in self.items:
            if item["kind"] == "none":
                continue
            with self.subTest(preset=item["key"]):
                self.assertTrue(item["fields"], "有模板却没算出字段")

    def test_code_json_is_usable(self):
        """页面上展示的 JSON 必须能原样保存，不能只是好看的文本。"""
        import json

        for item in self.items:
            if item["kind"] == "none":
                self.assertEqual(item["code"], "", "无需模板的条目不该给 JSON")
                continue
            with self.subTest(preset=item["key"]):
                spec = json.loads(item["code"])
                self.assertEqual(spec["kind"], item["kind"])
                self.assertEqual(spec["source_ids"], [])
                compiled = self.wf.compile_spec(spec)     # 存得进去才算合格
                self.assertTrue(compiled["columns"])


if __name__ == "__main__":
    unittest.main()
