"""格式变体回归：设备转发前缀、RFC5424、各应用自己的 JSON 字段名。

背景：nginx 的 log_format 是用户可配的，写死字段顺序会整行失败；
syslog 与 JSON 也有同样问题，只是失败方式不同——前者报错，后者静默丢字段。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.parsing import LogParser, strip_pri, syslog_head


class SyslogVariantTest(unittest.TestCase):
    def test_pri_prefix_is_stripped(self):
        self.assertEqual(strip_pri("<34>Nov  4 09:00:00 web01 sshd[1]: x"), "Nov  4 09:00:00 web01 sshd[1]: x")
        self.assertEqual(strip_pri("<190><34>Nov  4 09:00:00 h p: x"), "Nov  4 09:00:00 h p: x")
        self.assertEqual(strip_pri("Nov  4 09:00:00 h p: x"), "Nov  4 09:00:00 h p: x")

    def test_same_line_with_and_without_pri_gives_same_fields(self):
        base = "Nov  4 09:00:00 web01 sshd[2100]: Failed password for invalid user admin from 103.91.208.11 port 22 ssh2"
        plain = LogParser("syslog").parse_line(base, 1)[0]
        with_pri = LogParser("syslog").parse_line("<34>" + base, 1)[0]
        self.assertEqual(plain, with_pri, "<PRI> 只能影响行首，不能影响其它字段")
        self.assertEqual(plain["srcip"], "103.91.208.11")
        self.assertEqual(plain["result"], "失败")

    def test_rfc5424(self):
        line = "<34>1 2026-11-04T09:00:00.003Z web01 sshd 1234 ID47 - Accepted password for root from 1.2.3.4 port 22"
        row = LogParser("syslog").parse_line(line, 1)[0]
        self.assertEqual(row["host"], "web01")
        self.assertEqual(row["proc"], "sshd")
        self.assertEqual(row["pid"], 1234)
        self.assertEqual(row["srcip"], "1.2.3.4")
        self.assertEqual(row["result"], "成功")
        self.assertIsNotNone(row["ts"])

    def test_rfc5424_with_structured_data(self):
        line = '<34>1 2026-11-04T09:00:00Z web01 app 99 - - [exampleSDID@1 k="v"] Failed password for admin from 5.6.7.8'
        row = LogParser("syslog").parse_line(line, 1)[0]
        self.assertEqual(row["srcip"], "5.6.7.8")
        self.assertEqual(row["proc"], "app")

    def test_syslog_with_explicit_year(self):
        """部分设备补年份，不能因为多了 4 位数字就整行失败。"""
        row = LogParser("syslog").parse_line("Nov  4 2026 09:00:00 web01 sshd[1]: Accepted password for root from 1.2.3.4", 1)[0]
        self.assertEqual(row["srcip"], "1.2.3.4")
        self.assertEqual(row["host"], "web01")
        self.assertIsNotNone(row["ts"])

    def test_garbage_still_rejected(self):
        """宽松不能变成什么都吞，认不出的行必须报错而不是塞假数据。"""
        with self.assertRaises(ValueError):
            LogParser("syslog").parse_line("this is not a syslog line at all", 1)

    def test_firewall_uses_same_head(self):
        line = '<190>Nov  4 09:00:00 fw01 action=deny src=1.2.3.4 dst=5.6.7.8 proto=6'
        row = LogParser("firewall").parse_line(line, 1)[0]
        self.assertEqual(row["action"], "deny")
        self.assertEqual(row["srcip"], "1.2.3.4")
        self.assertEqual(row["host"], "fw01")
        self.assertEqual(row["protocol"], "6")


class JsonVariantTest(unittest.TestCase):
    def _ts(self, line: str):
        return LogParser("json").parse_line(line, 1)[0]["ts"]

    def test_common_timestamp_names(self):
        for key in ("ts", "time", "timestamp", "@timestamp", "_time", "event_time", "log_time"):
            with self.subTest(key=key):
                self.assertIsNotNone(self._ts('{"%s":"2026-11-04T09:00:00Z","msg":"x"}' % key), key + " 应能被识别")

    def test_nested_host_object(self):
        row = LogParser("json").parse_line('{"ts":"2026-11-04T09:00:00Z","host":{"name":"web01"},"msg":"x"}', 1)[0]
        self.assertEqual(row["host"], "web01")

    def test_source_ips_array(self):
        row = LogParser("json").parse_line('{"ts":1699000000,"sourceIPs":["10.0.0.1","10.0.0.2"],"msg":"x"}', 1)[0]
        self.assertEqual(row["host"], "10.0.0.1,10.0.0.2")

    def test_epoch_seconds(self):
        self.assertEqual(self._ts('{"ts":1699000000,"msg":"x"}'), 1699000000000)

    def test_unknown_shape_falls_back_to_raw(self):
        """字段名一个都不认识时仍要出一行，msg 用原始行兜底。"""
        row = LogParser("json").parse_line('{"foo":"bar"}', 1)[0]
        self.assertEqual(row["msg"], '{"foo":"bar"}')
        self.assertIsNone(row["ts"])


if __name__ == "__main__":
    unittest.main()
