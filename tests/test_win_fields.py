from __future__ import annotations

import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from storage import Store
from services.parsing import event_record, parser_config, xml_event


class WindowsFieldsTest(unittest.TestCase):
    """Windows 事件头的关联字段（EventRecordID/ActivityID/进程线程/Keywords）
    和 XML 导出路径的字段完整度。"""

    def test_json_system_fields_to_columns(self):
        payload = {
            "System": {
                "EventID": 4624,
                "EventRecordID": 321,
                "Correlation": {"#attributes": {"ActivityID": "{abc-123}"}},
                "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 8}},
                "Keywords": "0x8020000000000000",
            },
            "EventData": {"Data": [
                {"#attributes": {"Name": "TargetUserName"}, "#text": "alice"},
            ]},
        }
        rec = event_record(payload)
        self.assertEqual(rec["recordId"], "321")
        self.assertEqual(rec["activityId"], "{abc-123}")
        self.assertEqual(rec["processId"], "4")
        self.assertEqual(rec["threadId"], "8")
        self.assertEqual(rec["keywords"], "0x8020000000000000")

    def test_xml_unnamed_data_keeps_every_value(self):
        xml = (
            "<Event><System><EventID>4624</EventID><Computer>WIN01</Computer>"
            "<TimeCreated SystemTime='2026-11-04T01:00:00Z'/>"
            "<EventRecordID>123</EventRecordID>"
            "<Correlation ActivityID='{abc}'/>"
            "<Execution ProcessID='4' ThreadID='8'/>"
            "<Keywords>0x8020000000000000</Keywords></System>"
            "<EventData><Data>a</Data><Data>b</Data>"
            "<Data Name='TargetUserName'>alice</Data></EventData>"
            "<RenderingInfo><Message>登录成功 alice</Message></RenderingInfo></Event>"
        )
        rec = xml_event(ET.fromstring(xml))
        # 旧实现两个无名 Data 都写进 "Data" 键，b 覆盖 a
        self.assertEqual(rec["detail"].count("Data0"), 1)
        detail = rec["detail"]
        self.assertIn("Data0", detail)
        self.assertIn("Data1", detail)
        self.assertEqual(rec["msg"], "登录成功 alice")
        self.assertEqual(rec["recordId"], "123")
        self.assertEqual(rec["activityId"], "{abc}")
        self.assertEqual(rec["processId"], "4")
        self.assertEqual(rec["threadId"], "8")
        self.assertEqual(rec["keywords"], "0x8020000000000000")

    def test_xml_userdata_fields_survive_without_data_wrapper(self):
        xml = (
            "<Event><System><EventID>5857</EventID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel>"
            "<EventRecordID>9</EventRecordID></System>"
            "<UserData><Operation_StartedOperational><ProviderName>MSI</ProviderName>"
            "<HostProcess>WmiPrvSE.exe</HostProcess><Code>0x0</Code></Operation_StartedOperational></UserData>"
            "</Event>"
        )
        rec = xml_event(ET.fromstring(xml))
        self.assertIn("ProviderName", rec["msg"] + rec.get("detail", ""))
        self.assertEqual(rec["recordId"], "9")

    def test_smb_event_names_are_channel_scoped(self):
        smb_client = {"System": {"EventID": 30810, "Channel": "Microsoft-Windows-SmbClient/Connectivity"}}
        self.assertEqual(event_record(smb_client)["event"], "SMB TCP/IP 接口添加")
        # 同号串到安全通道必须回落，并且显示 Provider 来源而不是硬套 SMB 名
        security = {
            "System": {
                "EventID": 30810,
                "Channel": "Security",
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
            }
        }
        self.assertEqual(event_record(security)["event"], "Security-Auditing · 30810")

    def test_smb_server_endpoint_names(self):
        for eid, name in ((1010, "SMB 终结点添加"), (1011, "SMB 终结点删除")):
            rec = event_record({"System": {"EventID": eid, "Channel": "Microsoft-Windows-SMBServer/Operational"}})
            self.assertEqual(rec["event"], name)

    def test_codeintegrity_3089_is_channel_scoped(self):
        ci = {"System": {"EventID": 3089, "Channel": "Microsoft-Windows-CodeIntegrity/Operational"}}
        self.assertEqual(event_record(ci)["event"], "签名信息关联")

    def test_unknown_event_falls_back_to_provider_not_wrong_name(self):
        # 本机 System 的 7021 来自 Intel 网卡驱动 Netwtw14，不是 SCM 的服务启动失败
        rec = event_record({
            "System": {
                "EventID": 7021,
                "Channel": "System",
                "Provider": {"#attributes": {"Name": "Netwtw14"}},
            }
        })
        self.assertEqual(rec["event"], "Netwtw14 · 7021")
        self.assertNotIn("服务", rec["event"])

    def test_new_task_evtx_table_has_link_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp))
            task = store.create_task({"name": "列校验", "components": ["windows"], "source_ids": ["win_security"]})
            conn = store.task_connection(task["id"])
            store.ensure_raw_table(conn, parser_config("windows_event"))
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(raw_evtx)").fetchall()}
            self.assertTrue({"recordId", "activityId", "processId", "threadId", "keywords"} <= cols)


if __name__ == "__main__":
    unittest.main()
