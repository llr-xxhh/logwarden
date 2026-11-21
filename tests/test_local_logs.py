from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import local_logs


class LocalLogsTest(unittest.TestCase):
    """本机 EVTX 一键导入：路径白名单 + 文件→日志源映射。不依赖真实 winevt 目录。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.patcher = mock.patch.object(local_logs, "logs_dir", return_value=self.dir)
        self.patcher.start()
        (self.dir / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
        (self.dir / "Some-Channel%4Operational.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
        (self.dir / "notes.txt").write_text("not a log", encoding="utf-8")

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_resolve_accepts_bare_filename(self):
        path = local_logs.resolve("Security.evtx")
        self.assertEqual(path.name, "Security.evtx")
        self.assertEqual(path.parent, self.dir.resolve())

    def test_resolve_rejects_traversal_and_paths(self):
        for bad in ("..\\evil.evtx", "../evil.evtx", "sub\\a.evtx",
                    "C:\\Windows\\Security.evtx", "\\\\host\\c$\\a.evtx",
                    "notes.txt", "", "missing.evtx"):
            with self.assertRaises(ValueError, msg=bad):
                local_logs.resolve(bad)

    def test_channel_name_unescapes(self):
        self.assertEqual(local_logs.channel_name("Some-Channel%4Operational.evtx"),
                         "Some-Channel/Operational")
        self.assertEqual(local_logs.channel_name("Security.evtx"), "Security")

    def test_list_maps_catalog_sources_and_sorts(self):
        sources = {
            "win_security": {"name": "安全日志", "format": "evtx", "level": "required",
                             "paths": ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]},
            "nginx_access": {"name": "Nginx", "format": "combined", "paths": ["/var/log/nginx/access.log"]},
        }
        result = local_logs.list_files(sources)
        files = result["files"]
        # txt 不出现；已匹配的排最前
        self.assertEqual([f["file"] for f in files],
                         ["Security.evtx", "Some-Channel%4Operational.evtx"])
        self.assertEqual(files[0]["source_id"], "win_security")
        self.assertEqual(files[0]["level"], "required")
        self.assertTrue(files[0]["allowed"])
        self.assertIsNone(files[1]["source_id"])
        self.assertIsNone(files[1]["allowed"])
        self.assertTrue(all(f["readable"] for f in files))
        # evtx_sources 只含 EVTX 格式的源，带级别
        self.assertEqual(result["evtx_sources"],
                         [{"id": "win_security", "name": "安全日志", "level": "required"}])

    def test_list_task_scope_levels_and_order(self):
        (self.dir / "System.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 128)
        sources = {
            "win_security": {"name": "安全日志", "format": "evtx", "level": "required",
                             "paths": ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]},
            "win_system": {"name": "系统日志", "format": "evtx", "level": "recommended",
                           "paths": ["C:\\Windows\\System32\\winevt\\Logs\\System.evtx"]},
            "win_powershell": {"name": "PowerShell", "format": "evtx", "level": "optional",
                               "paths": ["C:\\Windows\\System32\\winevt\\Logs\\Some-Channel%4Operational.evtx"]},
        }
        result = local_logs.list_files(sources, allowed_ids={"win_security", "win_system"})
        # 下拉候选只留任务组件范围内的源
        self.assertEqual([s["id"] for s in result["evtx_sources"]], ["win_security", "win_system"])
        by_name = {f["file"]: f for f in result["files"]}
        self.assertTrue(by_name["Security.evtx"]["allowed"])
        self.assertFalse(by_name["Some-Channel%4Operational.evtx"]["allowed"])
        # 排序：必要 → 推荐 → 范围外沉底（范围外即使更大也排最后）
        self.assertEqual([f["file"] for f in result["files"]],
                         ["Security.evtx", "System.evtx", "Some-Channel%4Operational.evtx"])

    def test_list_empty_dir(self):
        (self.dir / "Security.evtx").unlink()
        (self.dir / "Some-Channel%4Operational.evtx").unlink()
        (self.dir / "notes.txt").unlink()
        result = local_logs.list_files({})
        self.assertEqual(result["files"], [])


if __name__ == "__main__":
    unittest.main()
