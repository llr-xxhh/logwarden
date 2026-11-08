"""自定义日志源：界面新增一个源不该改代码。

内置目录 templates/catalog.json 是只读的，自定义源写在 sources/*.json，
启动时合并进源表，建任务时和内置源一样可选。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import custom_sources


class CustomSourceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._old = custom_sources.SOURCE_DIR
        custom_sources.SOURCE_DIR = Path(self.tmp.name) / "sources"

    def tearDown(self):
        custom_sources.SOURCE_DIR = self._old
        self.tmp.cleanup()

    def test_create_and_list(self):
        item = custom_sources.save_custom({"id": "app_access", "name": "某应用访问日志", "format": "combined"})
        self.assertEqual(item["id"], "app_access")
        self.assertFalse(item["builtin"])
        listed = custom_sources.list_custom()
        self.assertEqual([x["id"] for x in listed], ["app_access"])
        self.assertEqual(listed[0]["name"], "某应用访问日志")

    def test_rejects_bad_id(self):
        for bad in ("1abc", "a", "中文源", "app-access", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    custom_sources.save_custom({"id": bad, "name": "x", "format": "combined"})

    def test_uppercase_id_is_normalized(self):
        """用户手打大写不算错，统一转小写即可。"""
        item = custom_sources.save_custom({"id": "App_Access", "name": "x", "format": "combined"})
        self.assertEqual(item["id"], "app_access")

    def test_rejects_builtin_collision(self):
        with self.assertRaises(ValueError):
            custom_sources.save_custom({"id": "nginx_access", "name": "撞名", "format": "combined"},
                                       builtin_ids={"nginx_access"})

    def test_rejects_unknown_format(self):
        with self.assertRaises(ValueError):
            custom_sources.save_custom({"id": "app_x", "name": "x", "format": "made_up"})

    def test_update_keeps_created_at(self):
        first = custom_sources.save_custom({"id": "app_x", "name": "旧名", "format": "combined"})
        second = custom_sources.save_custom({"id": "app_x", "name": "新名", "format": "json"})
        self.assertEqual(second["created_at"], first["created_at"])
        self.assertEqual(second["name"], "新名")
        self.assertEqual(second["format"], "json")

    def test_delete(self):
        custom_sources.save_custom({"id": "app_x", "name": "x", "format": "combined"})
        custom_sources.delete_custom("app_x")
        self.assertEqual(custom_sources.list_custom(), [])
        with self.assertRaises(KeyError):
            custom_sources.delete_custom("app_x")

    def test_component_wraps_sources(self):
        self.assertIsNone(custom_sources.custom_component([]))
        item = custom_sources.save_custom({"id": "app_x", "name": "x", "format": "combined"})
        component = custom_sources.custom_component([item])
        self.assertEqual(component["id"], "custom")
        self.assertEqual(component["sources"], ["app_x"])
        self.assertTrue(component["custom"])


if __name__ == "__main__":
    unittest.main()
