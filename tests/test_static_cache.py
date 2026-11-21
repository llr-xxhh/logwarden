from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from static_files import NoCacheStatic


class StaticCacheTest(unittest.TestCase):
    """静态资源必须带 no-cache：否则浏览器按 Last-Modified 启发式缓存，
    版本更新后用户看到的还是老界面（要 Ctrl+F5 才救得回来）。"""

    def setUp(self):
        self.static = NoCacheStatic(directory=str(ROOT / "static"), html=True)
        self.scope = {"type": "http", "method": "GET", "headers": [], "path": "/",
                      "query_string": b"", "scheme": "http", "server": ("127.0.0.1", 8766), "root_path": ""}

    def test_index_and_js_send_no_cache(self):
        for path in ("", "live.js"):
            resp = asyncio.run(self.static.get_response(path, self.scope))
            self.assertEqual(resp.status_code, 200, path)
            self.assertEqual(resp.headers.get("cache-control"), "no-cache", path)


if __name__ == "__main__":
    unittest.main()
