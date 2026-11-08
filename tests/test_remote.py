"""远程拉取的单元测试 + 本地 HTTP 端到端。

不碰真机：HTTP 分支起一个 127.0.0.1 的静态服务，把整条链路（探测 → 拉取 →
入库 → 查行数）跑一遍。SSH / SMB 需要真实服务端，这里只验参数归一化和路径转换，
真正连通靠手工验收。
"""
from __future__ import annotations

import gzip
import io
import sys
import tempfile
import threading
import time
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import remote
from services.importer import Importer
from services.query import QueryService
from storage import Store

SAMPLE = """10.20.31.15 - - [04/Nov/2026:09:00:00 +0800] "GET /index.html HTTP/1.1" 200 8432 "-" "Mozilla/5.0"
103.91.208.11 - - [04/Nov/2026:09:01:00 +0800] "GET /.git/config HTTP/1.1" 404 153 "-" "sqlmap/1.7.2"
103.91.208.11 - - [04/Nov/2026:09:02:00 +0800] "POST /upload/shell.php HTTP/1.1" 200 42 "-" "Mozilla/5.0"
"""


class NormalizeTest(unittest.TestCase):
    def test_ssh_defaults(self):
        spec = remote.normalize({"protocol": "ssh", "host": "10.0.0.5", "username": "root",
                                 "auth": "password", "password": "p", "path": "/var/log/secure"})
        self.assertEqual(spec["port"], 22)
        self.assertEqual(spec["auth"], "password")
        self.assertEqual(spec["path"], "/var/log/secure")

    def test_auth_alias_from_ui_text(self):
        # 界面下拉框的选项文案直接当 value 提交时也要认
        spec = remote.normalize({"protocol": "ssh", "host": "h", "username": "u",
                                 "auth": "密钥（推荐 · 不落库）", "key_text": "k", "path": "/x"})
        self.assertEqual(spec["auth"], "key")

    def test_missing_password(self):
        with self.assertRaises(ValueError):
            remote.normalize({"protocol": "ssh", "host": "h", "username": "u",
                              "auth": "password", "path": "/x"})

    def test_missing_host(self):
        with self.assertRaises(ValueError):
            remote.normalize({"protocol": "ssh", "path": "/x"})

    def test_session_without_cache(self):
        remote._LAST_AUTH.clear()
        with self.assertRaises(ValueError):
            remote.normalize({"protocol": "ssh", "host": "nope", "username": "u",
                              "auth": "session", "path": "/x"})

    def test_http_url_with_port(self):
        spec = remote.normalize({"protocol": "http", "host": "10.0.0.5", "port": "8080",
                                 "path": "/logs/access.log"})
        self.assertEqual(spec["url"], "http://10.0.0.5:8080/logs/access.log")

    def test_http_url_keeps_scheme_and_port(self):
        spec = remote.normalize({"protocol": "http", "host": "https://logs.example.com",
                                 "port": "8443", "path": "a.log"})
        self.assertEqual(spec["url"], "https://logs.example.com:8443/a.log")

    def test_http_strips_default_port(self):
        spec = remote.normalize({"protocol": "http", "host": "10.0.0.5", "port": "80", "path": "/a"})
        self.assertEqual(spec["url"], "http://10.0.0.5/a")

    def test_smb_port(self):
        spec = remote.normalize({"protocol": "smb", "host": "h", "username": "u",
                                 "password": "p", "path": "C:\\x\\y.evtx"})
        self.assertEqual(spec["port"], 445)


class SmbPathTest(unittest.TestCase):
    def test_drive_to_unc(self):
        self.assertEqual(remote.smb_unc("10.0.0.9", r"C:\Windows\System32\winevt\Logs\Security.evtx"),
                         r"\\10.0.0.9\C$\Windows\System32\winevt\Logs\Security.evtx")

    def test_unc_passthrough(self):
        self.assertEqual(remote.smb_unc("h", r"\\srv\share\a.log"), r"\\srv\share\a.log")

    def test_double_separators_collapsed(self):
        self.assertEqual(remote.smb_unc("h", "C:\\\\Windows\\\\a.log"), r"\\h\C$\Windows\a.log")

    def test_posix_path_rejected(self):
        with self.assertRaises(remote.PullError):
            remote.smb_unc("h", "/var/log/nginx/access.log")


class ConcatStreamTest(unittest.TestCase):
    def _pieces(self, *chunks):
        return [{"path": "f%d" % i, "size": len(c), "opener": (lambda c=c: io.BytesIO(c))}
                for i, c in enumerate(chunks)]

    def test_concatenates_in_order(self):
        stream = remote.ConcatStream(self._pieces(b"aaa\n", b"bbb\n", b"ccc\n"))
        self.assertEqual(stream.read(), b"aaa\nbbb\nccc\n")

    def test_seek_zero_rewinds_head(self):
        stream = remote.ConcatStream(self._pieces(b"0123456789", b"abcdefghij"))
        head = stream.read(8)
        self.assertEqual(head, b"01234567")
        self.assertEqual(stream.seek(0), 0)
        self.assertEqual(stream.read(8), b"01234567")
        self.assertEqual(stream.read(), b"89abcdefghij")

    def test_gzip_piece_decoded(self):
        payload = b"line1\nline2\n"
        piece = {"path": "a.log.gz", "size": 0,
                 "opener": lambda: remote._GzipPiece(io.BytesIO(gzip.compress(payload)))}
        self.assertEqual(remote.ConcatStream([piece]).read(), payload)

    def test_cancel_raises(self):
        flag = {"stop": False}
        stream = remote.ConcatStream(self._pieces(b"x" * 100), cancel=lambda: flag["stop"])
        flag["stop"] = True
        with self.assertRaises(remote.Cancelled):
            stream.read(10)

    def test_on_read_counts(self):
        seen = []
        stream = remote.ConcatStream(self._pieces(b"abc", b"de"), on_read=seen.append)
        stream.read()
        self.assertEqual(sum(seen), 5)

    def test_skip_unreadable_piece(self):
        # /var/log 里常混着当前账号读不了的文件：跳过它，其余照拉
        seen = []

        def boom():
            raise IOError("permission denied")

        pieces = [{"path": "root-only.log", "size": 10, "opener": boom},
                  {"path": "ok.log", "size": 3, "opener": lambda: io.BytesIO(b"ok\n")}]
        stream = remote.ConcatStream(pieces, on_skip=lambda p, e: seen.append(p["path"]))
        self.assertEqual(stream.read(), b"ok\n")
        self.assertEqual(seen, ["root-only.log"])

    def test_open_error_raised_without_on_skip(self):
        def boom():
            raise IOError("nope")

        stream = remote.ConcatStream([{"path": "a.log", "size": 1, "opener": boom}])
        with self.assertRaises(IOError):
            stream.read()


class CancelTest(unittest.TestCase):
    def _job(self, state="running", message="拉取中"):
        job = remote.Job("pull", {"protocol": "ssh", "host": "h", "port": 22, "username": "u"})
        job.state = state
        job.message = message
        return remote.JOBS.add(job)

    def test_cancel_running_job(self):
        job = self._job()
        res = remote.cancel(job.id)
        self.assertTrue(res["ok"])
        self.assertTrue(job.cancelled())
        self.assertEqual(job.message, "正在取消")

    def test_cancel_finished_job_keeps_reason(self):
        # 已经失败的任务被点取消，不能把真实原因冲成「正在取消」
        job = self._job(state="failed", message="认证失败：用户名、密码或密钥不正确")
        res = remote.cancel(job.id)
        self.assertFalse(res["ok"])
        self.assertEqual(job.message, "认证失败：用户名、密码或密钥不正确")
        self.assertFalse(job.cancelled())

    def test_snapshot_has_skipped_field(self):
        job = self._job(state="done", message="完成")
        job.skipped = ["root-only.log"]
        snap = job.snapshot()
        self.assertEqual(snap["skipped"], ["root-only.log"])
        self.assertEqual(snap["percent"], 100)


class EstimateTest(unittest.TestCase):
    def test_plain(self):
        data = b"x" * 100 + b"\n" * 10
        # 10 行、每行 11 字节 → 1100 字节约 100 行
        self.assertEqual(remote.estimate_lines(data, len(data), 1100), 100)

    def test_gzip_uses_compression_ratio(self):
        # 1000 字节 / 100 行（每行 10 字节），网络侧只有 100 字节：压缩比 10:1
        plain = b"y" * 900 + b"\n" * 100
        # 压缩后总 1000 字节 → 解压后约 10000 字节 → 约 1000 行
        self.assertEqual(remote.estimate_lines(plain, 100, 1000), 1000)

    def test_empty(self):
        self.assertEqual(remote.estimate_lines(b"", 0, 0), 0)


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class HttpEndToEndTest(unittest.TestCase):
    """用本地 HTTP 服务跑完整链路：probe → pull → 入库。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.web = Path(cls.tmp.name) / "web"
        cls.web.mkdir()
        (cls.web / "access.log").write_text(SAMPLE, encoding="utf-8")
        (cls.web / "rotated.log.gz").write_bytes(gzip.compress(SAMPLE.encode()))

        handler = lambda *a, **k: _QuietHandler(*a, directory=str(cls.web), **k)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.store = Store(Path(tempfile.mkdtemp()))
        self.queries = QueryService(self.store)
        self.importer = Importer(self.store, self.queries)
        self.task = self.store.create_task({
            "name": "远程测试", "components": ["nginx"], "source_ids": ["nginx_access"]})
        self.task_id = self.task["id"]

    def _wait(self, job_id, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            snap = remote.status(job_id)
            if snap["state"] not in ("pending", "running"):
                return snap
            time.sleep(0.05)
        self.fail("拉取任务超时")

    def test_probe_reports_size_and_sample(self):
        result = remote.probe({"protocol": "http", "host": "127.0.0.1", "port": self.port,
                               "path": "/access.log"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["files_total"], 1)
        self.assertGreater(result["total_size"], 0)
        self.assertGreater(result["est_lines"], 0)
        self.assertEqual(len(result["sample"]), 3)
        self.assertIn("GET /index.html", result["sample"][0])

    def test_pull_imports_rows(self):
        job = remote.start_pull({"protocol": "http", "host": "127.0.0.1", "port": self.port,
                                 "path": "/access.log"},
                                self.importer, self.task_id, "nginx_access", "combined")
        snap = self._wait(job.id)
        self.assertEqual(snap["state"], "done", snap.get("error"))
        self.assertEqual(snap["rows"], 3)
        self.assertEqual(snap["percent"], 100)
        page = self.queries.query(self.task_id, "nginx_access", {"size": 10})
        self.assertEqual(page["total"], 3)

    def test_pull_gzip_is_decoded_once(self):
        job = remote.start_pull({"protocol": "http", "host": "127.0.0.1", "port": self.port,
                                 "path": "/rotated.log.gz"},
                                self.importer, self.task_id, "nginx_access", "combined")
        snap = self._wait(job.id)
        self.assertEqual(snap["state"], "done", snap.get("error"))
        self.assertEqual(snap["rows"], 3)

    def test_pull_records_remote_filename(self):
        job = remote.start_pull({"protocol": "http", "host": "127.0.0.1", "port": self.port,
                                 "path": "/access.log"},
                                self.importer, self.task_id, "nginx_access", "combined")
        self._wait(job.id)
        imports = self.store.list_imports(self.task_id)
        self.assertTrue(imports)
        self.assertIn("access.log", imports[0]["filename"])

    def test_missing_file_fails_cleanly(self):
        job = remote.start_pull({"protocol": "http", "host": "127.0.0.1", "port": self.port,
                                 "path": "/nope.log"},
                                self.importer, self.task_id, "nginx_access", "combined")
        snap = self._wait(job.id)
        self.assertEqual(snap["state"], "failed")
        self.assertTrue(snap["error"])

    def test_format_mismatch_rejected(self):
        job = remote.start_pull({"protocol": "http", "host": "127.0.0.1", "port": self.port,
                                 "path": "/access.log"},
                                self.importer, self.task_id, "nginx_access", "syslog")
        snap = self._wait(job.id)
        self.assertEqual(snap["state"], "failed")
        self.assertIn("格式", snap["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
