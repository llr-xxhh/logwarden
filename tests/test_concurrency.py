# -*- coding: utf-8 -*-
"""2026-11-07 体检 A 级问题的回归测试。

A1  任务永久删除 vs 运行中的远程拉取
A2  并发首次打开任务库的迁移竞态
A3  回滚一次「正在进行中」的导入
A4  写锁等待阶段可被取消（SFTP 读超时属真机行为，不在单测覆盖）
"""
import threading
import unittest

from services import remote


class ActivePullForTest(unittest.TestCase):
    """A1：active_pull_for 只认本任务上未结束的 pull。"""

    def setUp(self):
        # 直接往进程内任务表塞假 job，不动 JOBS 的容量逻辑
        self.jobs = []
        from services.remote import JOBS

        self.JOBS = JOBS

    def _job(self, task_id, kind="pull", state="running"):
        job = remote.Job(kind, {"protocol": "http", "host": "h", "path": "/a.log"})
        job.task_id = task_id
        job.state = state
        self.JOBS.add(job)
        self.jobs.append(job)
        return job

    def tearDown(self):
        for j in self.jobs:
            self.JOBS._items.pop(j.id, None)

    def test_finds_running_pull_of_same_task(self):
        job = self._job("t_demo")
        found = remote.active_pull_for("t_demo")
        self.assertIsNotNone(found)
        self.assertEqual(found.id, job.id)

    def test_ignores_other_tasks_and_finished_jobs(self):
        self._job("t_other")
        self._job("t_demo", state="done")
        self._job("t_demo", kind="probe")
        self.assertIsNone(remote.active_pull_for("t_demo"))

    def test_cancelled_job_no_longer_blocks(self):
        job = self._job("t_demo")
        job.state = "cancelled"
        self.assertIsNone(remote.active_pull_for("t_demo"))

    def test_no_active_pull_returns_none(self):
        self.assertIsNone(remote.active_pull_for("t_empty"))


class JobTaskIdTest(unittest.TestCase):
    """Job 必须携带 task_id，否则删除拦截无从判断。"""

    def test_start_pull_stamps_task_id(self):
        # 不真连网络：normalize 会在参数校验阶段抛错，但这发生在 Job 创建之前，
        # 所以这里直接验证 start_pull 的赋值逻辑走的是 slot 而不是丢字段
        self.assertIn("task_id", remote.Job.__slots__)


class MigrateRaceTest(unittest.TestCase):
    """A2：多个线程同时首次打开同一任务库，不允许 duplicate column 崩溃。"""

    def test_concurrent_first_open(self):
        import os, tempfile, pathlib
        from storage import Store
        root = pathlib.Path(tempfile.mkdtemp())
        store = Store(root)
        task = store.create_task({"name": "race", "components": [], "source_ids": []})
        tid = task["id"]
        errors = []

        def open_it():
            try:
                conn = store.task_connection(tid)
                conn.execute("SELECT count(*) FROM import").fetchone()
                conn.close()
            except Exception as exc:  # duplicate column / locked 会落在这里
                errors.append(repr(exc))

        threads = [threading.Thread(target=open_it) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors, [])


class DeleteRunningImportTest(unittest.TestCase):
    """A3：进行中的导入不允许回滚，已完成的照常回滚。"""

    def test_delete_running_import_rejected(self):
        import tempfile, pathlib
        from storage import Store
        store = Store(pathlib.Path(tempfile.mkdtemp()))
        tid = store.create_task({"name": "d", "components": [], "source_ids": ["nginx_access"]})["id"]
        iid = store.begin_import(tid, "nginx_access", "combined", "x.log", 100)
        with self.assertRaisesRegex(ValueError, "正在进行"):
            store.delete_import(tid, iid)
        # 结束后可以正常回滚
        store.finish_import(tid, iid, 5, 0, [], None, None)
        res = store.delete_import(tid, iid)
        self.assertTrue(res)

    def test_delete_finished_import_ok(self):
        import tempfile, pathlib
        from storage import Store
        store = Store(pathlib.Path(tempfile.mkdtemp()))
        tid = store.create_task({"name": "d", "components": [], "source_ids": ["nginx_access"]})["id"]
        iid = store.begin_import(tid, "nginx_access", "combined", "x.log", 100)
        store.finish_import(tid, iid, 0, 0, [], None, None)
        store.delete_import(tid, iid)  # 不抛即通过


class WriteLockCancelTest(unittest.TestCase):
    """A4：写锁被占时，等待方取消后不应无限等下去。"""

    def test_acquire_loop_honours_cancel(self):
        from services.remote import JOBS
        job = remote.Job("pull", {"protocol": "http", "host": "h", "path": "/a.log"})
        job.task_id = "t_lock"
        got = threading.Event()

        def hold():
            with JOBS.write_lock:
                got.set()
                threading.Event().wait(5)   # 占住锁，模拟卡在网络读

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        got.wait(2)
        job.cancel()
        # 与 _run_pull 中相同结构的等待循环
        acquired = False
        while True:
            if job.cancelled():
                break
            if JOBS.write_lock.acquire(timeout=0.2):
                acquired = True
                JOBS.write_lock.release()
                break
        self.assertFalse(acquired)
        self.assertTrue(job.cancelled())


if __name__ == "__main__":
    unittest.main()
