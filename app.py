"""FastAPI entry point. Routes only translate HTTP and call services."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from storage import Store
from services import custom_sources, remote, web_format
from services.importer import Importer
from services.query import QueryService
from services.rule_engine import RuleEngine, RuleStore

ROOT = Path(__file__).resolve().parent
store = Store()
queries = QueryService(store)
importer = Importer(store, queries)
rule_store = RuleStore()
engine = RuleEngine(store, queries, rule_store)
app = FastAPI(title="LogWarden", version="0.7", docs_url="/api/docs", redoc_url=None)


@app.middleware("http")
async def security_headers(request, call_next):
    # 只信自己声明的地址：DNS rebinding 攻击会用公网域名把浏览器请求
    # 指回 127.0.0.1，进而复用进程里缓存的远程拉取凭据。Host 对不上直接拒
    host = (request.headers.get("host") or "").split(":", 1)[0]
    if host not in ("127.0.0.1", "localhost", "::1"):
        return JSONResponse(status_code=403, content={"detail": "本服务只允许本机访问"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(ValueError)
def value_error_handler(_, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(TypeError)
@app.exception_handler(AttributeError)
def type_error_handler(_, exc: Exception):
    # 请求体传错类型（sort 传字符串、fk 传数组之类）。入参校验是第一道防线，
    # 这里是兜底：宁可 400 也不能把客户端手滑变成 500
    return JSONResponse(status_code=400, content={"detail": "请求参数类型不对：%s" % exc})


@app.exception_handler(KeyError)
def key_error_handler(_, exc: KeyError):
    return JSONResponse(status_code=404, content={"detail": str(exc.args[0] if exc.args else exc)})


@app.exception_handler(remote.PullError)
def pull_error_handler(_, exc: remote.PullError):
    """远端侧的问题（连不上、路径不存在、认证失败）都当成 400，消息原样给前端。"""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "app": "logwarden", "engine": "duckdb", "version": app.version, "storage": str(store.root), "tasks": len(store.list_tasks())}


@app.get("/api/bootstrap")
def bootstrap() -> dict[str, Any]:
    return {
        "tasks": store.list_tasks(),
        "groups": queries.catalog["groups"],
        "components": list(queries.components.values()),
        "sources": list(queries.sources.values()),
        "templates": list(queries.templates.values()),
        "formats": web_format.list_formats(),
        # 模板落盘目录，前端在"日志未识别"时直接给出，省得用户去找
        "format_dir": str(web_format.FORMAT_DIR),
    }


@app.get("/api/tasks")
def tasks() -> list[dict[str, Any]]:
    return store.list_tasks()


@app.get("/api/deleted-tasks")
def deleted_tasks() -> list[dict[str, Any]]:
    """软删除的归档任务；与 /api/tasks/{id} 分开，避免路径参数把 deleted-tasks 吃掉。"""
    return store.list_deleted_tasks()


@app.post("/api/tasks/{task_id}/restore")
def restore_task(task_id: str) -> dict[str, Any]:
    task = store.restore_task(task_id)
    return queries.task_view(task["id"])


@app.post("/api/tasks", status_code=201)
def create_task(data: dict[str, Any]) -> dict[str, Any]:
    template = queries.templates.get(data.get("template_id"))
    components = list(dict.fromkeys(data.get("components") or (template or {}).get("components") or []))
    for cid in components:
        if cid not in queries.components:
            raise ValueError("未知组件: " + cid)
    allowed: list[str] = []
    for cid in components:
        allowed.extend(queries.components[cid]["sources"])
    explicit = data.get("source_ids")
    if explicit is not None:
        if not isinstance(explicit, list):
            raise ValueError("source_ids 必须是数组")
        unknown = [sid for sid in explicit if sid not in allowed]
        if unknown:
            raise ValueError("日志源不属于所选组件: " + ", ".join(unknown))
        source_ids = list(dict.fromkeys(explicit))
        if not source_ids:
            raise ValueError("所选组件下没有勾选任何日志源")
    else:
        source_ids = list(allowed)
    for sid in source_ids:
        queries.source(sid)
    payload = dict(data)
    payload["components"] = components
    payload["source_ids"] = list(dict.fromkeys(source_ids))
    payload["arch"] = data.get("arch") or (template or {}).get("name") or "自定义组合"
    task = store.create_task(payload)
    return queries.task_view(task["id"])


@app.get("/api/tasks/{task_id}")
def task_detail(task_id: str) -> dict[str, Any]:
    return queries.task_view(task_id)


@app.patch("/api/tasks/{task_id}/sources")
def update_task_sources(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """证据清单抽屉勾选增删源。范围与建任务一致：只能勾任务组件下的源。

    已导入的数据不因取消勾选而删除——重新勾上即恢复显示。
    """
    task = store.get_task(task_id)
    allowed: list[str] = []
    for cid in task["components"]:
        component = queries.components.get(cid)
        if component:
            allowed.extend(component["sources"])
    explicit = data.get("source_ids")
    if not isinstance(explicit, list):
        raise ValueError("source_ids 必须是数组")
    unknown = [sid for sid in explicit if sid not in allowed]
    if unknown:
        raise ValueError("日志源不属于该任务的组件: " + ", ".join(unknown))
    source_ids = list(dict.fromkeys(explicit))
    if not source_ids:
        raise ValueError("至少保留一个日志源")
    for sid in source_ids:
        queries.source(sid)
    store.update_task_sources(task_id, source_ids)
    return queries.task_view(task_id)


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: str, permanent: bool = False) -> dict[str, Any]:
    if permanent:
        # 拉取线程还拿着这个任务的连接在写，此刻删库文件会：线程崩溃 + 并发请求
        # 重建空库文件导致删除接口 500 + 前端轮询一个指向已删任务的 job
        job = remote.active_pull_for(task_id)
        if job:
            raise ValueError("该任务有正在进行的远程拉取（%s），请先取消再删除" % job.id)
    store.delete_task(task_id, permanent)
    return {"ok": True, "permanent": permanent}


@app.delete("/api/tasks/{task_id}/imports/{import_id}")
def delete_import(task_id: str, import_id: str) -> dict[str, Any]:
    """回滚一次导入：删掉它写入的所有行，用于选错源/选错格式/传错文件。"""
    store.get_task(task_id)
    return store.delete_import(task_id, import_id)


@app.get("/api/tasks/{task_id}/imports")
def imports(task_id: str) -> list[dict[str, Any]]:
    store.get_task(task_id)
    return store.list_imports(task_id)


@app.post("/api/tasks/{task_id}/imports", status_code=201)
def upload_log(
    task_id: str,
    file: UploadFile = File(...),
    source_id: str = Form(...),
    fmt: str = Form(""),
    encoding: str = Form("utf-8"),
) -> dict[str, Any]:
    source = queries.source(source_id)
    selected = fmt or source.get("format", "text")
    size = getattr(file, "size", None) or 0
    if not size:
        # 部分 multipart 实现不填 size，这里补一次真实字节数，否则 500MB 上限形同虚设
        try:
            file.file.seek(0, os.SEEK_END)
            size = file.file.tell()
            file.file.seek(0)
        except OSError:
            size = 0
    return importer.import_stream(task_id, source_id, selected, file.filename or "upload.log", file.file, size, encoding)


@app.post("/api/tasks/{task_id}/imports/text", status_code=201)
def import_text(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    source_id = str(data.get("source_id") or "")
    source = queries.source(source_id)
    text = str(data.get("text") or "")
    if not text.strip():
        raise ValueError("粘贴内容为空")
    if len(text.splitlines()) > 5000:
        raise ValueError("单次粘贴最多 5000 行")
    return importer.import_text(task_id, source_id, data.get("fmt") or source.get("format", "text"), text)


# --- 远程拉取 ---------------------------------------------------------------
# 凭据只走请求体，不落库；拉取是后台任务，接口立刻返回 job，前端轮询进度。

@app.post("/api/remote/probe")
def remote_probe(data: dict[str, Any]) -> dict[str, Any]:
    """连通性 + 文件清单 + 行数估算 + 样本。同步执行，几秒内返回。"""
    return remote.probe(data)


@app.post("/api/remote/pull", status_code=201)
def remote_pull(data: dict[str, Any]) -> dict[str, Any]:
    task_id = str(data.get("task_id") or "")
    source_id = str(data.get("source_id") or "")
    store.get_task(task_id)
    source = queries.source(source_id)
    fmt = str(data.get("fmt") or source.get("format") or "text")
    encoding = str(data.get("encoding") or "utf-8")
    job = remote.start_pull(data, importer, task_id, source_id, fmt, encoding)
    return job.snapshot()


@app.get("/api/remote/jobs/{job_id}")
def remote_job(job_id: str) -> dict[str, Any]:
    return remote.status(job_id)


@app.post("/api/remote/jobs/{job_id}/cancel")
def remote_job_cancel(job_id: str) -> dict[str, Any]:
    return remote.cancel(job_id)


@app.post("/api/preview")
def preview(data: dict[str, Any]) -> dict[str, Any]:
    source = queries.source(str(data.get("source_id") or ""))
    text = str(data.get("text") or "")
    if len(text.splitlines()) > 5000:
        raise ValueError("预览最多 5000 行")
    template = str(data.get("template") or "").strip()
    if template:
        return web_format.preview(template, text.splitlines())
    return importer.preview(data.get("fmt") or source.get("format", "text"), source["id"], text)


@app.get("/api/formats")
def formats() -> list[dict[str, Any]]:
    return web_format.list_formats()


@app.post("/api/formats", status_code=201)
def create_format(data: dict[str, Any]) -> dict[str, Any]:
    # 前端直接提交模板 JSON：{name, kind, template|pattern, time_format?, types?, source_ids, id?}
    # 带 id 就是编辑，不带就是新建；绑定冲突通过返回体的 detached 告诉前端
    body = data.get("spec") if isinstance(data.get("spec"), dict) else data
    return web_format.save_format(body, data.get("id") or None)


@app.get("/api/sources/custom")
def custom_sources_list() -> list[dict[str, Any]]:
    return custom_sources.list_custom()


@app.post("/api/sources/custom", status_code=201)
def custom_sources_save(data: dict[str, Any]) -> dict[str, Any]:
    builtin = {sid for sid, item in queries.sources.items() if item.get("builtin") is not False}
    item = custom_sources.save_custom(data, builtin)
    queries.reload_sources()
    return item


@app.delete("/api/sources/custom/{source_id}")
def custom_sources_delete(source_id: str) -> dict[str, bool]:
    custom_sources.delete_custom(source_id)
    queries.reload_sources()
    return {"ok": True}


@app.post("/api/formats/preview")
def preview_format(data: dict[str, Any]) -> dict[str, Any]:
    text = str(data.get("text") or "")
    if len(text.splitlines()) > 5000:
        raise ValueError("预览最多 5000 行")
    body = data.get("spec") if isinstance(data.get("spec"), dict) else data
    return web_format.preview_spec(body, text.splitlines())


@app.post("/api/formats/detect")
def detect_format(data: dict[str, Any]) -> dict[str, Any]:
    """粘一行日志，自动认厂商并生成模板 JSON。"""
    return web_format.detect_format(str(data.get("line") or ""))


@app.get("/api/formats/help")
def format_help() -> dict[str, Any]:
    return {"samples": web_format.SAMPLES, "semantic": sorted(web_format.SEMANTIC_TYPES)}


@app.get("/api/formats/presets")
def format_presets() -> list[dict[str, Any]]:
    """内置格式参考：系统已经认识哪些日志形状。"""
    return web_format.presets()


@app.delete("/api/formats/{format_id}")
def remove_format(format_id: str) -> dict[str, bool]:
    web_format.delete_format(format_id)
    return {"ok": True}


@app.post("/api/tasks/{task_id}/query")
def query_logs(task_id: str, data: dict[str, Any]) -> dict[str, Any]:
    store.get_task(task_id)
    result = queries.query(task_id, str(data.get("source_id") or ""), data)
    engine.decorate_rows(result["rows"], result["kind"])
    return result


@app.get("/api/tasks/{task_id}/sources/{source_id}/stats")
def source_stats(task_id: str, source_id: str, dimension: str | None = None, sort: str = "cnt", window_sec: int = 60) -> dict[str, Any]:
    store.get_task(task_id)
    return queries.stats(task_id, source_id, dimension, sort, window_sec)


@app.get("/api/rules")
def rules() -> list[dict[str, Any]]:
    return rule_store.load()


@app.get("/api/rules/errors")
def rule_load_errors() -> list[dict[str, str]]:
    """规则文件加载失败清单，界面据此提示，避免整批规则静默消失。"""
    rule_store.load()
    return rule_store.errors


@app.post("/api/rules", status_code=201)
def create_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return rule_store.save(rule)


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: str, rule: dict[str, Any]) -> dict[str, Any]:
    rule = dict(rule)
    rule["id"] = rule_id
    return rule_store.save(rule)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str) -> dict[str, bool]:
    rule_store.delete(rule_id)
    return {"ok": True}


@app.post("/api/rules/reset")
def reset_rules() -> list[dict[str, Any]]:
    rule_store.reset()
    return rule_store.load()


@app.post("/api/rules/test")
def test_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    return engine.test(data.get("sample") or {}, data.get("kind") or "web")


@app.get("/api/tasks/{task_id}/sources/{source_id}/alerts")
def alerts(task_id: str, source_id: str) -> dict[str, Any]:
    store.get_task(task_id)
    return engine.alerts(task_id, source_id)


app.mount("/", StaticFiles(directory=str(ROOT / "static"), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=int(os.environ.get("LOGVIEW_PORT", "8765")), reload=False, log_level="info")
