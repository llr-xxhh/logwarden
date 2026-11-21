"""静态文件响应：统一加 no-cache，杜绝浏览器启发式缓存导致的"更新后还是老界面"。

StaticFiles 默认只发 ETag / Last-Modified，不发 Cache-Control。按 RFC 7234，
浏览器会按 Last-Modified 做启发式缓存（常见取文件年龄的 10%）——index.html
半个月没改过，浏览器可能几天内连协商请求都不发，版本更新后用户仍看老界面，
Ctrl+F5 才能救。no-cache 强制每次协商（命中 ETag 回 304），本地回环无感知。
"""
from __future__ import annotations

from starlette.staticfiles import StaticFiles


class NoCacheStatic(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response
