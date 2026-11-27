# -*- mode: python ; coding: utf-8 -*-
"""LogWarden onedir 打包配置。

只读资源（前端/解析器/内置规则/模板/格式定义）进 _internal，
可写数据（meta.duckdb、data-duck/、rules/custom/、sources/、runtime/）
由 paths.py 定位到 exe 所在目录，不进包。
"""
from pathlib import Path

ROOT = Path(SPECPATH)

datas = [
    (ROOT / "static", "static"),
    (ROOT / "templates", "templates"),
    (ROOT / "parsers", "parsers"),
    (ROOT / "formats", "formats"),
    (ROOT / "rules" / "builtin", "rules/builtin"),
]

hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "python_multipart",
    "services.local_logs",
]

a = Analysis(
    [str(ROOT / "start.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "pytest", "playwright"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="logwarden",
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="logwarden",
)
