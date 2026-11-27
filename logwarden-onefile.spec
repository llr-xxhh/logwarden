# -*- mode: python ; coding: utf-8 -*-
"""LogWarden onefile 打包配置：单文件 exe，双击即用。

所有只读资源（前端/解析器/内置规则/模板/格式定义）压进 exe 本体，
运行时解到 %TEMP% 只读挂载（sys._MEIPASS）；可写数据（meta.duckdb、
data-duck/、rules/custom/、sources/、formats/、runtime/）仍由 paths.py
定位到 exe 所在目录——数据不进包，换机拷 exe + data 目录即迁移。

与 onedir 版（logwarden.spec）的差异：无 COLLECT，binaries/datas 全部
打进 EXE，启动时多一步自解压（1-3 秒），换来真正的单文件便携。
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="LogWarden-0.9.0",
    console=False,
    disable_windowed_traceback=False,
    upx=False,
)
