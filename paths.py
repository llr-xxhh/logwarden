"""路径定位：只读资源（APP）与可写数据（DATA）分离。

源码运行：两者都指向项目根，行为与旧版完全一致。
PyInstaller 打包：APP 指向解包资源目录（sys._MEIPASS），
DATA 指向 exe 所在目录——任务库（data-duck/、meta.duckdb）、
自定义规则（rules/custom/）、自定义源（sources/）全部留在 exe 旁边，
升级替换 exe 不丢数据。LOGVIEW_DATA_DIR 环境变量仍可覆盖数据目录。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _app() -> Path:
    """只读资源根：前端、解析器、内置规则、模板、格式定义。"""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", "") or Path(sys.executable).resolve().parent)
    return Path(__file__).resolve().parent


def _data() -> Path:
    """可写数据根：LOGVIEW_DATA_DIR > exe 目录（打包） > 项目根（源码）。"""
    env = os.environ.get("LOGVIEW_DATA_DIR")
    if env:
        return Path(env)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP = _app().resolve()
DATA = _data().resolve()
