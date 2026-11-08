"""Start the local service and open an isolated debug browser.

Usage: python start.py [--browser auto|chrome|edge|firefox|none]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "runtime"
RUNTIME.mkdir(exist_ok=True)


def say(text: str) -> None:
    """pythonw 下 sys.stdout 为 None，直接 print 会抛异常。"""
    stream = sys.stdout
    if stream is not None:
        try:
            print(text)
        except OSError:
            pass


def notify_error(message: str) -> None:
    """无控制台启动时，把失败原因写盘并弹窗，否则用户看不到任何反馈。"""
    try:
        (RUNTIME / "last-error.txt").write_text(message, encoding="utf-8")
    except OSError:
        pass
    if os.name != "nt" or not sys.executable.lower().endswith("pythonw.exe"):
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, "LogWarden 启动失败", 0x10)
    except Exception:
        pass


def healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/health" % port, timeout=1) as response:
            data = json.loads(response.read().decode("utf-8"))
            return response.status == 200 and data.get("ok") is True and data.get("app") == "logwarden"
    except (OSError, ValueError, UnicodeError):
        return False


def start_service(port: int) -> subprocess.Popen | None:
    if healthy(port):
        return None
    log_path = RUNTIME / "server.log"
    log = log_path.open("a", encoding="utf-8")
    env = dict(os.environ)
    env["LOGVIEW_PORT"] = str(port)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "app.py")],
        cwd=str(ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=flags,
    )
    log.close()
    (RUNTIME / "server.json").write_text(json.dumps({"pid": process.pid, "port": port}, indent=2), encoding="utf-8")
    for _ in range(60):
        if healthy(port):
            return process
        if process.poll() is not None:
            raise RuntimeError("后端启动失败，请查看 runtime/server.log")
        time.sleep(0.25)
    raise RuntimeError("后端启动超时，请查看 runtime/server.log")


def browser_candidates(name: str) -> list[str]:
    paths = []
    if name == "chrome":
        paths = [r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]
    elif name == "edge":
        paths = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"]
    elif name == "firefox":
        paths = [r"C:\Program Files\Mozilla Firefox\firefox.exe", r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"]
    executable = {"chrome": "chrome", "edge": "msedge", "firefox": "firefox"}[name]
    found = shutil.which(executable)
    if found:
        paths.insert(0, found)
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    if name == "chrome":
        paths.append(str(local / "Google" / "Chrome" / "Application" / "chrome.exe"))
    if name == "edge":
        paths.append(str(local / "Microsoft" / "Edge" / "Application" / "msedge.exe"))
        for base in (Path(r"C:\Program Files (x86)\Microsoft\EdgeCore"), Path(r"C:\Program Files\Microsoft\EdgeCore"), local / "Microsoft" / "EdgeCore"):
            if base.exists():
                paths.extend(str(path) for path in sorted(base.glob("*/msedge.exe"), reverse=True))
    if name == "firefox":
        paths.append(str(local / "Mozilla Firefox" / "firefox.exe"))
    result = []
    for path in paths:
        if path and Path(path).exists() and path not in result:
            result.append(path)
    return result


def start_browser(name: str, debug_port: int, url: str) -> tuple[str, str]:
    names = ["chrome", "edge", "firefox"] if name == "auto" else [name]
    tried = []
    found_any = False
    for candidate in names:
        paths = browser_candidates(candidate)
        if not paths:
            tried.append(candidate + ": 未安装")
            continue
        found_any = True
        executable = paths[0]
        profile = RUNTIME / ("browser-" + candidate)
        profile.mkdir(exist_ok=True)
        if candidate == "firefox":
            args = [executable, "--remote-debugging-port", str(debug_port), "--profile", str(profile), "--new-window", url]
        else:
            args = [executable, "--remote-debugging-port=%d" % debug_port, "--user-data-dir=%s" % profile, "--no-first-run", "--no-default-browser-check", "--new-window", url]
        try:
            process = subprocess.Popen(args, cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            tried.append(candidate + ": 启动失败 (" + str(exc) + ")")
            continue
        time.sleep(1.2)
        if process.poll() is None:
            return candidate, executable
        tried.append(candidate + ": 启动后立即退出")
    if found_any:
        raise RuntimeError("浏览器启动失败；已尝试 " + "，".join(tried))
    raise RuntimeError("未找到 Chrome、Edge 或 Firefox；可用 --browser none 只启动服务")


def check_deps() -> None:
    """换机回退到系统 Python 时，依赖多半还没装；提前查出来弹窗说清楚，
    不让用户去 runtime\\server.log 里翻 ImportError。"""
    import importlib.util

    required = {"duckdb": "duckdb", "fastapi": "fastapi", "uvicorn": "uvicorn", "multipart": "python-multipart"}
    missing = [pkg for module, pkg in required.items() if importlib.util.find_spec(module) is None]
    if missing:
        raise RuntimeError(
            "Python 依赖未安装：%s\n\n请在本目录执行：\n  python -m pip install -r requirements.txt"
            % "、".join(missing)
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="启动 LogWarden 与调试浏览器")
    parser.add_argument("--browser", choices=["auto", "chrome", "edge", "firefox", "none"], default="auto")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--debug-port", type=int, default=9223)
    args = parser.parse_args()
    check_deps()
    start_service(args.port)
    url = "http://127.0.0.1:%d" % args.port
    say("LogWarden: " + url)
    if args.browser != "none":
        name, executable = start_browser(args.browser, args.debug_port, url)
        say("浏览器: %s (%s)" % (name, executable))
        if name != "firefox":
            say("调试端点: http://127.0.0.1:%d/json/version" % args.debug_port)
        else:
            say("远程调试端口: %d (WebDriver BiDi)" % args.debug_port)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        notify_error("%s\n\n日志：runtime\\server.log" % exc)
        raise SystemExit(1)
