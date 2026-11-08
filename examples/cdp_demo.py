"""LogWarden AI 操盘示例：通过 Chrome DevTools Protocol 直连调试端口。

前置：
  1. 双击 启动.vbs（或 python start.py）——服务会以调试模式拉起浏览器（端口 9223）
  2. pip install playwright && playwright install chromium

**优先用 HTTP API**：建任务、导日志、改规则改模板都是 JSON 接口，一步到位，
不受动画、懒加载、缓存影响。完整接口说明见 skills/logwarden/SKILL.md。
CDP 留给"需要人同步看到界面"的场景——演示、确认布局、让人看着 AI 干活。

这个脚本演示三件事：连上、URL 直达、读状态。
界面的每个状态都有直达 URL，所以大部分操作不用模拟点击。
"""
from playwright.sync_api import sync_playwright

CDP_ENDPOINT = "http://127.0.0.1:9223"   # start.py --debug-port 指定的调试端口
APP_URL_FRAGMENT = "8766"                 # LogWarden 服务端口


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP_ENDPOINT)

        # LogWarden 的页面在启动时已由 start.py 打开，找到它
        page = next(
            (c for c in browser.contexts[0].pages if APP_URL_FRAGMENT in c.url),
            None,
        )
        if page is None:
            raise SystemExit("未找到 LogWarden 页面，请先通过 启动.vbs 启动服务")

        print("已连接:", page.title())

        # ---- 以下是对界面的常规操作，与真人点击等价 ----
        page.bring_to_front()

        # 读侧栏任务列表（DOM 即 API）
        tasks = page.locator(".nav .item").all_inner_texts()
        print("任务列表:", [t.strip().split("\n")[0] for t in tasks])

        # ---- URL 直达：界面每个状态都有地址，比逐级点击可靠 ----
        #   ?pg=alerts|logs|stats|rules|import   直达对应页面
        #   ?evi=1                               打开证据清单抽屉
        #   ?nt=1&sel=nginx,windows              弹新建任务并预勾组件
        #   #<task_id>                           切到指定任务
        # 换成真实任务 id 再跑：
        # page.goto("http://127.0.0.1:8766/?pg=alerts#t_xxxxxxxxxxxx")
        # print("告警页标题:", page.locator("h2").first.inner_text())

        browser.close()  # 只断开 CDP 连接，不关闭用户的浏览器


if __name__ == "__main__":
    main()
