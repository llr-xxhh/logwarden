"""生成 sample-data/ 下的三份演示日志。

场景编排成一条能讲通的攻击链：
  203.0.113.45（外部）→ 扫 nginx → SQL 注入探测 → 上传 webshell → 执行命令 → 拖走备份
  同时段 Linux 侧：同一 IP 对 SSH 爆破 → 拿下 ubuntu 账号 → sudo 提权 → 建后门账号
  再横向到 Windows 终端 198.51.100.77 → 4625 爆破 → 4624 成功 → 落地 PowerShell → 装服务

全部使用 RFC 5737 保留地址段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24），
主机名与账号为通用名，不含任何真实环境信息。
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent          # 脚本就在 sample-data/ 里，产物也写这里
OUT.mkdir(exist_ok=True)

random.seed(20261105)          # 固定种子，每次生成同一份数据，便于复现截图

ATTACKER = "203.0.113.45"
SCANNER = "203.0.113.46"     # 扫描器常与后续利用不是同一个 IP，排行里要能分开看
LATERAL = "198.51.100.77"
# 正常访客走内网（站点经反向代理映射到公网，日志里记的是代理侧地址）。
# 这样「外网来源」在结论摘要里只剩攻击者一个，演示时不至于被正常用户淹掉。
CLIENTS = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.21", "10.0.0.22"]
HOST_LINUX = "web-prod-01"
HOST_WIN = "WIN-CLIENT-07"

BASE = datetime(2026, 11, 5, 9, 0, 0)   # 演示当天 09:00 起

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def nginx_ts(dt):
    return dt.strftime("[%d/%b/%Y:%H:%M:%S +0800]")


def syslog_ts(dt):
    # syslog 传统格式补零到两位日期，用两个空格对齐（Nov  5）
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)


def epoch_ms(dt):
    return int(dt.timestamp() * 1000)


# --------------------------------------------------------------------------- nginx
NGINX = []
UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
UA_CURL = "curl/8.4.0"
UA_SQLMAP = "sqlmap/1.8.8#stable (https://sqlmap.org)"
UA_SCAN = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
UA_SHELL = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"

NORMAL_PATHS = ["/", "/index.html", "/about", "/products", "/products/list?page=2",
                "/static/app.css", "/static/app.js", "/static/logo.png",
                "/api/v1/categories", "/api/v1/products?limit=20", "/favicon.ico"]
SCAN_PATHS = ["/admin", "/wp-login.php", "/.env", "/phpmyadmin/", "/backup.zip",
              "/.git/config", "/config.php", "/server-status", "/actuator/env",
              "/console", "/manager/html", "/.aws/credentials", "/db.sql",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]


def add(dt, ip, method, path, status, size, ua, ref="-"):
    NGINX.append((dt, ip, method, path, status, size, ua, ref))


# 09:00-10:10 正常业务，每 30 秒左右一条
t = BASE
while t < BASE + timedelta(minutes=70):
    path = random.choice(NORMAL_PATHS)
    ua = UA_BROWSER if random.random() > 0.15 else UA_CURL
    add(t, random.choice(CLIENTS), "GET", path, 200, random.randint(1200, 48000), ua,
        "https://www.example.com/" if random.random() > 0.6 else "-")
    t += timedelta(seconds=random.randint(12, 55))

# 10:12-10:38 目录扫描：同一 IP，大量 404，路径分散
t = BASE + timedelta(minutes=72)
scan_hits = 0
while t < BASE + timedelta(minutes=98):
    path = random.choice(SCAN_PATHS) + ("?id=1" if random.random() > 0.7 else "")
    add(t, SCANNER, "GET", path,
        404 if random.random() > 0.12 else 403,
        random.randint(150, 600), UA_SCAN)
    scan_hits += 1
    t += timedelta(seconds=random.randint(1, 4))

# 10:40-11:02 SQL 注入探测
t = BASE + timedelta(minutes=100)
payloads = [
    "/product.php?id=1%27%20union%20select%201,2,3,4--",
    "/product.php?id=1%20and%201=1",
    "/product.php?id=1%27%20and%20extractvalue(1,concat(0x7e,database()))--",
    "/search?q=%27%20or%20%271%27%3D%271",
    "/login.php?user=admin%27--&pass=x",
]
while t < BASE + timedelta(minutes=122):
    add(t, ATTACKER, "GET", random.choice(payloads),
        random.choice([200, 500, 500, 302]),
        random.randint(800, 9000), UA_SQLMAP)
    t += timedelta(seconds=random.randint(5, 20))

# 11:05-11:20 试探上传点
t = BASE + timedelta(minutes=125)
for path in ["/upload/", "/upload.php", "/admin/upload", "/uploads/"]:
    add(t, ATTACKER, "GET", path, 200, 2100, UA_SHELL)
    t += timedelta(seconds=40)

# 11:23 webshell 上传成功
add(BASE + timedelta(minutes=143), ATTACKER, "POST", "/upload/shell.php", 200, 342, UA_SHELL)

# 11:26-13:40 webshell 持续执行命令
t = BASE + timedelta(minutes=146)
cmds = ["whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /var/www",
        "cat /var/www/html/config.php", "netstat -antp", "ps aux"]
while t < BASE + timedelta(minutes=280):
    add(t, ATTACKER, "POST", "/upload/shell.php?cmd=" + random.choice(cmds),
        200, random.randint(180, 3200), UA_SHELL)
    t += timedelta(minutes=random.randint(3, 11))

# 14:10-14:16 打包下载备份（超大响应，外带特征）
t = BASE + timedelta(minutes=310)
for _ in range(6):
    add(t, ATTACKER, "GET", "/data/backup.zip", 200,
        random.randint(41_000_000, 52_000_000), UA_CURL)
    t += timedelta(seconds=random.randint(45, 90))

# 15:00 之后恢复正常
t = BASE + timedelta(minutes=360)
while t < BASE + timedelta(minutes=400):
    add(t, random.choice(CLIENTS), "GET", random.choice(NORMAL_PATHS), 200,
        random.randint(1200, 48000), UA_BROWSER)
    t += timedelta(seconds=random.randint(20, 70))

NGINX.sort(key=lambda x: x[0])
with (OUT / "nginx-access.log").open("w", encoding="utf-8", newline="\n") as fp:
    for dt, ip, method, path, status, size, ua, ref in NGINX:
        fp.write('%s - - %s "%s %s HTTP/1.1" %d %d "%s" "%s"\n'
                 % (ip, nginx_ts(dt), method, path, status, size, ref, ua))

# ---------------------------------------------------------------------- auth.log
AUTH = []


def auth(dt, msg, pid=None):
    AUTH.append((dt, msg, pid or random.randint(1000, 32000)))


# 10:05-10:36 SSH 爆破
t = BASE + timedelta(minutes=65)
users = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "www-data"]
while t < BASE + timedelta(minutes=96):
    user = random.choice(users)
    port = random.randint(30000, 65000)
    if user in ("root", "admin", "test", "oracle", "postgres"):
        auth(t, "Failed password for invalid user %s from %s port %d ssh2"
             % (user, ATTACKER, port))
    else:
        auth(t, "Failed password for %s from %s port %d ssh2"
             % (user, ATTACKER, port))
    t += timedelta(seconds=random.randint(5, 14))

# 10:36 爆破成功（落在 ubuntu 账号）
ok_t = BASE + timedelta(minutes=96, seconds=18)
auth(ok_t, "Accepted password for ubuntu from %s port 51882 ssh2" % ATTACKER)
auth(ok_t + timedelta(seconds=3), "pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)")

# 10:40 sudo 提权
auth(BASE + timedelta(minutes=100), "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash")
auth(BASE + timedelta(minutes=100, seconds=2),
     "pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)")

# 11:00 建后门账号
auth(BASE + timedelta(minutes=120), "new user: name=svcbackup, UID=1001, GID=1001, home=/home/svcbackup, shell=/bin/bash")
auth(BASE + timedelta(minutes=120, seconds=40), "new group: name=svcbackup, GID=1001")
auth(BASE + timedelta(minutes=121), "useradd: new user svcbackup added to group sudo")

# 11:02 写 authorized_keys
auth(BASE + timedelta(minutes=122), "pam_unix(sshd:session): session opened for user svcbackup(uid=1001) by (uid=0)")

# 12:30-14:00 持续会话
for minute in range(150, 300, 30):
    auth(BASE + timedelta(minutes=minute), "session opened for user root(uid=0) by ubuntu(uid=1000)", )

AUTH.sort(key=lambda x: x[0])
with (OUT / "linux-auth.log").open("w", encoding="utf-8", newline="\n") as fp:
    for dt, msg, pid in AUTH:
        fp.write("%s %s %s[%d]: %s\n" % (syslog_ts(dt), HOST_LINUX, "sshd", pid, msg))

# ---------------------------------------------------------------- windows 事件 CSV
WIN_HEADERS = ["TimeCreated", "EventID", "Computer", "Channel", "LevelName",
               "TargetUserName", "SubjectUserName", "IpAddress", "LogonType",
               "NewProcessName", "ParentImage", "CommandLine", "TargetFilename",
               "ServiceName", "Message"]
WIN = []


def win(dt, eid, **kw):
    row = {
        "TimeCreated": dt.strftime("%Y-%m-%dT%H:%M:%S.000+08:00"),
        "EventID": eid,
        "Computer": HOST_WIN,
        "Channel": "Security" if eid in (4624, 4625, 4688, 4720, 4726, 4672) else "System",
        "LevelName": "信息",
    }
    row.update(kw)
    WIN.append(row)


# 4625 连续失败（同一来源 IP，5 个账号轮询）
t = BASE + timedelta(minutes=150)
for i in range(28):
    user = ["administrator", "admin", "test", "guest", "finance"][i % 5]
    win(t, 4625,
        TargetUserName=user,
        IpAddress=LATERAL,
        LogonType="3",
        Message="账户登录失败：%s" % user)
    t += timedelta(seconds=random.randint(8, 25))

# 4624 成功（类型 3，网络登录）
win(BASE + timedelta(minutes=158), 4624,
    TargetUserName="administrator",
    IpAddress=LATERAL,
    LogonType="3",
    Message="账户登录成功：administrator，登录类型 3（网络）")

# 4688 执行可疑命令
win(BASE + timedelta(minutes=160), 4688,
    SubjectUserName="administrator",
    NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    ParentImage="C:\\Windows\\System32\\cmd.exe",
    CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA",
    Message="已创建新进程")

# 4720 新建账号
win(BASE + timedelta(minutes=164), 4720,
    TargetUserName="svc_update",
    SubjectUserName="administrator",
    Message="已创建用户账户：svc_update")

# 4726 删除账号（清理痕迹）
win(BASE + timedelta(minutes=168), 4726,
    TargetUserName="svc_update",
    SubjectUserName="administrator",
    Message="已删除用户账户")

# 7045 安装服务（System 日志）
win(BASE + timedelta(minutes=172), 7045,
    ServiceName="WindowsUpdateSvc",
    SubjectUserName="SYSTEM",
    Message="已安装服务 WindowsUpdateSvc，映像路径 C:\\Windows\\Temp\\wusvc.exe")

# 4688 落地另一个进程
win(BASE + timedelta(minutes=180), 4688,
    SubjectUserName="SYSTEM",
    NewProcessName="C:\\Windows\\Temp\\wusvc.exe",
    ParentImage="C:\\Windows\\System32\\services.exe",
    CommandLine="C:\\Windows\\Temp\\wusvc.exe -k net",
    Message="已创建新进程")

WIN.sort(key=lambda r: r["TimeCreated"])
# newline="" 交给 csv 模块自己写行结束符；写成 newline="\r\n" 会得到 \r\r\n，
# 文本模式读回来行数翻倍，Excel 里也会多出空行
with (OUT / "windows-security.csv").open("w", encoding="utf-8", newline="") as fp:
    writer = csv.DictWriter(fp, fieldnames=WIN_HEADERS, extrasaction="ignore",
                            lineterminator="\r\n")
    writer.writeheader()
    for row in WIN:
        writer.writerow({k: row.get(k, "") for k in WIN_HEADERS})

# ------------------------------------------------------------------ 汇总与校验
def count_lines(p):
    return sum(1 for _ in p.open(encoding="utf-8"))


print("生成目录:", OUT)
for name in ("nginx-access.log", "linux-auth.log", "windows-security.csv"):
    p = OUT / name
    print("  %-22s %6.1f KB  %5d 行" % (name, p.stat().st_size / 1024, count_lines(p)))

print("\n时间线（用于 README 与截图说明）")
print("  09:00-10:10  正常业务流量")
print("  10:12-10:38  目录扫描，IP %s，%d 次" % (SCANNER, scan_hits))
print("  10:40-11:02  SQL 注入探测（sqlmap UA）")
print("  11:23        webshell 上传成功 /upload/shell.php")
print("  11:26-13:40  webshell 执行命令 8 类")
print("  14:10-14:16  下载 /data/backup.zip，单次 41-52 MB（外带信号）")
print("  10:05-10:36  SSH 爆破 → 10:36 成功登录 ubuntu → 10:40 sudo → 11:00 建 svcbackup")
print("  11:30-12:26  Windows：28 次 4625 → 4624 成功 → PowerShell -enc → 4720/7045")
