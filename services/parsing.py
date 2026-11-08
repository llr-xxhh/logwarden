"""Line-oriented log parsers. Binary conversion belongs outside this module."""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PARSER_DIR = Path(__file__).resolve().parents[1] / "parsers"
ALIASES = {"tomcat": "combined", "evtx": "windows_event", "bash_history": "shell", "auditd": "audit"}
MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^]]+)]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
SYSLOG_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:\[\s]+(?:\s+\([^)]*\))?)(?:\[(?P<pid>\d+)])?:\s*(?P<msg>.*)$")
ISO_SYSLOG_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<proc>[^:\[\s]+(?:\s+\([^)]*\))?)(?:\[(?P<pid>\d+)])?:\s*(?P<msg>.*)$")
# rsyslog 每 20 分钟写一条 "-- MARK --" 心跳：整行只有时间、主机和这个标记，
# 不含任何事件。识别出来直接丢掉，不能算解析失败。
SYSLOG_MARK_RE = re.compile(
    r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+\S+\s+--\s*MARK\s*--\s*$"
)
# rsyslog 的重复抑制：连续相同消息只留一条，后面补 "last message repeated N times"。
# 这行没有 "proc:" 段，但本身是有意义的信息（说明上一条重复了 N 次），不能当坏行丢掉。
SYSLOG_REPEAT_RE = re.compile(r"\blast message repeated \d+ times?\b")
# 设备转发与 rsyslog 中继几乎都会带 <PRI> 前缀（有时叠两层），必须先剥掉再识别
PRI_RE = re.compile(r"^<\d{1,3}>")
# RFC5424：<PRI>VERSION TS HOST APP PROCID MSGID STRUCTURED-DATA [MSG]
RFC5424_RE = re.compile(
    r"^(?P<ver>[1-9]\d?)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?:-|(?:\[[^\]]*])+)(?:\s+(?P<msg>.*))?$"
)
# 防火墙/网络设备常见"没有 program 段"的写法：时间 主机 直接跟内容，没有 proc:
SYSLOG_LOOSE_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s*(?P<msg>.*)$")
ISO_LOOSE_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s*(?P<msg>.*)$")
AUDIT_HEAD_RE = re.compile(r"^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):?(?P<msg>.*)$")
FIELD_RE = re.compile(r"(?P<k>[A-Za-z_][A-Za-z0-9_]*)=(?P<q>[\"']?)(?P<v>.*?)(?P=q)(?:\s+|$)")
# 标准 crontab 行：5 个时间字段（分 时 日 月 周）或 @daily 这类别名，后面才是命令
CRON_LINE_RE = re.compile(r"^(@(?:reboot|yearly|annually|monthly|weekly|daily|hourly|midnight)\b|(?:[\d*/,-]+\s+){4}[\d*/,-]+\s+\S)")


def parser_config(fmt: str) -> dict[str, Any]:
    fmt = ALIASES.get(fmt, fmt)
    # fmt 是用户输入，直接拼路径可以读到 parsers/ 目录之外的任意 .json；
    # 解析器名全是内部短名，白名单之外一律拒绝
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", fmt or ""):
        raise ValueError("不支持的解析格式")
    path = PARSER_DIR / (fmt + ".json")
    if not path.exists():
        raise ValueError("不支持的解析格式: " + fmt)
    return json.loads(path.read_text(encoding="utf-8"))


def epoch_ms(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number < 10000000000:
            number *= 1000
        return int(number)
    text = str(value).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return epoch_ms(float(text))
    try:
        normalized = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return int(dt.timestamp() * 1000)
    except ValueError:
        return None


def combined_time(value: str) -> int | None:
    try:
        return int(datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").timestamp() * 1000)
    except ValueError:
        return None


def syslog_time(value: str) -> int | None:
    match = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}):(\d{2}):(\d{2})", value)
    if not match:
        return epoch_ms(value)
    month, day = MONTHS[match.group(1)], int(match.group(2))
    hour, minute, second = int(match.group(4)), int(match.group(5)), int(match.group(6))
    explicit = match.group(3)
    if explicit:                                    # 部分设备会补年份，直接按本地时区折算
        try:
            return int(datetime(int(explicit), month, day, hour, minute, second).astimezone().timestamp() * 1000)
        except ValueError:
            return None
    now = datetime.now().astimezone()
    for year in range(now.year, now.year - 8, -1):
        try:
            dt = now.replace(year=year, month=month, day=day, hour=hour, minute=minute, second=second, microsecond=0)
        except ValueError:
            continue   # 2 月 29 日这类当年不存在的日期，换一年再试
        if (dt - now).total_seconds() > 86400:
            continue   # 落在未来，说明是去年的日志
        return int(dt.timestamp() * 1000)
    return None


def strip_pri(line: str) -> str:
    """剥掉 <PRI> 前缀；叠了两层的设备日志也能处理。"""
    while True:
        match = PRI_RE.match(line)
        if not match:
            return line
        line = line[match.end():]


def syslog_head(line: str, loose: bool = False) -> dict[str, Any] | None:
    """识别 syslog 头部（RFC3164 / 带年份变体 / RFC5424），返回 ts/host/proc/pid/msg。

    统一入口：syslog 与防火墙解析都走这里，避免两套正则各写一份、各漏一种前缀。
    loose=True 允许缺少 "proc:" 段（防火墙、网络设备的常见写法）；普通 syslog 不开，
    否则任何 "时间 主机 内容" 的行都会被吞成合法日志。
    """
    body = strip_pri(line)
    rfc5424 = RFC5424_RE.match(body)
    if rfc5424:
        return {
            "ts": epoch_ms(rfc5424.group("ts")),
            "host": rfc5424.group("host"),
            "proc": rfc5424.group("app"),
            "pid": integer(rfc5424.group("procid")),
            "msg": (rfc5424.group("msg") or "").lstrip("\ufeff"),
        }
    match = SYSLOG_RE.match(body) or ISO_SYSLOG_RE.match(body)
    if match:
        data = match.groupdict()
        return {
            "ts": syslog_time(data["ts"]) if match.re is SYSLOG_RE else epoch_ms(data["ts"]),
            "host": data.get("host") or "-",
            "proc": data.get("proc") or "-",
            "pid": integer(data.get("pid")),
            "msg": data.get("msg") or "",
        }
    if not loose:
        return None
    loose_match = SYSLOG_LOOSE_RE.match(body) or ISO_LOOSE_RE.match(body)
    if not loose_match:
        return None
    return {
        "ts": syslog_time(loose_match.group("ts")) if loose_match.re is SYSLOG_LOOSE_RE else epoch_ms(loose_match.group("ts")),
        "host": loose_match.group("host") or "-",
        "proc": "-",
        "pid": None,
        "msg": loose_match.group("msg") or "",
    }


def integer(value: Any, default: int | None = None) -> int | None:
    try:
        return default if value in (None, "", "-") else int(value)
    except (TypeError, ValueError):
        return default


def text_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return str(value.get("#text") or value.get("text") or "")
    return str(value)


def plain_value(value: Any) -> Any:
    """带属性的元素在 JSON 里是 {"#attributes": {...}, "#text": "..."}，取值要脱壳。

    System.evtx 里大量事件带 Qualifiers（如 <EventID Qualifiers="16384">1074</EventID>），
    不脱壳就会把 EventID 读成 None，事件名全退化成「Windows 事件」。
    """
    if isinstance(value, dict):
        if value.get("#text") is not None:
            return value.get("#text")
        attrs = value.get("#attributes") or {}
        return attrs.get("SystemTime") or attrs.get("Name") or None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def time_value(value: Any) -> Any:
    """TimeCreated 可能是字符串、{"#attributes": {"SystemTime": ...}} 或已拍平的值。"""
    if isinstance(value, dict):
        attrs = value.get("#attributes") or {}
        return attrs.get("SystemTime") or value.get("#text")
    return value


def pick(data: dict[str, Any], *names: str, default: Any = None) -> Any:
    """按顺序取第一个有值的别名字段，跳过 None / 空串 / "-" / 空容器。"""
    for name in names:
        value = data.get(name)
        if value not in (None, "", "-", [], {}):
            return value
    return default


def pick_text(value: Any) -> str:
    """把可能是字符串、数组或嵌套对象的字段压平成文本。"""
    if isinstance(value, list):
        return ",".join(str(item) for item in value if item not in (None, "", "-"))
    if isinstance(value, dict):
        for key in ("name", "hostname", "host", "fqdn", "value", "#text", "text"):
            if value.get(key) not in (None, "", "-"):
                return str(value[key])
        return ""
    return "" if value is None else str(value)


# Windows 事件 ID 中文名。写进 event 字段供接口与导出报告使用；界面另有同源展示映射。
# 注意同名 ID 在不同日志里含义不同（104 / 1102 都是清日志，属不同日志通道），这里按最常见含义取名。
WINDOWS_EVENT_NAMES: dict[int, str] = {
    # 安全日志 · 登录与会话
    4624: "登录成功", 4625: "登录失败", 4634: "注销", 4647: "用户注销", 4648: "显式凭据登录",
    4649: "重放攻击", 4672: "特权登录", 4776: "凭据验证", 4778: "会话重连", 4779: "会话断开", 4627: "组成员身份",
    4800: "锁定工作站", 4801: "解锁工作站", 4802: "屏保启动", 4803: "屏保停止",
    # 安全日志 · 账户与组
    4720: "创建用户", 4722: "启用账号", 4723: "修改密码", 4724: "重置密码", 4725: "禁用账号",
    4726: "删除用户", 4738: "修改用户", 4740: "账户锁定", 4767: "解锁账号", 4781: "账户改名",
    4782: "密码哈希访问", 4727: "创建全局组", 4728: "加入全局组", 4729: "移出全局组",
    4730: "删除全局组", 4731: "创建本地组", 4732: "加入本地组", 4733: "移出本地组",
    4734: "删除本地组", 4735: "修改本地组", 4737: "修改全局组", 4754: "创建通用组",
    4755: "修改通用组", 4756: "加入通用组", 4757: "移出通用组", 4758: "删除通用组",
    4741: "创建计算机账户", 4742: "修改计算机账户", 4743: "删除计算机账户",
    4764: "组类型变更", 4765: "添加SID历史", 4766: "SID历史添加失败",
    # 安全日志 · Kerberos
    4768: "TGT请求", 4769: "服务票据请求", 4770: "服务票据续期", 4771: "预认证失败",
    4772: "TGT请求失败", 4773: "服务票据请求失败",
    # 安全日志 · 进程与对象
    4688: "创建进程", 4689: "进程退出", 4656: "请求句柄", 4657: "修改注册表值",
    4658: "关闭句柄", 4660: "删除对象", 4662: "对象操作", 4663: "访问对象",
    4670: "对象权限变更", 4673: "特权服务调用", 4674: "特权操作",
    # 安全日志 · 策略与任务
    4713: "Kerberos策略变更", 4716: "信任域信息修改", 4719: "审核策略变更", 4739: "域策略变更",
    4902: "创建审核策略", 4904: "注册事件源", 4905: "注销事件源", 4907: "审核配置变更",
    4908: "特殊组登录配置", 4912: "修改审核策略",
    4697: "安装服务", 4698: "创建计划任务", 4699: "删除计划任务", 4700: "启用计划任务",
    4701: "停用计划任务", 4702: "更新计划任务", 4704: "分配用户权限", 4705: "移除用户权限",
    # 安全日志 · 侦察与凭据
    4793: "密码策略检查", 4794: "设置DSRM密码", 4797: "查询空密码",
    4798: "枚举本地组成员", 4799: "枚举安全组成员", 5379: "读取凭据", 4616: "系统时间更改",
    5058: "密钥文件操作", 5059: "密钥迁移", 5061: "加密操作",
    # 安全日志 · AD 与信任
    4928: "建立复制源", 4929: "移除复制源", 4865: "添加域信任", 4866: "删除域信任",
    4867: "修改域信任", 5136: "修改目录对象", 5137: "创建目录对象", 5138: "恢复目录对象",
    5139: "移动目录对象", 5141: "删除目录对象",
    # 安全日志 · 共享与网络
    5140: "访问共享", 5142: "添加共享", 5143: "修改共享", 5144: "删除共享", 5145: "详细文件共享",
    5152: "WFP拦截数据包", 5154: "WFP允许监听", 5156: "WFP允许连接", 5157: "WFP阻止连接",
    5158: "WFP允许绑定",
    # 安全日志 · 防火墙与证书
    4946: "添加防火墙规则", 4947: "修改防火墙规则", 4948: "删除防火墙规则", 4950: "修改防火墙设置",
    5024: "防火墙服务启动", 5025: "防火墙服务停止", 5031: "防火墙拦截程序",
    4886: "证书请求", 4887: "证书颁发", 4888: "证书拒绝", 4898: "加载证书模板",
    # 安全日志 · 日志服务
    1100: "日志服务关闭", 1102: "清空安全日志", 1104: "日志已满",
    # 系统日志
    41: "未正常关机", 51: "磁盘分页错误", 104: "清空系统日志",
    219: "驱动加载失败", 1001: "崩溃/错误报告", 1074: "关机/重启", 1076: "关机原因",
    6005: "日志服务启动", 6006: "日志服务停止", 6008: "异常关机", 6013: "系统运行时长",
    7023: "服务终止错误", 7024: "服务特定错误", 7026: "启动驱动失败", 7031: "服务崩溃",
    7032: "服务恢复操作", 7034: "服务意外终止", 7036: "服务状态变更", 7040: "服务启动类型",
    7045: "安装新服务", 10016: "DCOM权限错误",
    # 远程桌面连接（RemoteConnectionManager）
    # 1149 只在装了「RD 会话主机」角色的机器上出现；普通 Win10 被连入时只有 261/258。
    # 谁真正登录了要看 Security 的 4624 LogonType=10，不能只指望这一条通道。
    1147: "RDP 连接被拒绝", 1148: "RDP 认证失败", 1149: "RDP 认证成功",
    258: "RDP 监听启动", 261: "RDP 连接到达", 263: "WDDM 图形模式启用",
    # WMI 活动（WMI-Activity）—— 5857 噪声大，5861 才是持久化信号
    5857: "WMI 提供程序加载", 5858: "WMI 提供程序错误", 5860: "WMI 临时事件订阅", 5861: "WMI 永久事件订阅",
    # 代码完整性（CodeIntegrity）—— BYOVD 入口
    3033: "未签名映像被拦截", 3076: "映像签名不符", 3077: "映像签名不受信任",
    # 防火墙规则（Firewall With Advanced Security）
    # 实测 Win10：添加是 2097，删除是 2006；2004/2005 是文档里的添加/修改，不同版本各写各的
    2002: "防火墙设置已更改", 2004: "防火墙规则已添加", 2005: "防火墙规则已修改",
    2006: "防火墙规则已删除", 2009: "防火墙规则处理失败",
    2010: "网络配置文件已更改", 2033: "清空全部防火墙规则", 2097: "防火墙规则已添加",
    # SMB 客户端
    30803: "SMB 连接成功", 31001: "SMB 认证失败", 31002: "SMB 连接失败",
    # SMB 服务端（SMBServer）—— 入站方向：谁连了本机的共享
    551: "SMB 会话认证失败", 1009: "拒绝匿名访问", 1023: "共享启用存取枚举", 1025: "共享可被匿名访问",
    # Sysmon
    1: "创建进程", 2: "改文件时间", 3: "网络连接", 4: "服务状态变更", 5: "进程终止",
    6: "加载驱动", 7: "加载映像", 8: "创建远程线程", 9: "读取磁盘", 10: "访问进程",
    11: "创建文件", 12: "创建/删除注册表", 13: "设置注册表值", 14: "重命名注册表", 15: "创建数据流",
    17: "创建管道", 18: "连接管道", 19: "创建 WMI 筛选器", 20: "WMI 消费者",
    21: "WMI 绑定", 22: "DNS 查询", 23: "删除文件", 24: "剪贴板捕获", 25: "进程篡改",
    26: "删除文件记录", 27: "阻止可执行文件", 28: "阻止文件粉碎", 29: "检测可执行文件",
    # PowerShell
    400: "引擎启动", 403: "引擎停止", 600: "提供程序启动", 800: "管道执行详情",
    4103: "模块日志", 4104: "脚本块日志",
    40961: "引擎启动", 40962: "引擎停止",
}

# 同号 ID 在不同通道含义完全不同。这两个集合只在对应通道里成立：
# 例如 22 在 Sysmon 是 DNS 查询，在 RDP 通道是会话通知；600 在 PowerShell 之外另有含义。
SYSMON_ONLY_IDS = frozenset({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 25, 26, 27, 28, 29})
POWERSHELL_ONLY_IDS = frozenset({400, 403, 600, 800, 4103, 4104, 40961, 40962})
# 新增的扩展通道：这些 ID 只在对应通道里成立，串到别的通道就退回「Windows 事件」。
# 值是该通道在 Channel 字段里的特征子串（小写比较）。
CHANNEL_ONLY_IDS: dict[int, str] = {
    1147: "remoteconnectionmanager", 1148: "remoteconnectionmanager", 1149: "remoteconnectionmanager",
    258: "remoteconnectionmanager", 261: "remoteconnectionmanager", 263: "remoteconnectionmanager",
    3033: "codeintegrity", 3076: "codeintegrity", 3077: "codeintegrity",
    2002: "firewall", 2004: "firewall", 2005: "firewall", 2006: "firewall",
    2009: "firewall", 2010: "firewall", 2033: "firewall", 2097: "firewall",
    5857: "wmi-activity", 5858: "wmi-activity", 5860: "wmi-activity", 5861: "wmi-activity",
    30803: "smbclient", 31001: "smbclient", 31002: "smbclient",
    551: "smbserver", 1009: "smbserver", 1023: "smbserver", 1025: "smbserver",
}
# 同号 ID 撞了全局字典时，按通道覆盖。10/12 在 Sysmon 里是「访问进程 / 创建注册表」，
# 在 Security-Mitigations 里是「缓解措施阻止 / 审计」——必须先看通道再查名字。
CHANNEL_OVERRIDES: dict[str, dict[int, str]] = {
    "security-mitigations": {2: "缓解措施审计", 10: "缓解措施阻止", 12: "缓解措施审计"},
}


def event_name(eid: int, channel: str = "") -> str:
    """按事件 ID 取中文名，有通道信息时排除串号误标。

    没有通道信息（手工 JSON / CSV）时不做限制，保持旧行为。
    """
    name = WINDOWS_EVENT_NAMES.get(eid)
    if name is None:
        return "Windows 事件"
    low = (channel or "").lower()
    for hint, table in CHANNEL_OVERRIDES.items():
        if hint in low:
            overridden = table.get(eid)
            if overridden:
                return overridden
    if not low:
        return name
    if eid in SYSMON_ONLY_IDS and "sysmon" not in low:
        return "Windows 事件"
    if eid in POWERSHELL_ONLY_IDS and "powershell" not in low:
        return "Windows 事件"
    hint = CHANNEL_ONLY_IDS.get(eid)
    if hint and hint not in low:
        return "Windows 事件"
    return name


def flatten_event_data(payload: dict[str, Any]) -> dict[str, Any]:
    """把 EventData / UserData 的 <Data Name="X">值</Data> 展开成 {Name: 值}。

    wevtutil /f:json、evtx 组件产出的都是这种「名值对数组」形状，
    直接 dict(EventData) 只会得到 {'Data': [...]}，字段全丢。
    """
    flat: dict[str, Any] = {}
    for container in ("EventData", "UserData"):
        block = payload.get(container)
        if not isinstance(block, dict):
            continue
        data = block.get("Data")
        items = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            attrs = item.get("#attributes") or {}
            flat[attrs.get("Name") or "Data%d" % index] = item.get("#text")
        # UserData 有时把字段直接写成子元素，没有 Data 包装
        for key, value in block.items():
            if key in ("Data", "#attributes"):
                continue
            if isinstance(value, dict):
                text = value.get("#text")
                if text is not None:
                    flat.setdefault(key, text)
                    continue
                # WMI 这类 provider 在 UserData 下多包一层：
                # {"Operation_StartedOperational": {"ProviderName": ..., "HostProcess": ...}}
                for inner_key, inner_value in value.items():
                    if inner_key.startswith("#"):
                        continue
                    inner_text = inner_value.get("#text") if isinstance(inner_value, dict) else inner_value
                    if not isinstance(inner_text, (list, dict)):
                        flat.setdefault(inner_key, inner_text)
            elif not isinstance(value, list):
                flat.setdefault(key, value)
    return flat


def _first(*values: Any) -> str:
    """取第一个有意义的文本值。

    跳过 None / 空串 / 事件日志里的占位符 "-"——不跳的话 4688 的
    TargetUserName="-" 会把真正的 SubjectUserName 挡掉。
    """
    for value in values:
        text = text_value(plain_value(value)).strip()
        if text and text != "-":
            return text
    return ""


def _compact(*parts: Any) -> str:
    return " · ".join(re.sub(r"\s+", " ", str(p)).strip() for p in parts
                      if p and re.sub(r"\s+", " ", str(p)).strip() not in ("", "-"))


def _top_privileges(text: str, limit: int = 3) -> str:
    """特权列表在 EventData 里是多行制表符分隔，取前几条并压成一行。"""
    items = [x.strip() for x in re.split(r"[\r\n\t]+", text or "") if x.strip()]
    if not items:
        return ""
    head = "、".join(items[:limit])
    return head + ("…+%d" % (len(items) - limit) if len(items) > limit else "")


_NTSTATUS = {
    "0xc000006d": "STATUS_LOGON_FAILURE（用户名或密码错误）",
    "0xc0000064": "STATUS_NO_SUCH_USER（用户不存在）",
    "0xc0000071": "STATUS_PASSWORD_EXPIRED（密码过期）",
    "0xc0000072": "STATUS_ACCOUNT_DISABLED（账号已禁用）",
    "0xc0000234": "STATUS_ACCOUNT_LOCKED_OUT（账号已锁定）",
    "0xc0000022": "STATUS_ACCESS_DENIED（拒绝访问）",
}


def _sockaddr(hexstr: str) -> str:
    """SMBServer 的 ClientAddress 是十六进制 sockaddr：AF(2B) + 端口(2B) + 地址。"""
    h = (hexstr or "").strip().lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        return ""
    try:
        raw = bytes.fromhex(h if len(h) % 2 == 0 else h + "0")
        if len(raw) < 4:
            return ""
        af = int.from_bytes(raw[0:2], "little")
        port = int.from_bytes(raw[2:4], "big")
        if af == 2 and len(raw) >= 8:  # AF_INET
            ip = ".".join(str(b) for b in raw[4:8])
        elif af == 23 and len(raw) >= 24:  # AF_INET6
            import socket as _s
            ip = _s.inet_ntop(_s.AF_INET6, raw[8:24])
        else:
            return ""
        return "%s:%d" % (ip, port) if port else ip
    except Exception:
        return ""


# 各事件类型要拼进摘要的字段，按「谁 / 怎么来的 / 干了什么」组织
_MSG_TEMPLATES = {
    4624: lambda g: _compact("登录成功", g("TargetUserName"), ("类型 " + g("LogonType")) if g("LogonType") else "",
                             "/".join(x for x in (g("LogonProcessName"), g("AuthenticationPackageName")) if x),
                             ("来源 " + g("WorkstationName", "IpAddress")) if g("WorkstationName", "IpAddress") else "",
                             ("进程 " + g("ProcessName")) if g("ProcessName") else ""),
    4625: lambda g: _compact("登录失败", g("TargetUserName"), ("类型 " + g("LogonType")) if g("LogonType") else "",
                             ("来源 " + g("WorkstationName", "IpAddress")) if g("WorkstationName", "IpAddress") else "",
                             ("状态 " + "/".join(x for x in (g("Status"), g("SubStatus")) if x)) if g("Status") else "",
                             ("进程 " + g("ProcessName")) if g("ProcessName") else ""),
    4634: lambda g: _compact("注销", g("TargetUserName"), ("类型 " + g("LogonType")) if g("LogonType") else ""),
    4647: lambda g: _compact("用户主动注销", g("TargetUserName")),
    4648: lambda g: _compact("显式凭据登录", g("SubjectUserName"), ("→ " + g("TargetServerName")) if g("TargetServerName") else "",
                             ("进程 " + g("ProcessName")) if g("ProcessName") else ""),
    4672: lambda g: _compact("特权登录", g("SubjectUserName"), _top_privileges(g("PrivilegeList"))),
    4688: lambda g: _compact("创建进程", g("NewProcessName", "Image"), ("PID " + g("NewProcessId")) if g("NewProcessId") else "",
                             ("父进程 " + g("ParentProcessName")) if g("ParentProcessName") else "",
                             ("命令行 " + g("CommandLine")) if g("CommandLine") else "",
                             ("用户 " + g("SubjectUserName")) if g("SubjectUserName") else "",
                             ("提权 " + g("TokenElevationType")) if g("TokenElevationType") else ""),
    4689: lambda g: _compact("进程退出", ("状态 " + g("Status")) if g("Status") else ""),
    4720: lambda g: _compact("创建用户", g("TargetUserName"), ("操作者 " + g("SubjectUserName")) if g("SubjectUserName") else ""),
    4722: lambda g: _compact("启用账号", g("TargetUserName")),
    4723: lambda g: _compact("用户改密码", g("TargetUserName")),
    4724: lambda g: _compact("重置密码", g("TargetUserName"), ("操作者 " + g("SubjectUserName")) if g("SubjectUserName") else ""),
    4725: lambda g: _compact("禁用账号", g("TargetUserName")),
    4726: lambda g: _compact("删除用户", g("TargetUserName"), ("操作者 " + g("SubjectUserName")) if g("SubjectUserName") else ""),
    4732: lambda g: _compact("加入本地组", g("MemberName"), ("→ " + g("GroupName")) if g("GroupName") else ""),
    4733: lambda g: _compact("移出本地组", g("MemberName"), ("← " + g("GroupName")) if g("GroupName") else ""),
    4738: lambda g: _compact("修改用户", g("TargetUserName")),
    4767: lambda g: _compact("解锁账号", g("TargetUserName")),
    4771: lambda g: _compact("Kerberos 预认证失败", g("TargetUserName"), ("来源 " + g("IpAddress")) if g("IpAddress") else "",
                             ("状态 " + g("Status")) if g("Status") else ""),
    4776: lambda g: _compact("凭据验证", g("TargetUserName"), ("来源 " + g("Workstation")) if g("Workstation") else "",
                             ("状态 " + g("Status")) if g("Status") else ""),
    4798: lambda g: _compact("枚举本地组成员", g("TargetUserName"), ("调用者 " + g("CallerProcessName")) if g("CallerProcessName") else "",
                             ("操作者 " + g("SubjectUserName")) if g("SubjectUserName") else ""),
    4799: lambda g: _compact("枚举安全启用组成员", g("TargetUserName"), ("调用者 " + g("CallerProcessName")) if g("CallerProcessName") else ""),
    4627: lambda g: _compact("组成员身份", g("TargetUserName"), g("MemberName")),
    5058: lambda g: _compact("密钥操作", g("SubjectUserName"), g("AlgorithmName"), g("KeyName")),
    5059: lambda g: _compact("密钥迁移", g("SubjectUserName"), g("KeyName")),
    5061: lambda g: _compact("加密操作", g("SubjectUserName"), g("AlgorithmName"), g("KeyName")),
    5379: lambda g: _compact("读取凭据", g("SubjectUserName"), g("TargetName")),
    1102: lambda g: _compact("清空安全日志", ("操作者 " + g("SubjectUserName")) if g("SubjectUserName") else ""),
    5140: lambda g: _compact("访问共享", g("ShareName"), g("ObjectName"), ("来源 " + g("IpAddress")) if g("IpAddress") else ""),
    5145: lambda g: _compact("访问共享文件", g("ShareName"), g("RelativeTargetName"), ("来源 " + g("IpAddress")) if g("IpAddress") else ""),
    5156: lambda g: _compact("网络连接放行", "%s:%s → %s:%s" % (g("SourceAddress"), g("SourcePort"), g("DestAddress"), g("DestPort"))),
    5157: lambda g: _compact("网络连接阻止", "%s:%s → %s:%s" % (g("SourceAddress"), g("SourcePort"), g("DestAddress"), g("DestPort"))),
    7045: lambda g: _compact("安装服务", g("ServiceName"), g("ImagePath"),
                             ("类型 " + g("ServiceType")) if g("ServiceType") else "",
                             ("启动 " + g("StartType")) if g("StartType") else ""),
    7040: lambda g: _compact("服务启动类型变更", g("param1"), ("→ " + g("param2")) if g("param2") else ""),
    7036: lambda g: _compact("服务状态变更", g("param1"), ("→ " + g("param2")) if g("param2") else ""),
    7034: lambda g: _compact("服务意外终止", g("param1")),
    1074: lambda g: _compact("关机/重启", g("param1"), g("param2"), ("进程 " + g("param3")) if g("param3") else ""),
    4103: lambda g: _compact("模块日志", g("Payload")),
    4104: lambda g: _compact("脚本块", g("ScriptBlockText")),
    600: lambda g: _compact("提供程序启动", g("param1")),
    # 扩展通道：这些 provider 不做消息渲染，RenderingInfo.Message 是空的，
    # 不自己拼的话整列消息全是空字符串。
    5857: lambda g: _compact("WMI 提供程序加载", g("ProviderName"), ("进程 " + g("HostProcess")) if g("HostProcess") else ""),
    5858: lambda g: _compact("WMI 提供程序错误", g("ProviderName"), g("Code")),
    5861: lambda g: _compact("WMI 永久事件订阅", g("Consumer"), g("Query")),
    2097: lambda g: _compact("添加防火墙规则", g("RuleName"), g("EmbeddedContext")),
    2004: lambda g: _compact("添加防火墙规则", g("RuleName")),
    2006: lambda g: _compact("删除防火墙规则", g("RuleName")),
    2002: lambda g: _compact("防火墙设置更改",
                            ("类型 " + g("SettingType")) if g("SettingType") else "", g("SettingValueDisplay")),
    2010: lambda g: _compact("网络配置文件变更", g("InterfaceName")),
    2033: lambda g: "清空全部防火墙规则",
    3033: lambda g: _compact("未签名映像被拦截", g("FileNameBuffer", "File Name", "FileName"),
                            ("进程 " + g("ProcessNameBuffer")) if g("ProcessNameBuffer") else ""),
    261: lambda g: _compact("RDP 连接到达", g("ListenerName")),
    263: lambda g: "WDDM 图形模式启用",
    1149: lambda g: _compact("RDP 认证成功", g("Param1", "UserName"), g("Param3", "Address")),
    551: lambda g: _compact("SMB 会话认证失败",
                            ("客户端 " + _sockaddr(g("ClientAddress"))) if _sockaddr(g("ClientAddress")) else "",
                            _NTSTATUS.get((g("Status") or "").lower(), g("Status"))),
    1009: lambda g: _compact("拒绝匿名访问", g("ClientAddress") and ("客户端 " + (_sockaddr(g("ClientAddress")) or g("ClientAddress")))),
}

# 已经映射成独立列的字段，不再重复进 detail
_MAPPED_FIELDS = {
    "TargetUserName", "SubjectUserName", "TargetUserSid", "TargetSid", "SubjectUserSid",
    "IpAddress", "SourceNetworkAddress", "LogonType",
    "NewProcessName", "Image", "ProcessName", "CallerProcessName",
    "CommandLine", "ParentProcessName", "ParentImage", "CreatorProcessName",
    "TargetFilename", "TargetObject", "ServiceName", "TaskName", "ShareName", "ObjectName",
}
# 这些是事件头部字段，不是事件内容。合成摘要和 detail 时都要排除，
# 否则兜底会拼出「EventID=5857 · Computer=DESKTOP · Channel=…」这种废话。
_SYSTEM_KEYS = frozenset({
    "EventID", "Computer", "TimeCreated", "Level", "Channel", "Provider",
    "EventRecordID", "Keywords", "Task", "Opcode", "Version", "Security",
    "EventData", "UserData", "System", "#attributes",
})


def compose_message(eid: int, data: dict[str, Any]) -> str:
    """按事件类型把 EventData 拼成一句人能读的摘要。

    EVTX 二进制不存渲染后的消息文本（Message 需要调 Windows API 现场生成），
    不合成的话「消息」列全是空的，界面上只能看到事件 ID 和账号。
    """
    def g(*names: str) -> str:
        return _first(*(data.get(n) for n in names))

    template = _MSG_TEMPLATES.get(eid)
    if template:
        text = template(g)
        if text:
            return text
    # 未收录的事件：挑几个有值且短的字段兜底。SID 和超长值对读者没意义，
    # 直接跳过——否则一条 5058 会被 SID 撑成四行。
    parts = []
    for name, value in data.items():
        if name == "#attributes" or name in _SYSTEM_KEYS:
            continue
        if not isinstance(value, (str, int, float)):
            continue
        text = text_value(plain_value(value)).strip()
        if not text or text == "-":
            continue
        if re.fullmatch(r"S-1-(?:\d+-)+\d+", text):
            continue
        if len(text) > 80:
            continue
        parts.append("%s=%s" % (name, text))
        if len(parts) >= 3:
            break
    return " · ".join(parts)[:160]


def build_detail(data: dict[str, Any]) -> str:
    """把没映射成列的 EventData 字段收进 JSON，给详情面板用。

    白名单维护不动的事件类型太多，这里用「排除已映射 + 去掉空值」的方式，
    新事件类型不用改代码也能带上全部上下文。
    """
    detail = {}
    for name, value in data.items():
        if name == "#attributes" or name in _MAPPED_FIELDS or name in _SYSTEM_KEYS:
            continue
        if not isinstance(value, (str, int, float)):
            continue
        text = text_value(plain_value(value)).strip()
        if not text or text == "-":
            continue
        detail[name] = text[:300]
    return json.dumps(detail, ensure_ascii=False, separators=(",", ":")) if detail else ""


def event_record(data: dict[str, Any]) -> dict[str, Any]:
    system = data.get("System") if isinstance(data.get("System"), dict) else {}
    event_data = data.get("EventData") if isinstance(data.get("EventData"), dict) else {}
    flat = dict(event_data)
    flat.update(flatten_event_data(data))
    flat.update(data)
    eid = integer(plain_value(flat.get("eventId") or flat.get("EventID") or system.get("EventID")))
    ts = epoch_ms(time_value(flat.get("ts") or flat.get("TimeCreated") or flat.get("UtcTime") or flat.get("timestamp") or system.get("TimeCreated")))
    channel = text_value(flat.get("Channel") or system.get("Channel"))

    message = text_value(flat.get("msg") or flat.get("Message") or flat.get("message"))
    command = _first(flat.get("cmdline"), flat.get("CommandLine"))
    image = _first(flat.get("image"), flat.get("NewProcessName"), flat.get("Image"),
                   flat.get("ProcessName"), flat.get("CallerProcessName"))
    if not message:
        # 传 flat 而不是 event_data：WMI 这类把字段嵌在 UserData 下一层，
        # 原始块里拿不到 ProviderName，展开后的 flat 才有。
        message = compose_message(eid, flat)
    if not message:
        message = " ".join(x for x in (image, command) if x)
    level = text_value(plain_value(flat.get("level") or flat.get("LevelName") or flat.get("Level") or "信息"))
    level = {"1": "严重", "2": "错误", "3": "警告", "4": "信息", "0": "信息"}.get(level, level)
    return {
        "ts": ts,
        "host": text_value(flat.get("host") or flat.get("Computer") or system.get("Computer")),
        "eventId": eid,
        "level": level,
        "user": _first(flat.get("user"), flat.get("TargetUserName"), flat.get("SubjectUserName"), flat.get("User")),
        "srcip": _first(flat.get("srcip"), flat.get("IpAddress"), flat.get("SourceNetworkAddress"), flat.get("SourceIp")) or "-",
        "logonType": _first(flat.get("logonType"), flat.get("LogonType")) or "-",
        "msg": message,
        "kind": text_value(flat.get("kind") or "脚本块" if eid in (4103, 4104) else flat.get("kind") or ""),
        "text": text_value(flat.get("text") or flat.get("ScriptBlockText") or message),
        "event": text_value(flat.get("event") or event_name(eid, channel)),
        "image": image,
        "cmdline": command,
        "target": _first(flat.get("target"), flat.get("TargetFilename"), flat.get("TargetObject"),
                         flat.get("ServiceName"), flat.get("TaskName"), flat.get("ShareName"),
                         flat.get("ObjectName"), flat.get("QueryName"), flat.get("DestinationIp")),
        "parent": _first(flat.get("parent"), flat.get("ParentImage"), flat.get("ParentProcessName"),
                         flat.get("CreatorProcessName")),
        "sid": _first(flat.get("TargetUserSid"), flat.get("TargetSid"), flat.get("SubjectUserSid"), flat.get("sid")),
        "detail": build_detail(flat),
    }


def xml_event(element: ET.Element) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for child in element.iter():
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "EventID":
            data["EventID"] = child.text
        elif tag == "Computer":
            data["Computer"] = child.text
        elif tag == "TimeCreated":
            data["TimeCreated"] = child.attrib.get("SystemTime")
        elif tag == "Level":
            data["Level"] = child.text
        elif tag == "Channel":
            data["Channel"] = child.text
        elif tag == "Data":
            data[child.attrib.get("Name", "Data")] = child.text or ""
    return event_record(data)


class LogParser:
    def __init__(self, fmt: str, source_id: str = ""):
        self.config = parser_config(fmt)
        self.fmt = self.config["id"]
        self.source_id = source_id
        self.w3c_fields: list[str] = []
        self.pending_shell_ts: int | None = None
        self.csv_headers: list[str] | None = None
        self.csv_buffer = ""
        self.xml_parser: ET.XMLPullParser | None = None
        self.xml_lines: list[str] = []
        # 该源挂了自定义 log_format 就用模板解析，否则走内置 combined
        self.web_format = None
        if self.fmt == "combined" and source_id:
            from services.web_format import compile_item, format_for_source

            item = format_for_source(source_id)
            if item:
                self.web_format = compile_item(item)

    def template_columns(self) -> dict[str, str]:
        """模板会产出的额外列及其类型；没有模板时返回空字典。

        导入前据此给 raw 表补列，模板里多一个变量就多一个可统计的字段。
        """
        if not self.web_format:
            return {}
        known = set(self.config.get("fields") or ())
        return {name: ctype for name, ctype in (self.web_format.get("columns") or {}).items() if name not in known}

    def parse_line(self, line: str, line_no: int) -> list[dict[str, Any]]:
        if not line.strip():
            return []
        if self.fmt == "combined":
            return [self.parse_combined(line)]
        if self.fmt == "w3c":
            return self.parse_w3c(line)
        if self.fmt == "syslog":
            record = self.parse_syslog(line)
            # None 表示这是 rsyslog 心跳这类控制行：不产生记录，也不算解析失败
            return [] if record is None else [record]
        if self.fmt == "audit":
            return [self.parse_audit(line)]
        if self.fmt == "shell":
            return self.parse_shell(line)
        if self.fmt == "windows_event":
            return self.parse_windows(line)
        if self.fmt == "firewall":
            return [self.parse_firewall(line)]
        if self.fmt == "json":
            return [self.parse_json(line)]
        return [self.parse_text(line)]

    def parse_combined(self, line: str) -> dict[str, Any]:
        if self.web_format:
            from services.web_format import parse_line as parse_web_line

            return parse_web_line(self.web_format, line)
        match = COMBINED_RE.match(line)
        if not match:
            raise ValueError("combined 格式不匹配")
        request = match.group("request")
        parts = request.split(" ", 2)
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else request
        return {
            "ts": combined_time(match.group("ts")),
            "ip": match.group("ip"),
            "method": method,
            "path": path,
            "status": integer(match.group("status"), 0),
            "bytes": integer(match.group("bytes"), 0),
            "ua": match.group("ua") or "-",
            "ref": match.group("ref") or "-",
        }

    def parse_w3c(self, line: str) -> list[dict[str, Any]]:
        if line.startswith("#"):
            if line.lower().startswith("#fields:"):
                self.w3c_fields = line.split(":", 1)[1].strip().split()
            return []
        if not self.w3c_fields:
            raise ValueError("W3C 文件缺少 #Fields 头")
        values = line.split()
        if len(values) != len(self.w3c_fields):
            raise ValueError("W3C 数据列数与 #Fields 不一致：应有 %d 列，实际 %d 列" % (len(self.w3c_fields), len(values)))
        item = dict(zip(self.w3c_fields, values))
        date = item.get("date", "")
        clock = item.get("time", "")
        path = item.get("cs-uri-stem", "")
        query = item.get("cs-uri-query", "")
        if query and query != "-":
            path += "?" + query
        return [{
            "ts": epoch_ms(date + "T" + clock + "+00:00"),
            "ip": item.get("c-ip") or item.get("s-ip") or "-",
            "method": item.get("cs-method") or "-",
            "path": path,
            "status": integer(item.get("sc-status"), 0),
            "bytes": integer(item.get("sc-bytes"), 0),
            "ua": item.get("cs(User-Agent)") or "-",
            "ref": item.get("cs(Referer)") or "-",
        }]

    def parse_syslog(self, line: str) -> dict[str, Any] | None:
        # rsyslog 每 20 分钟写一条 "-- MARK --"，纯心跳、不含事件。
        # 原来它会撞上「proc 后必须有冒号」而判成解析失败，一天攒 72 条假错误，
        # 把真正的坏行淹掉。这里直接跳过，且不计入失败。
        if SYSLOG_MARK_RE.match(strip_pri(line)):
            return None
        head = syslog_head(line)
        if not head and SYSLOG_REPEAT_RE.search(line):
            # 重复折叠行没有 "proc:" 段，退回宽松模式保住时间与主机
            head = syslog_head(line, loose=True)
        if not head:
            raise ValueError("syslog 格式不匹配")
        message = head["msg"]
        ts = head["ts"]
        user = ""
        srcip = "-"
        result = "正常"
        accepted = re.search(r"Accepted\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)", message, re.I)
        failed = re.search(r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)", message, re.I)
        if accepted or failed:
            found = accepted or failed
            user, srcip = found.group(1), found.group(2)
            result = "成功" if accepted else "失败"
        elif re.search(r"authentication failure|maximum authentication attempts|Failed password", message, re.I):
            result = "失败"
        sudo = re.search(r"sudo:\s*(\S+)\s*:", message)
        if sudo:
            user = sudo.group(1)
        new_user = re.search(r"new user:\s*name=([^,\s]+)", message)
        if new_user:
            user = new_user.group(1)
        ip_match = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", message)
        if srcip == "-" and ip_match:
            srcip = ip_match.group(1)
        level = "warn" if result == "失败" else "info"
        return {"ts": ts, "host": head["host"] or "-", "proc": head["proc"] or "-", "pid": head["pid"], "user": user or "-", "srcip": srcip, "result": result, "level": level, "msg": message}

    def parse_audit(self, line: str) -> dict[str, Any]:
        match = AUDIT_HEAD_RE.match(line)
        if not match:
            raise ValueError("auditd 格式不匹配")
        message = match.group("msg").strip()
        fields = {m.group("k"): m.group("v") for m in FIELD_RE.finditer(message)}
        return {
            "ts": epoch_ms(match.group("epoch")),
            "host": fields.get("hostname") or fields.get("node") or "-",
            "type": match.group("type"),
            "key": fields.get("key") or "-",
            "comm": fields.get("comm") or "-",
            "exe": fields.get("exe") or "-",
            "msg": message,
        }

    def parse_shell(self, line: str) -> list[dict[str, Any]]:
        stripped = line.strip()
        timestamp = re.fullmatch(r"#(\d{9,13})", stripped)
        if timestamp:
            self.pending_shell_ts = epoch_ms(timestamp.group(1))
            return []
        if not stripped or stripped.startswith("#"):
            return []
        source = "cron" if CRON_LINE_RE.match(stripped) else "history"
        ts = self.pending_shell_ts
        self.pending_shell_ts = None
        return [{"ts": ts, "host": "-", "user": "-", "source": source, "cmd": stripped}]

    def parse_windows(self, line: str) -> list[dict[str, Any]]:
        stripped = line.strip()
        if self.xml_parser is None and self.csv_headers is None and stripped.startswith("{"):
            payload = json.loads(stripped)
            # wevtutil /f:json、evtx 组件出来的是 {"Event": {...}}，比裸事件多一层壳
            if isinstance(payload, dict) and isinstance(payload.get("Event"), dict):
                payload = payload["Event"]
            return [event_record(payload)]
        if stripped.startswith("<") or self.xml_parser is not None:
            if self.xml_parser is None:
                self.xml_parser = ET.XMLPullParser(["end"])
                # 导出的事件流是多个 <Event> 根元素平铺（wevtutil /f:xml、ToXml 输出都这样），
                # 不包虚拟根节点，expat 会把第二个 <Event> 报成 junk after document element
                self.xml_parser.feed("<logview-stream>")
            self.xml_lines.append(line)
            self.xml_parser.feed(line)
            result = []
            for _, element in self.xml_parser.read_events():
                if element.tag.rsplit("}", 1)[-1] == "Event":
                    record = xml_event(element)
                    record["_raw"] = "".join(self.xml_lines).rstrip("\r\n")
                    self.xml_lines = []
                    result.append(record)
                    element.clear()
            return result
        if self.csv_headers is None and "EventID" in stripped and "," in stripped:
            self.csv_headers = next(csv.reader([line], strict=True))
            return []
        if self.csv_headers is not None:
            self.csv_buffer += line
            try:
                values = next(csv.reader([self.csv_buffer], strict=True))
            except csv.Error as exc:
                if "unexpected end of data" in str(exc).lower():
                    return []
                self.csv_buffer = ""
                raise
            self.csv_buffer = ""
            if len(values) != len(self.csv_headers):
                raise ValueError("Windows CSV 列数不一致")
            return [event_record(dict(zip(self.csv_headers, values)))]
        raise ValueError("Windows 事件支持 JSON 行、XML 或 CSV 导出；EVTX 请先转换")

    def finalize(self) -> list[dict[str, Any]]:
        """Flush streaming formats at EOF; truncated XML/CSV must never look successful."""
        if self.xml_parser is not None:
            self.xml_parser.feed("</logview-stream>")
            self.xml_parser.close()
            result = []
            for _, element in self.xml_parser.read_events():
                if element.tag.rsplit("}", 1)[-1] == "Event":
                    record = xml_event(element)
                    record["_raw"] = "".join(self.xml_lines).rstrip("\r\n")
                    result.append(record)
                    element.clear()
            self.xml_lines = []
            return result
        if self.csv_buffer.strip():
            self.csv_buffer = ""
            raise ValueError("Windows CSV 在文件末尾存在未闭合字段")
        return []

    def parse_json(self, line: str) -> dict[str, Any]:
        data = json.loads(line)
        if not isinstance(data, dict):
            raise ValueError("JSON 日志每行必须是对象")
        obj = data.get("objectRef") if isinstance(data.get("objectRef"), dict) else {}
        response = data.get("responseStatus") if isinstance(data.get("responseStatus"), dict) else {}
        # 字段名由各应用自己定，这里列常见别名而不是只认一套，否则 @timestamp / _time 会整列丢失
        raw_host = pick(data, "host", "hostname", "hostName", "node", "server", "computer", "Computer", "sourceIPs")
        proc = pick(data, "proc", "stream", "verb", "logger", "logger_name", "service", "component") or obj.get("resource") or "-"
        message = pick(data, "msg", "message", "log", "content", "text", "body") or response.get("message") or line.strip()
        return {
            "ts": epoch_ms(pick(data, "ts", "time", "timestamp", "@timestamp", "_time", "event_time", "eventTime", "log_time", "datetime", "startTime", "utc_time", "stageTimestamp")),
            "host": pick_text(raw_host) or "-",
            "proc": text_value(proc),
            "level": text_value(pick(data, "level", "severity", "stream", "loglevel", "log_level", "priority") or "info"),
            "msg": text_value(message),
        }

    def parse_firewall(self, line: str) -> dict[str, Any]:
        """Parse common firewall syslog with vendor-specific key=value fields."""
        head = syslog_head(line, loose=True)
        if head:
            message = head["msg"] or line.strip()
            ts = head["ts"]
            host = head["host"] or "-"
        else:
            message = strip_pri(line).strip()
            ts = None
            host = "-"
        fields = {m.group("k").lower(): m.group("v") for m in FIELD_RE.finditer(message)}
        if ts is None:
            # FortiGate 这类设备把日期拆在 date= / time= 两个字段里，比 syslog 头更准
            day, clock = fields.get("date"), fields.get("time")
            if day and clock:
                ts = epoch_ms(day.replace("/", "-") + "T" + clock)

        def get(*names: str, default: str = "-") -> str:
            for name in names:
                if fields.get(name) not in (None, ""):
                    return fields[name]
            return default

        action = get("action", "act", "policy_action", default="unknown").lower()
        if action in ("allow", "permit", "pass", "accepted"):
            action = "accept"
        elif action in ("drop", "reject", "block", "blocked"):
            action = "deny"
        return {
            "ts": ts,
            "host": get("devicename", "device_name", "hostname", default=host),
            "vendor": get("vendor", "manufacturer", default="防火墙"),
            "action": action,
            "protocol": get("proto", "protocol", "ip_protocol", default="-").upper(),
            "srcip": get("src", "srcip", "src_ip", "source", "source_ip"),
            "srcport": integer(get("spt", "srcport", "src_port", "source_port", default=""), None),
            "dstip": get("dst", "dstip", "dst_ip", "destination", "destination_ip"),
            "dstport": integer(get("dpt", "dstport", "dst_port", "destination_port", default=""), None),
            "rule": get("rule", "rule_name", "policy", "policy_name"),
            "msg": message,
        }

    def parse_text(self, line: str) -> dict[str, Any]:
        ts = None
        message = line.rstrip("\r\n")
        iso = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*(.*)$", message)
        if iso:
            ts = epoch_ms(iso.group(1))
            message = iso.group(2)
        level_match = re.search(r"\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b", message, re.I)
        level = level_match.group(1).upper() if level_match else "info"
        return {"ts": ts, "host": "-", "proc": "-", "level": level, "msg": message}
