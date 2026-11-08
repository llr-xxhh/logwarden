# 演练数据

一套合成的入侵排查演练日志，用来在没有任何真实环境的情况下跑通 LogWarden 的完整流程。

**全部数据为虚构**：正常业务流量的客户端取自 RFC 1918 私有地址段（`10.0.0.0/24`，模拟内网办公终端），攻击源取自 RFC 5737 文档专用地址段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`），主机名 `web-prod-01` / `WIN-CLIENT-07`，账号 `ubuntu` / `administrator` / `svc_update` 均为通用名。不包含任何真实系统、真实用户或真实业务信息。

## 文件

| 文件 | 行数 | 导入到哪个源 | 解析格式 |
|---|---|---|---|
| `nginx-access.log` | 961 | `nginx_access`（nginx 访问日志） | `combined` |
| `linux-auth.log` | 208 | `ubuntu_auth`（Ubuntu 认证日志） | `syslog` |
| `windows-security.csv` | 34 | `win_security`（Windows 安全日志） | `windows_event` |

## 攻击链

时间线基于 2026-11-05。

```
09:00-10:10  正常业务流量（5 个内网客户端 10.0.0.x）
10:12-10:38  目录扫描 · 203.0.113.46 · 645 次 404，探测 .git/.env/backup.zip
10:40-11:02  SQL 注入探测 · 203.0.113.45 · sqlmap UA · union select / extractvalue
11:05-11:20  试探上传点 /upload.php、/admin/upload
11:23        webshell 上传成功 /upload/shell.php
11:26-13:40  webshell 执行命令：whoami / id / cat config.php / netstat -antp
14:10-14:16  下载 /data/backup.zip，单次 41-52 MB（数据外带信号）

Linux 侧
10:05-10:36  SSH 爆破 · 203.0.113.45 · root/admin/test 等账号轮询
10:36        Accepted password for ubuntu（爆破成功）
10:40        sudo 提权到 root
11:00        新建后门账号 svcbackup，加入 sudo 组

Windows 侧
11:30-11:58  4625 登录失败 ×28 · 198.51.100.77 · administrator/admin/guest 轮询
11:58        4624 登录成功（类型 3 网络登录，同一来源）
12:00        4688 执行 powershell.exe -nop -w hidden -enc
12:04        4720 新建账号 svc_update → 12:08 删除
12:12        7045 安装服务 WindowsUpdateSvc，指向 C:\Windows\Temp\wusvc.exe
```

## 预期结果

用「nginx + Ubuntu 主机 + Windows 主机」三个组件建任务，全部导入后：

- 总行数 **1203**，独立 IP **7**（2 外网 + 5 内网）
- 规则命中 **1595** 次，有命中的规则 15 条，其中高危 7 条、中危 5 条
- 证据完整度 **3/3**（三个组件的必要项都已收齐）

主要命中：

| 源 | 规则 | 次数 |
|---|---|---|
| nginx | 敏感文件探测 | 210 |
| nginx | 敏感管理接口暴露 | 40 |
| nginx | SQL 注入特征 | 28 |
| nginx | 上传目录里的脚本被请求 | 22 |
| nginx | 命令执行类参数 | 21 |
| nginx | 同路径响应体积突变 | 3 |
| auth | 认证失败爆发 | 1 |
| auth | 账号创建或提权 | 1 |
| Windows | 登录失败 4625 | 28 |
| Windows | 外网来源登录成功 4624 | 1 |
| Windows | 可疑命令行创建进程 4688 | 1 |
| Windows | 创建本地账号 4720 | 1 |
| Windows | 账号被删除 4726 | 1 |
| Windows | 安装新服务 7045 | 1 |

## 重新生成

数据由同目录的 `generate.py` 生成（固定随机种子，每次输出一致）。想改攻击链、调整数据量或换成自己的场景，改脚本里的参数再跑：

```bash
python sample-data/generate.py
```
