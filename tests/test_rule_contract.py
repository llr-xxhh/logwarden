"""Validate rule IDs, scopes, parser fields and metadata before runtime."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARSER_KINDS = {
    "web": "combined.json",
    "auth": "syslog.json",
    "syslog": "syslog.json",
    "audit": "audit.json",
    "shell": "shell.json",
    "win": "windows_event.json",
    "ps": "windows_event.json",
    "sysmon": "windows_event.json",
    "firewall": "firewall.json",
    "text": "text.json",
}
VALID_SCOPES = set(PARSER_KINDS)
ENRICHED_FILES = {"correlation.json", "web-advanced.json", "windows-advanced.json", "linux-advanced.json", "database-advanced.json"}


def parser_fields(kind: str) -> set[str]:
    data = json.loads((ROOT / "parsers" / PARSER_KINDS[kind]).read_text(encoding="utf-8"))
    return set(data["fields"]) | {"raw", "source_id"}


def match_fields(match: dict) -> set[str]:
    fields: set[str] = set()
    for key, value in (match or {}).items():
        if key in ("any", "not"):
            children = value if isinstance(value, list) else [value]
            for child in children:
                fields |= match_fields(child)
        elif key == "agg":
            for name in ("where", "fail", "success"):
                fields |= match_fields(value.get(name) or {})
            for name in ("group_by", "distinct"):
                if value.get(name):
                    fields.add(value[name])
        else:
            fields.add(key)
    return fields


def scope_kinds(scope) -> list[str]:
    if scope == "all":
        return list(PARSER_KINDS)
    if scope == "syslog":
        return ["auth", "syslog"]
    return scope if isinstance(scope, list) else [scope]


class RuleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = []
        for path in sorted((ROOT / "rules" / "builtin").glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            cls.documents.append((path.name, data))

    def test_ids_are_unique(self):
        seen = {}
        duplicates = []
        for filename, data in self.documents:
            for rule in data.get("rules", []):
                rid = rule.get("id")
                if rid in seen:
                    duplicates.append((rid, seen[rid], filename))
                seen[rid] = filename
        self.assertEqual(duplicates, [])

    def test_required_fields_and_scopes(self):
        failures = []
        for filename, data in self.documents:
            for rule in data.get("rules", []):
                rid = rule.get("id", "<missing>")
                for key in ("id", "name", "severity", "kind", "scope", "match", "false_positive"):
                    if key not in rule:
                        failures.append((filename, rid, "缺少 " + key))
                scopes = rule.get("scope") if isinstance(rule.get("scope"), list) else [rule.get("scope")]
                for scope in scopes:
                    if scope not in VALID_SCOPES:
                        failures.append((filename, rid, "未知 scope " + str(scope)))
        self.assertEqual(failures, [])

    def test_fields_exist_in_every_target_parser(self):
        failures = []
        cache = {kind: parser_fields(kind) for kind in PARSER_KINDS}
        for filename, data in self.documents:
            for rule in data.get("rules", []):
                fields = match_fields(rule.get("match") or {})
                for kind in scope_kinds(rule.get("scope", "all")):
                    missing = sorted(fields - cache[kind])
                    if missing:
                        failures.append((rule["id"], kind, missing))
        self.assertEqual(failures, [], "规则字段必须存在于其所有适用日志源")

    def test_metadata_format(self):
        failures = []
        for filename, data in self.documents:
            for rule in data.get("rules", []):
                if filename in ENRICHED_FILES:
                    for key in ("attack", "references", "triage"):
                        if not rule.get(key):
                            failures.append((rule["id"], "新规则缺少 " + key))
                for technique in rule.get("attack", []):
                    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                        failures.append((rule["id"], "ATT&CK 编号格式错误", technique))
                for url in rule.get("references", []):
                    if not url.startswith("https://"):
                        failures.append((rule["id"], "参考来源必须使用 HTTPS", url))
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
