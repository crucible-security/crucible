from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from crucible.models import Finding, ScanResult, Severity
from crucible.reporters.base import BaseReporter

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_CRUCIBLE_URI = "https://github.com/crucible-security/crucible"


class SARIFReporter(BaseReporter):
    """Render failed Crucible findings as SARIF 2.1.0."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def render(self, result: ScanResult) -> None:
        print(self.to_json(result))

    def to_dict(self, result: ScanResult) -> dict[str, Any]:
        failed_findings = result.get_failed_findings()
        rules = [_rule_for_finding(finding) for finding in failed_findings]
        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Crucible",
                            "informationUri": _CRUCIBLE_URI,
                            "version": result.crucible_version,
                            "rules": _dedupe_rules(rules),
                        }
                    },
                    "results": [
                        _result_for_finding(finding, result)
                        for finding in failed_findings
                    ],
                }
            ],
        }

    def to_json(self, result: ScanResult) -> str:
        return json.dumps(self.to_dict(result), indent=self.indent, ensure_ascii=False)

    def write(self, result: ScanResult, path: str | Path) -> Path:
        output = Path(path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_json(result), encoding="utf-8")
        return output


def _rule_id(finding: Finding) -> str:
    return finding.attack_name or finding.id


def _level_for_severity(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _rule_for_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": _rule_id(finding),
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "defaultConfiguration": {"level": _level_for_severity(finding.severity)},
        "help": {"text": finding.remediation},
        "properties": {
            "category": finding.category.value,
            "severity": finding.severity.value,
            "owasp_ref": finding.owasp_ref,
            "tags": [finding.category.value, finding.severity.value],
        },
    }


def _dedupe_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for rule in rules:
        deduped.setdefault(str(rule["id"]), rule)
    return list(deduped.values())


def _result_for_finding(finding: Finding, result: ScanResult) -> dict[str, Any]:
    message = finding.description or finding.title
    target_uri = str(result.target.url)
    return {
        "ruleId": _rule_id(finding),
        "level": _level_for_severity(finding.severity),
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": target_uri}}}],
        "partialFingerprints": {
            "crucibleFindingId": finding.id,
            "cruciblePayload": finding.payload,
        },
        "properties": {
            "attack_name": finding.attack_name,
            "category": finding.category.value,
            "confidence": finding.confidence,
            "owasp_ref": finding.owasp_ref,
            "payload": finding.payload,
            "remediation": finding.remediation,
            "response_snippet": finding.response_snippet,
            "severity": finding.severity.value,
            "target": result.target.name,
        },
    }
