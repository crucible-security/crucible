from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from crucible.reporters.base import BaseReporter

if TYPE_CHECKING:
    from crucible.models import Finding, ScanResult


class STIXReporter(BaseReporter):
    """Generates a STIX 2.1 compliant Threat Intelligence Bundle.

    Export privacy guarantees:
    - Target endpoint URL is NEVER exported.
    - Raw attack payloads are NEVER exported.
    - Payloads are uniquely identified only via SHA-256 hashes of their text.
    """

    def __init__(self, spec_version: str = "2.1") -> None:
        self.spec_version = spec_version

    def render(self, result: ScanResult) -> None:
        from rich.console import Console

        console = Console()
        console.print(self.to_json(result))

    def to_dict(self, result: ScanResult) -> dict[str, Any]:
        """Convert ScanResult findings into a STIX 2.1 Bundle."""
        indicators: list[dict[str, Any]] = []
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Collect all failed findings (where passed is False, i.e. vulnerability exists)
        for mod_res in result.modules:
            for finding in mod_res.findings:
                if finding.passed is False:
                    indicators.append(self._build_indicator(finding, now_str))

        bundle_id = f"bundle--{uuid.uuid4()}"
        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": indicators,
        }

    def to_json(self, result: ScanResult, indent: int = 2) -> str:
        """Serialize the STIX Bundle to a JSON string."""
        return json.dumps(self.to_dict(result), indent=indent, ensure_ascii=False)

    def write(self, result: ScanResult, path: str | Path) -> Path:
        """Write the STIX Bundle JSON file to the specified path."""
        output = Path(path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_json(result), encoding="utf-8")
        return output

    def _build_indicator(self, finding: Finding, timestamp_str: str) -> dict[str, Any]:
        """Construct a single STIX 2.1 Indicator object for a vulnerability finding."""
        # Calculate SHA-256 hash of the payload for anonymous/private identification
        payload_hash = hashlib.sha256(finding.payload.encode("utf-8")).hexdigest()

        indicator_id = f"indicator--{uuid.uuid4()}"
        description = (
            f"Vulnerability found in AI agent behavior. "
            f"Category: {finding.category.value}. "
            f"Severity: {finding.severity.value}. "
            f"Description: {finding.description}"
        )

        ext_refs = []
        if finding.atlas_technique:
            ext_refs.append(
                {
                    "source_name": "mitre-atlas",
                    "external_id": finding.atlas_technique,
                    "url": f"https://atlas.mitre.org/techniques/{finding.atlas_technique}",
                }
            )

        if finding.owasp_ref:
            ext_refs.append(
                {
                    "source_name": "owasp-llm-top-10",
                    "external_id": finding.owasp_ref.split(":")[0],
                    "description": finding.owasp_ref,
                }
            )

        severity_map = {
            "critical": 95,
            "high": 80,
            "medium": 50,
            "low": 20,
            "info": 10,
        }
        confidence = severity_map.get(finding.severity.value.lower(), 50)

        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": self.spec_version,
            "id": indicator_id,
            "created": timestamp_str,
            "modified": timestamp_str,
            "name": finding.title or finding.attack_name,
            "description": description,
            "indicator_types": ["malicious-activity"],
            "pattern": f"[x-ai-prompt:payload_sha256 = '{payload_hash}']",
            "pattern_type": "stix",
            "pattern_version": self.spec_version,
            "valid_from": timestamp_str,
            "confidence": confidence,
        }

        if ext_refs:
            indicator["external_references"] = ext_refs

        return indicator
