
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from crucible.models import ScanResult
from crucible.reporters.base import BaseReporter

class JSONReporter(BaseReporter):

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def render(self, result: ScanResult) -> None:
        from rich.console import Console

        console = Console()
        console.print(self.to_json(result))

    def to_dict(self, result: ScanResult) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(
            result.model_dump_json()
        )
        return data

    def to_json(self, result: ScanResult) -> str:
        data = self.to_dict(result)
        return json.dumps(
            data, indent=self.indent, ensure_ascii=False
        )

    def write(
        self, result: ScanResult, path: str | Path
    ) -> Path:
        output = Path(path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            self.to_json(result), encoding="utf-8"
        )
        return output

