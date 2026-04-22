from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from crucible.cli import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


class TestCLI:
    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "init" in result.output
        assert "scan" in result.output
        assert "report" in result.output

    def test_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Crucible" in result.output

    def test_scan_help(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output
        assert "--name" in result.output
        assert "--header" in result.output

    def test_scan_missing_target(self) -> None:
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0

    def test_init_creates_config(self, tmp_path: Path) -> None:
        import os

        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(
                app,
                ["init", "--target", "https://example.com/api"],
            )
            assert result.exit_code == 0
            config_file = tmp_path / ".crucible.json"
            assert config_file.exists()
            data = json.loads(config_file.read_text())
            assert data["target"]["url"] == "https://example.com/api"
            assert data["target"]["provider"] == "custom"
        finally:
            os.chdir(old_cwd)

    def test_report_file_not_found(self) -> None:
        result = runner.invoke(app, ["report", "nonexistent.json"])
        assert result.exit_code == 1

    def test_report_invalid_json(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json")
        result = runner.invoke(app, ["report", str(bad_file)])
        assert result.exit_code == 1

    def test_report_valid_json(self, tmp_path: Path) -> None:
        from crucible.models import AgentTarget, ScanResult

        target = AgentTarget(
            name="test",
            url="https://example.com/api",  # type: ignore[arg-type]
        )
        scan = ScanResult(target=target)
        report_file = tmp_path / "report.json"
        report_file.write_text(scan.model_dump_json(), encoding="utf-8")

        result = runner.invoke(app, ["report", str(report_file)])
        assert result.exit_code == 0
        assert "CRUCIBLE" in result.output


class TestReporters:
    def test_json_reporter_import(self) -> None:
        from crucible.reporters.json_reporter import JSONReporter

        reporter = JSONReporter()
        assert reporter.indent == 2

    def test_terminal_reporter_import(self) -> None:
        from crucible.reporters.terminal import TerminalReporter

        reporter = TerminalReporter()
        assert reporter.console is not None

    def test_base_reporter_abstract(self) -> None:
        from crucible.reporters.base import BaseReporter

        with pytest.raises(TypeError):
            BaseReporter()  # type: ignore[abstract]
