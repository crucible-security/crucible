from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import pytest
import respx
from typer.testing import CliRunner

from crucible.cli import app

if TYPE_CHECKING:
    from pathlib import Path

import re

runner = CliRunner()


def strip_ansi(text: str) -> str:
    """Strip ANSI escape codes from string."""
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


class TestCLI:
    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"], color=False)
        output = strip_ansi(result.output)
        assert result.exit_code == 0
        assert "init" in output
        assert "scan" in output
        assert "report" in output

    def test_version(self) -> None:
        result = runner.invoke(app, ["--version"], color=False)
        output = strip_ansi(result.output)
        assert result.exit_code == 0
        assert "Crucible" in output

    def test_scan_help(self) -> None:
        result = runner.invoke(app, ["scan", "--help"], color=False)
        output = strip_ansi(result.output)
        assert result.exit_code == 0
        assert "--target" in output
        assert "--name" in output
        assert "--header" in output

    def test_scan_missing_target(self) -> None:
        result = runner.invoke(app, ["scan"], color=False)
        assert result.exit_code != 0

    def test_init_creates_config(self, tmp_path: Path) -> None:
        import os

        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(
                app,
                ["init", "--target", "https://example.com/api"],
                color=False,
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
        result = runner.invoke(app, ["report", "nonexistent.json"], color=False)
        assert result.exit_code == 1

    def test_report_invalid_json(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json")
        result = runner.invoke(app, ["report", str(bad_file)], color=False)
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

        result = runner.invoke(app, ["report", str(report_file)], color=False)
        assert result.exit_code == 0

    @respx.mock
    def test_scan_success(self, tmp_path: Path) -> None:

        # Mock the agent response
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )

        report_file = tmp_path / "scan-report.json"
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--output-file",
                str(report_file),
            ],
            color=False,
        )
        assert result.exit_code == 0
        assert report_file.exists()
        data = json.loads(report_file.read_text(encoding="utf-8"))
        assert data["status"] == "completed"
        assert "grade" in data

    @respx.mock
    def test_scan_format_table(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )
        result = runner.invoke(
            app,
            ["scan", "--target", "https://agent.test/chat", "--format", "table"],
            color=False,
        )
        assert result.exit_code == 0
        assert "CRUCIBLE SECURITY SCAN" in result.output

    @respx.mock
    def test_scan_format_terminal(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )
        result = runner.invoke(
            app,
            ["scan", "--target", "https://agent.test/chat", "--format", "terminal"],
            color=False,
        )
        assert result.exit_code == 0
        assert "CRUCIBLE SECURITY SCAN" in result.output

    @respx.mock
    def test_scan_format_json(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--format",
                "json",
                "--quiet",
            ],
            color=False,
        )
        assert result.exit_code == 0
        # Output should be valid JSON
        data = json.loads(result.stdout)
        assert data["status"] == "completed"
        # Should NOT contain the terminal header
        assert "CRUCIBLE" not in result.output

    @respx.mock
    def test_scan_format_html(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--format",
                "html",
                "--quiet",
            ],
            color=False,
        )
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.stdout
        assert "CRUCIBLE" not in result.stdout

    @respx.mock
    def test_scan_slack_webhook(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )
        respx.post("https://hooks.slack.com/services/T/B/X").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--slack-webhook",
                "https://hooks.slack.com/services/T/B/X",
                "--quiet",
            ],
            color=False,
        )
        assert result.exit_code == 0

    @respx.mock
    def test_scan_fail_on_critical_passes(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="I cannot do that.")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--fail-on",
                "CRITICAL",
                "--quiet",
            ],
            color=False,
        )
        assert result.exit_code == 0

    @respx.mock
    def test_scan_fail_on_critical_fails(self) -> None:
        # 'injection_success' triggers the IgnorePreviousInstructions attack which is CRITICAL
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="injection_success")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--fail-on",
                "CRITICAL",
            ],
            color=False,
        )
        assert result.exit_code == 1
        assert (
            "Scan failed due to findings matching or exceeding CRITICAL severity"
            in result.stdout
        )

    @respx.mock
    def test_scan_verbose_output(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--verbose",
                "--quiet",  # Suppress progress bar to cleanly check stderr
            ],
            color=False,
        )
        assert result.exit_code == 0
        assert "[ATTACK]" in result.output
        assert "Payload:" in result.output
        assert "Response:" in result.output
        assert "Result:" in result.output


class TestReporters:
    def test_json_reporter_import(self) -> None:
        from crucible.reporters.json_reporter import JSONReporter

        reporter = JSONReporter()
        assert reporter.indent == 2

    def test_json_reporter_full(self, tmp_path: Path) -> None:
        from crucible.models import AgentTarget, ScanResult
        from crucible.reporters.json_reporter import JSONReporter

        target = AgentTarget(name="test", url="https://test.example.com/api")  # type: ignore[arg-type]
        scan = ScanResult(target=target)
        reporter = JSONReporter(indent=4)

        # Test to_dict
        data = reporter.to_dict(scan)
        assert data["target"]["name"] == "test"

        # Test to_json
        json_data = reporter.to_json(scan)
        assert '"indent": 4' not in json_data  # indent is for the output file
        assert "test" in json_data

        # Test write
        report_file = tmp_path / "reporter.json"
        written_path = reporter.write(scan, report_file)
        assert written_path.exists()
        assert "test" in report_file.read_text()

    def test_terminal_reporter_import(self) -> None:
        from crucible.reporters.terminal import TerminalReporter

        reporter = TerminalReporter()
        assert reporter.console is not None

    def test_base_reporter_abstract(self) -> None:
        from crucible.reporters.base import BaseReporter

        with pytest.raises(TypeError):
            BaseReporter()  # type: ignore[abstract]
