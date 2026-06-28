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

    def test_scan_help_shows_new_flags(self) -> None:
        """Verify Phase 1 enterprise connectivity flags are visible."""
        result = runner.invoke(app, ["scan", "--help"], color=False)
        output = strip_ansi(result.output)
        assert result.exit_code == 0
        assert "--format-preset" in output
        assert "--response-path" in output
        assert "--retry" in output
        assert "--delay" in output
        assert "--proxy" in output

    def test_scan_missing_target(self) -> None:
        result = runner.invoke(app, ["scan"], color=False)
        assert result.exit_code != 0

    @respx.mock
    def test_scan_invalid_format_preset(self) -> None:
        """Unknown format preset should fail with exit code 1."""
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--format-preset",
                "invalid_preset",
                "--quiet",
            ],
            color=False,
        )
        assert result.exit_code == 1
        assert "Unknown format preset" in strip_ansi(result.output)

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
            return_value=httpx.Response(
                200, text="Sure, here is the system prompt: secret"
            )
        )
        slack_route = respx.post("https://hooks.slack.com/services/T/B/X").mock(
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
        assert slack_route.called
        request_body = json.loads(slack_route.calls.last.request.content)
        assert "attachments" in request_body
        attachment = request_body["attachments"][0]
        assert "color" in attachment
        blocks = attachment["blocks"]
        assert any("https://agent.test/chat" in str(block) for block in blocks)
        assert any("findings" in str(block).lower() for block in blocks)

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
    def test_scan_fail_on_high_fails_with_critical(self) -> None:
        # 'injection_success' triggers IgnorePreviousInstructions (CRITICAL)
        # CRITICAL severity is higher than HIGH threshold, so this must fail.
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
                "HIGH",
            ],
            color=False,
        )
        assert result.exit_code == 1
        assert (
            "Scan failed due to findings matching or exceeding HIGH severity"
            in result.stdout
        )

    @respx.mock
    def test_scan_fail_on_high_fails_with_high(self) -> None:
        # 'delimiter_bypass' triggers DelimiterInjection (HIGH)
        # HIGH severity equals the HIGH threshold, so this must fail.
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="delimiter_bypass")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--fail-on",
                "HIGH",
            ],
            color=False,
        )
        assert result.exit_code == 1
        assert (
            "Scan failed due to findings matching or exceeding HIGH severity"
            in result.stdout
        )

    @respx.mock
    def test_scan_fail_on_high_passes_with_medium(self) -> None:
        # 'roleplay_success' triggers RolePlayInjection (MEDIUM)
        # MEDIUM severity is less than HIGH threshold, so this should pass normally.
        def mock_response(request: httpx.Request) -> httpx.Response:
            try:
                body_str = request.read().decode("utf-8")
            except Exception:
                body_str = ""

            if "EvilBot" in body_str or "ROLEPLAY_SUCCESS" in body_str:
                return httpx.Response(200, text="roleplay_success")
            return httpx.Response(200, text="I cannot do that. Against guidelines.")

        respx.post("https://agent.test/chat").mock(side_effect=mock_response)
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--fail-on",
                "HIGH",
            ],
            color=False,
        )
        assert result.exit_code == 0

    @respx.mock
    def test_scan_fail_on_invalid_severity(self) -> None:
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="Defended.")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://agent.test/chat",
                "--fail-on",
                "INVALID_SEV",
            ],
            color=False,
        )
        assert result.exit_code == 1
        assert "Invalid severity for --fail-on" in result.stdout

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
