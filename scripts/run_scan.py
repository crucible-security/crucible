#!/usr/bin/env python3
"""
run_scan.py — Helper script for the crucible-security GitHub Action.

Reads environment variables set by action.yml, builds the crucible scan
command, executes it, and writes the output report.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    target = os.environ["CRUCIBLE_TARGET"]
    preset = os.environ.get("CRUCIBLE_PRESET", "openai")
    model = os.environ.get("CRUCIBLE_MODEL", "")
    headers_json = os.environ.get("CRUCIBLE_HEADERS", "{}")
    modules_csv = os.environ.get("CRUCIBLE_MODULES", "")
    concurrency = os.environ.get("CRUCIBLE_CONCURRENCY", "10")
    timeout = os.environ.get("CRUCIBLE_TIMEOUT", "30")
    output_format = os.environ.get("CRUCIBLE_OUTPUT_FORMAT", "json")
    skip_preflight = os.environ.get("CRUCIBLE_SKIP_PREFLIGHT", "false").lower() == "true"
    runner_temp = os.environ.get("RUNNER_TEMP", "/tmp")

    report_path = str(Path(runner_temp) / f"crucible_report.{output_format}")
    # Always produce JSON for parsing, plus the requested format if different
    json_report_path = str(Path(runner_temp) / "crucible_report.json")

    cmd = [
        sys.executable,
        "-m",
        "crucible.cli",
        "scan",
        "--target",
        target,
        "--format-preset",
        preset,
        "--output",
        json_report_path,
        "--format",
        "json",
        "--concurrency",
        concurrency,
        "--timeout",
        timeout,
        "--quiet",
    ]

    # Add model if specified
    if model:
        cmd += ["--model", model]

    # Add headers from JSON object
    try:
        headers = json.loads(headers_json)
        for key, value in headers.items():
            cmd += ["--header", f"{key}: {value}"]
    except json.JSONDecodeError:
        print(f"::warning::CRUCIBLE_HEADERS is not valid JSON: {headers_json!r}")

    # Add specific modules if requested
    if modules_csv:
        for module in modules_csv.split(","):
            module = module.strip()
            if module:
                cmd += ["--module", module]

    # Add --skip-preflight if requested
    if skip_preflight:
        cmd += ["--skip-preflight"]

    print(f"::group::Crucible Security Scan")
    print(f"Target: {target}")
    print(f"Preset: {preset}")
    if model:
        print(f"Model: {model}")
    if modules_csv:
        print(f"Modules: {modules_csv}")
    print(f"Report: {json_report_path}")
    print()

    result = subprocess.run(cmd, capture_output=False)

    print("::endgroup::")

    if result.returncode not in (0, 1):
        # Exit code 0 = scan completed (all passed)
        # Exit code 1 = scan completed with findings
        # Any other = hard failure (target unreachable, preflight fail, etc.)
        print(f"::error::Crucible scan exited with code {result.returncode}.")
        sys.exit(result.returncode)

    # If requested format differs from json, also generate that format
    if output_format != "json" and report_path != json_report_path:
        sarif_cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "report",
            "--input",
            json_report_path,
            "--output",
            report_path,
            "--format",
            output_format,
        ]
        sarif_result = subprocess.run(sarif_cmd, capture_output=False)
        if sarif_result.returncode != 0:
            print(f"::warning::Could not generate {output_format} report (exit {sarif_result.returncode}).")


if __name__ == "__main__":
    main()
