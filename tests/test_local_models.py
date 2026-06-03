from __future__ import annotations

import json

from typer.testing import CliRunner

from crucible.cli import app
from crucible.models import PROVIDER_PRESETS


def test_provider_presets_exist() -> None:
    expected_presets = [
        "openai",
        "langchain",
        "glean",
        "raw",
        "generic",
        "ollama",
        "lmstudio",
        "huggingface-tgi",
    ]
    for preset in expected_presets:
        assert preset in PROVIDER_PRESETS


def test_ollama_preset_construction() -> None:
    preset = PROVIDER_PRESETS["ollama"]
    assert preset.requires_model is True
    assert preset.default_timeout == 120.0
    assert preset.response_path == "message.content"

    # Check model parameter injection
    resolved_body = preset.body_template.replace("{model}", "mistral").replace(
        "{payload}", "test payload"
    )
    data = json.loads(resolved_body)
    assert data["model"] == "mistral"
    assert data["messages"][0]["content"] == "test payload"


def test_lmstudio_preset_construction() -> None:
    preset = PROVIDER_PRESETS["lmstudio"]
    assert preset.default_timeout == 120.0
    assert preset.response_path == "choices[0].message.content"


def test_huggingface_tgi_preset_construction() -> None:
    preset = PROVIDER_PRESETS["huggingface-tgi"]
    assert preset.default_timeout == 120.0
    assert preset.response_path == "generated_text"


def test_cli_local_model_preset_resolution() -> None:
    runner = CliRunner()
    # Test unknown format preset
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "http://localhost:11434",
            "--format-preset",
            "unknown-preset",
        ],
    )
    assert result.exit_code != 0
    assert "Unknown format preset" in result.output
