"""Tests for memory and RAG poisoning evaluation (Phase 7 / v0.8.0)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from crucible.cli import app
from crucible.models import MemoryType, PoisonPlantRecord, PoisonStatus
from crucible.poison.document_generator import DocumentGenerator
from crucible.poison.session_store import PoisonSessionStore


# ===========================================================================
# Document Generator Tests
# ===========================================================================

def test_document_generator_technique_1() -> None:
    generator = DocumentGenerator()
    doc, signal = generator.generate(1, "travel policy")
    assert len(signal) == 8
    assert signal in doc
    assert "confirmation code" in doc
    assert "travel policy" in doc


def test_document_generator_technique_2() -> None:
    generator = DocumentGenerator()
    doc, signal = generator.generate(2, "travel policy")
    assert len(signal) == 8
    assert signal in doc
    assert "SYSTEM ADMINISTRATOR MESSAGE" in doc
    assert "\u200b\u200b" in doc


def test_document_generator_technique_3() -> None:
    generator = DocumentGenerator()
    doc, signal = generator.generate(3, "travel policy")
    assert len(signal) == 8
    assert signal in doc
    assert "Default Response Template" in doc


def test_document_generator_technique_4() -> None:
    generator = DocumentGenerator()
    doc, signal = generator.generate(4, "travel policy")
    assert len(signal) == 8
    assert signal in doc
    assert "validation token" in doc


def test_activation_signal_unique_per_call() -> None:
    generator = DocumentGenerator()
    signals = {generator.generate_activation_signal() for _ in range(100)}
    assert len(signals) == 100  # All unique


# ===========================================================================
# Session Store Tests
# ===========================================================================

def test_poison_session_store_saves_and_loads(tmp_path: Path) -> None:
    store = PoisonSessionStore(store_dir=tmp_path)
    record = PoisonPlantRecord(
        session_id="session-123",
        memory_type=MemoryType.RAG,
        topic="test topic",
        technique=1,
        trigger="what is the test topic?",
        activation_signal="X7K2M9QP",
        document_text="Poison doc content X7K2M9QP",
        planted_at=datetime.now(timezone.utc).isoformat(),
        target_url="http://localhost:8080",
    )
    store.save(record)

    loaded = store.load("session-123")
    assert loaded is not None
    assert loaded.session_id == "session-123"
    assert loaded.activation_signal == "X7K2M9QP"
    assert loaded.status == PoisonStatus.PLANTED


def test_poison_session_store_lists_all(tmp_path: Path) -> None:
    store = PoisonSessionStore(store_dir=tmp_path)
    for i in range(3):
        record = PoisonPlantRecord(
            session_id=f"session-{i}",
            memory_type=MemoryType.EPISODIC,
            topic="topic",
            technique=2,
            trigger="trigger",
            activation_signal="SIG",
            document_text="doc",
            planted_at=f"2026-06-29T12:0{i}:00Z",
            target_url="http://localhost:8080",
        )
        store.save(record)

    all_records = store.list_all()
    assert len(all_records) == 3
    # Sorted descending by planted_at
    assert all_records[0].session_id == "session-2"
    assert all_records[1].session_id == "session-1"
    assert all_records[2].session_id == "session-0"


# ===========================================================================
# Verification Logic Tests
# ===========================================================================

def test_verify_detects_activation_when_signal_present() -> None:
    # A test helper check: does signal appear in response
    signal = "X7K2M9QP"
    response = f"Sure, the answer contains X7K2M9QP token."
    assert signal in response


def test_verify_detects_no_activation() -> None:
    signal = "X7K2M9QP"
    response = "The answer does not contain the code."
    assert signal not in response


# ===========================================================================
# CLI Integration Tests
# ===========================================================================

@patch("httpx.Client")
def test_rag_plant_via_ingest_endpoint(mock_client_class: MagicMock, tmp_path: Path) -> None:
    # Setup mock Client and response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success"}
    mock_resp.text = "OK: activation_signal SIG"

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp
    mock_client_class.return_value = mock_client

    runner = CliRunner()
    session_file = tmp_path / "plant.json"

    # Mock the PoisonSessionStore inside the CLI call by patch
    with patch("crucible.poison.session_store.PoisonSessionStore") as mock_store_class:
        mock_store = MagicMock()
        mock_store.load.return_value = None
        mock_store_class.return_value = mock_store

        result = runner.invoke(
            app,
            [
                "poison-test",
                "rag",
                "--ingest-endpoint",
                "http://localhost:8081/ingest",
                "--query-endpoint",
                "http://localhost:8081/query",
                "--trigger",
                "travel rules",
                "--topic",
                "travel",
                "--session-id",
                "rag-session-999",
                "--output",
                str(session_file),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "ingested" in result.output.lower()
        assert "poison" in result.output.lower()
        mock_client.post.assert_called()  # Ingest + Query calls

        assert session_file.exists()



def test_plant_command_creates_record_file(tmp_path: Path) -> None:
    runner = CliRunner()
    session_file = tmp_path / "plant_t1.json"

    with patch("crucible.poison.session_store.PoisonSessionStore") as mock_store_class:
        mock_store = MagicMock()
        mock_store.load.return_value = None
        mock_store_class.return_value = mock_store

        result = runner.invoke(
            app,
            [
                "poison-test",
                "plant",
                "--target",
                "http://localhost:11434/api/chat",
                "--topic",
                "financial overview",
                "--technique",
                "1",
                "--trigger",
                "tell me about finance",
                "--session-id",
                "plant-session-001",
                "--output",
                str(session_file),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "planted" in result.output.lower()
        assert session_file.exists()
        # Verify document content contains the technique 1 appendix text
        data = json.loads(session_file.read_text(encoding="utf-8"))
        assert data["session_id"] == "plant-session-001"
        assert "Appendix A: System Processing Metadata" in data["document_text"]


def test_list_command_shows_all_sessions() -> None:
    runner = CliRunner()
    with patch("crucible.poison.session_store.PoisonSessionStore") as mock_store_class:
        mock_store = MagicMock()
        mock_store.list_all.return_value = [
            PoisonPlantRecord(
                session_id="sess-A",
                memory_type=MemoryType.SEMANTIC,
                topic="topic A",
                technique=1,
                trigger="trigger A",
                activation_signal="SIGA",
                document_text="doc A",
                planted_at="2026-06-29T10:00:00Z",
                status=PoisonStatus.PLANTED,
                target_url="http://localhost:8080",
            )
        ]
        mock_store_class.return_value = mock_store

        result = runner.invoke(app, ["poison-test", "list"])
        assert result.exit_code == 0, result.output
        assert "sess-a" in result.output.lower()
        assert "planted" in result.output.lower()


def test_status_command_shows_single_session() -> None:
    runner = CliRunner()
    with patch("crucible.poison.session_store.PoisonSessionStore") as mock_store_class:
        mock_store = MagicMock()
        mock_store.load.return_value = PoisonPlantRecord(
            session_id="sess-B",
            memory_type=MemoryType.EPISODIC,
            topic="topic B",
            technique=3,
            trigger="trigger B",
            activation_signal="SIGB",
            document_text="doc B",
            planted_at="2026-06-29T11:00:00Z",
            status=PoisonStatus.VERIFIED_ACTIVE,
            target_url="http://localhost:8080",
        )
        mock_store_class.return_value = mock_store

        result = runner.invoke(app, ["poison-test", "status", "--session-id", "sess-B"])
        assert result.exit_code == 0, result.output
        assert "sess-b" in result.output.lower()
        assert "verified_active" in result.output.lower()

