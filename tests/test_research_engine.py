"""Tests for the Deep Research Engine (v0.4.0)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from crucible.attacks.dynamic_generator import DynamicAttackGenerator
from crucible.core.research_engine import (
    AttackTemplate,
    GitHubAdvisoryScraper,
    HackerOneScraper,
    PatternExtractor,
    RawResearchItem,
    ResearchEngine,
    SecurityBlogScraper,
    VectorStore,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_store(tmp_path: Path) -> VectorStore:
    return VectorStore(store_path=tmp_path / "test_store.json")


@pytest.fixture()
def sample_item() -> RawResearchItem:
    return RawResearchItem(
        source="test_source",
        url="https://example.com/vuln",
        title="Critical SSRF in AI Agent via URL Fragment Bypass",
        content=(
            "A server-side request forgery vulnerability was found in an AI agent framework. "
            "By appending a '#' fragment to the baseURL parameter, an attacker can force the "
            "backend to issue requests to http://169.254.169.254/latest/meta-data, bypassing "
            "SSRF protections. The Metadata-Flavor: Google header can be injected to bypass "
            "GCP metadata service protections."
        ),
    )


@pytest.fixture()
def sample_template() -> AttackTemplate:
    return AttackTemplate(
        id=AttackTemplate.make_id("test_source", "Critical SSRF"),
        source="test_source",
        url="https://example.com/vuln",
        title="Critical SSRF in AI Agent via URL Fragment Bypass",
        vulnerability_class="SSRF",
        cwe_id="CWE-918",
        target_context="REST API with user-controlled baseURL parameter",
        attack_description="Append '#' to baseURL to truncate SDK path appends.",
        payloads=[
            "http://169.254.169.254/latest/meta-data#",
            "http://127.0.0.1:6379/#",
        ],
        bypass_techniques=["URL fragment truncation (#)", "Hex IP: 0xa9fea9fe"],
        detection_patterns=["ami-id", "instance-id", "computeMetadata"],
        severity="CRITICAL",
    )


# ---------------------------------------------------------------------------
# VectorStore tests
# ---------------------------------------------------------------------------


class TestVectorStore:
    def test_add_and_retrieve(
        self, tmp_store: VectorStore, sample_template: AttackTemplate
    ) -> None:
        added = tmp_store.add(sample_template)
        assert added is True
        assert tmp_store.count == 1

    def test_deduplication(
        self, tmp_store: VectorStore, sample_template: AttackTemplate
    ) -> None:
        tmp_store.add(sample_template)
        added_again = tmp_store.add(sample_template)
        assert added_again is False
        assert tmp_store.count == 1

    def test_persistence(self, tmp_path: Path, sample_template: AttackTemplate) -> None:
        store_path = tmp_path / "store.json"
        store1 = VectorStore(store_path=store_path)
        store1.add(sample_template)
        store1.save()

        store2 = VectorStore(store_path=store_path)
        assert store2.count == 1
        assert store2.get_all()[0].id == sample_template.id

    def test_query_by_class(
        self, tmp_store: VectorStore, sample_template: AttackTemplate
    ) -> None:
        tmp_store.add(sample_template)
        results = tmp_store.query(vulnerability_class="SSRF")
        assert len(results) == 1
        assert results[0].vulnerability_class == "SSRF"

    def test_query_by_severity(
        self, tmp_store: VectorStore, sample_template: AttackTemplate
    ) -> None:
        tmp_store.add(sample_template)
        results = tmp_store.query(severity="CRITICAL")
        assert len(results) == 1
        results_high = tmp_store.query(severity="HIGH")
        assert len(results_high) == 0

    def test_query_no_match(
        self, tmp_store: VectorStore, sample_template: AttackTemplate
    ) -> None:
        tmp_store.add(sample_template)
        results = tmp_store.query(vulnerability_class="SQLi")
        assert results == []


# ---------------------------------------------------------------------------
# PatternExtractor tests
# ---------------------------------------------------------------------------


class TestPatternExtractor:
    def test_heuristic_ssrf(self, sample_item: RawResearchItem) -> None:
        extractor = PatternExtractor(api_key=None)
        template = extractor.extract(sample_item)
        assert template is not None
        assert template.vulnerability_class == "SSRF"
        assert template.cwe_id == "CWE-918"
        assert template.severity == "HIGH"

    def test_heuristic_prompt_injection(self) -> None:
        item = RawResearchItem(
            source="test",
            url="https://example.com",
            title="Prompt Injection in GPT-4o System Prompt",
            content="Attackers can inject prompt injection payloads to override the system prompt.",
        )
        extractor = PatternExtractor(api_key=None)
        template = extractor.extract(item)
        assert template is not None
        assert template.vulnerability_class == "Prompt Injection"
        assert template.cwe_id == "CWE-1048"

    def test_heuristic_returns_none_for_irrelevant(self) -> None:
        item = RawResearchItem(
            source="test",
            url="https://example.com",
            title="Performance Optimization Tips",
            content="Use caching to speed up your application.",
        )
        extractor = PatternExtractor(api_key=None)
        template = extractor.extract(item)
        assert template is None

    def test_attack_template_id_generation(self) -> None:
        id1 = AttackTemplate.make_id("source_a", "title_x")
        id2 = AttackTemplate.make_id("source_a", "title_x")
        id3 = AttackTemplate.make_id("source_a", "title_y")
        assert id1 == id2
        assert id1 != id3
        assert len(id1) == 16

    @patch("httpx.Client")
    def test_llm_extraction_gemini(
        self, mock_client_cls: MagicMock, sample_item: RawResearchItem
    ) -> None:
        """Test LLM extraction with a mocked Gemini API response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {
                                        "vulnerability_class": "SSRF",
                                        "cwe_id": "CWE-918",
                                        "target_context": "AI agent with user-controlled URL",
                                        "attack_description": "URL fragment bypass",
                                        "payloads": [
                                            "http://169.254.169.254/latest/meta-data#"
                                        ],
                                        "bypass_techniques": ["URL fragment (#)"],
                                        "detection_patterns": ["ami-id"],
                                        "severity": "CRITICAL",
                                    }
                                )
                            }
                        ]
                    }
                }
            ]
        }
        mock_client_cls.return_value.__enter__.return_value.post.return_value = (
            mock_response
        )

        extractor = PatternExtractor(provider="gemini", api_key="fake-key")
        template = extractor.extract(sample_item)

        assert template is not None
        assert template.vulnerability_class == "SSRF"
        assert template.severity == "CRITICAL"
        assert len(template.payloads) == 1

    def test_llm_extraction_handles_skip(self, sample_item: RawResearchItem) -> None:
        """When LLM returns {skip: true}, extract() should return None."""
        with patch.object(
            PatternExtractor, "_call_gemini", return_value='{"skip": true}'
        ):
            extractor = PatternExtractor(provider="gemini", api_key="fake-key")
            template = extractor.extract(sample_item)
            assert template is None

    def test_llm_extraction_handles_malformed_json(
        self, sample_item: RawResearchItem
    ) -> None:
        """When LLM returns malformed JSON, fall back to heuristic."""
        with patch.object(
            PatternExtractor, "_call_gemini", return_value="not json at all"
        ):
            extractor = PatternExtractor(provider="gemini", api_key="fake-key")
            # Falls back to heuristic — SSRF item should still yield a template
            template = extractor.extract(sample_item)
            assert template is not None


# ---------------------------------------------------------------------------
# Scraper tests (mocked HTTP)
# ---------------------------------------------------------------------------


class TestScrapers:
    def test_hackerone_filters_irrelevant(self) -> None:
        """HackerOne scraper should skip non-AI/SSRF reports."""
        mock_data = {
            "data": {
                "hacktivity_items": {
                    "edges": [
                        {
                            "node": {
                                "report": {
                                    "title": "Broken link on homepage",
                                    "url": "https://hackerone.com/reports/123",
                                    "vulnerability_information": "The footer link is broken.",
                                }
                            }
                        }
                    ]
                }
            }
        }
        with patch("httpx.Client") as mock_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_data
            mock_cls.return_value.__enter__.return_value.post.return_value = mock_resp

            scraper = HackerOneScraper()
            results = scraper.scrape()
            assert results == []

    def test_hackerone_accepts_ssrf_report(self) -> None:
        """HackerOne scraper should accept SSRF-tagged reports."""
        mock_data = {
            "data": {
                "hacktivity_items": {
                    "edges": [
                        {
                            "node": {
                                "report": {
                                    "title": "SSRF via image URL in AI chat endpoint",
                                    "url": "https://hackerone.com/reports/999",
                                    "vulnerability_information": "By sending an ssrf payload to the endpoint...",
                                }
                            }
                        }
                    ]
                }
            }
        }
        with patch("httpx.Client") as mock_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_data
            mock_cls.return_value.__enter__.return_value.post.return_value = mock_resp

            scraper = HackerOneScraper()
            results = scraper.scrape()
            assert len(results) == 1
            assert "SSRF" in results[0].title

    def test_github_advisory_accepts_cwes(self) -> None:
        """GitHub Advisory scraper should accept advisories matching target CWEs."""
        mock_data = [
            {
                "summary": "SSRF in AI framework URL handler",
                "description": "An SSRF vulnerability exists...",
                "html_url": "https://github.com/advisories/GHSA-test",
                "cwes": [{"cwe_id": "CWE-918"}],
            }
        ]
        with patch("httpx.Client") as mock_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_data
            mock_cls.return_value.__enter__.return_value.get.return_value = mock_resp

            scraper = GitHubAdvisoryScraper()
            results = scraper.scrape()
            assert len(results) == 1

    def test_security_blog_rss_parsing(self) -> None:
        """Blog scraper should parse a minimal RSS feed and filter AI-relevant items."""
        mock_rss = """<?xml version="1.0"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>New SSRF bypass via LLM tool-calling</title>
              <link>https://example.com/article1</link>
              <description>A novel ssrf bypass technique was found in prompt injection scenarios...</description>
            </item>
            <item>
              <title>Cloud cost optimization tips</title>
              <link>https://example.com/article2</link>
              <description>Save money on AWS bills.</description>
            </item>
          </channel>
        </rss>"""

        scraper = SecurityBlogScraper()
        scraper._FEEDS = [{"name": "Test Feed", "url": "https://test.com/rss"}]

        with patch.object(scraper, "_get", return_value=mock_rss):
            results = scraper.scrape()
            assert len(results) == 1
            assert "SSRF" in results[0].title


# ---------------------------------------------------------------------------
# ResearchEngine integration tests
# ---------------------------------------------------------------------------


class TestResearchEngine:
    def test_update_adds_templates(
        self, tmp_path: Path, sample_item: RawResearchItem
    ) -> None:
        """Full update cycle should store new templates."""
        mock_scraper = MagicMock()
        mock_scraper.name = "mock_scraper"
        mock_scraper.scrape.return_value = [sample_item]

        engine = ResearchEngine(
            store_path=tmp_path / "store.json",
            scrapers=[mock_scraper],
        )
        new_count = engine.update(verbose=False)
        assert new_count == 1
        assert engine.store.count == 1

    def test_update_deduplicates(
        self, tmp_path: Path, sample_item: RawResearchItem
    ) -> None:
        """Running update twice should not duplicate templates."""
        mock_scraper = MagicMock()
        mock_scraper.name = "mock_scraper"
        mock_scraper.scrape.return_value = [sample_item]

        engine = ResearchEngine(
            store_path=tmp_path / "store.json",
            scrapers=[mock_scraper],
        )
        engine.update(verbose=False)
        new_count = engine.update(verbose=False)
        assert new_count == 0
        assert engine.store.count == 1

    def test_query_returns_correct_class(
        self, tmp_path: Path, sample_template: AttackTemplate
    ) -> None:
        engine = ResearchEngine(
            store_path=tmp_path / "store.json",
            scrapers=[],
        )
        engine.store.add(sample_template)
        results = engine.query(vulnerability_class="SSRF")
        assert len(results) == 1

    def test_get_all_payloads(
        self, tmp_path: Path, sample_template: AttackTemplate
    ) -> None:
        engine = ResearchEngine(store_path=tmp_path / "store.json", scrapers=[])
        engine.store.add(sample_template)
        payloads = engine.get_all_payloads(vulnerability_class="SSRF")
        assert "http://169.254.169.254/latest/meta-data#" in payloads

    def test_summary(self, tmp_path: Path, sample_template: AttackTemplate) -> None:
        engine = ResearchEngine(store_path=tmp_path / "store.json", scrapers=[])
        engine.store.add(sample_template)
        s = engine.summary()
        assert s["total_templates"] == 1
        assert "SSRF" in s["by_vulnerability_class"]
        assert "CRITICAL" in s["by_severity"]


# ---------------------------------------------------------------------------
# DynamicAttackGenerator tests
# ---------------------------------------------------------------------------


class TestDynamicAttackGenerator:
    def test_get_attacks_returns_base_attacks(
        self, tmp_path: Path, sample_template: AttackTemplate
    ) -> None:
        from crucible.attacks.base import BaseAttack

        gen = DynamicAttackGenerator(store_path=tmp_path / "store.json")
        gen._engine.store.add(sample_template)

        attacks = gen.get_attacks(vulnerability_class="SSRF")
        assert len(attacks) == 1
        assert isinstance(attacks[0], BaseAttack)

    def test_get_attacks_payloads_correct(
        self, tmp_path: Path, sample_template: AttackTemplate
    ) -> None:
        gen = DynamicAttackGenerator(store_path=tmp_path / "store.json")
        gen._engine.store.add(sample_template)

        attacks = gen.get_attacks()
        assert "http://169.254.169.254/latest/meta-data#" in attacks[0].get_payloads()

    def test_get_attacks_empty_when_no_payloads(self, tmp_path: Path) -> None:
        """Templates with no payloads should be skipped."""
        empty_template = AttackTemplate(
            id="empty001",
            source="test",
            url="https://example.com",
            title="Empty Template",
            vulnerability_class="SSRF",
            cwe_id="CWE-918",
            target_context="",
            attack_description="",
            payloads=[],  # No payloads
            bypass_techniques=[],
            detection_patterns=[],
            severity="HIGH",
        )
        gen = DynamicAttackGenerator(store_path=tmp_path / "store.json")
        gen._engine.store.add(empty_template)
        attacks = gen.get_attacks()
        assert attacks == []

    def test_summary(self, tmp_path: Path, sample_template: AttackTemplate) -> None:
        gen = DynamicAttackGenerator(store_path=tmp_path / "store.json")
        gen._engine.store.add(sample_template)
        s = gen.summary()
        assert s["total_templates"] == 1
