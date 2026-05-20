"""Deep Research Engine for Crucible (v0.4.0).

This module provides autonomous intelligence gathering for the Crucible framework.
It scrapes curated security feeds (HackerOne, GitHub Advisories, CVE/MITRE, security
blogs) and uses an LLM to distill unstructured text into structured attack templates
that can be immediately leveraged by the DynamicAttackGenerator.

Architecture:
    ResearchEngine
        ├── BaseScraper (ABC)
        │     ├── HackerOneScraper    — public HackerOne Hacktivity (AI/ML/SSRF tags)
        │     ├── GitHubAdvisoryScraper — GitHub Security Advisories (GraphQL API)
        │     ├── CVEMitreScraper    — NVD JSON feeds filtered by AI/ML CWE IDs
        │     └── BlogScraper        — Configurable list of security blog RSS/HTML
        ├── PatternExtractor          — LLM-based pattern distillation
        └── VectorStore               — Local JSON index of extracted AttackTemplates
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from crucible.models import Finding

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RawResearchItem:
    """A raw piece of security intelligence scraped from a source."""

    source: str
    url: str
    title: str
    content: str
    scraped_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class AttackTemplate:
    """A structured, actionable attack pattern extracted from raw research."""

    id: str  # SHA-256 of (source + title)
    source: str  # Origin feed
    url: str  # Reference URL
    title: str  # Descriptive title
    vulnerability_class: str  # e.g. SSRF, Prompt Injection, RCE
    cwe_id: str  # e.g. CWE-918
    target_context: str  # e.g. "REST API with user-controlled URL"
    attack_description: str  # Textual attack description
    payloads: list[str]  # Ready-to-use attack payloads
    bypass_techniques: list[str]  # Extracted bypass patterns
    detection_patterns: list[str]  # Patterns that indicate a successful exploit
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    success_count: int = 0  # Number of times this template led to a bypass
    failure_count: int = 0  # Number of times this template was refused
    last_success: str | None = None
    extracted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def make_id(cls, source: str, title: str) -> str:
        return hashlib.sha256(f"{source}::{title}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Scrapers
# ---------------------------------------------------------------------------


class BaseScraper(ABC):
    """Abstract base class for all research scrapers."""

    name: str = ""

    def __init__(self, timeout: float = 15.0) -> None:
        self._client_timeout = timeout

    @abstractmethod
    def scrape(self) -> list[RawResearchItem]:
        """Fetch and return raw research items from the source."""
        ...

    def _get(self, url: str, headers: dict[str, str] | None = None) -> str | None:
        """Simple synchronous HTTP GET with error handling."""
        try:
            with httpx.Client(
                timeout=self._client_timeout, follow_redirects=True
            ) as client:
                response = client.get(url, headers=headers or {})
                response.raise_for_status()
                return response.text
        except Exception:
            return None


class HackerOneScraper(BaseScraper):
    """Scrapes HackerOne's public Hacktivity feed for AI/ML/SSRF vulnerability reports.

    Uses the public GraphQL endpoint — no auth required for public disclosures.
    Filters for AI, ML, SSRF, LLM, and prompt-injection tags to surface the most
    relevant offensive intelligence.
    """

    name = "hackerone_hacktivity"

    # Public GraphQL endpoint (no auth required for public activity)
    _GQL_URL = "https://hackerone.com/graphql"

    # Keyword filter for relevant disclosures
    _KEYWORDS = [
        "ssrf",
        "llm",
        "ai",
        "prompt injection",
        "server-side request forgery",
        "rce",
        "remote code execution",
        "idor",
        "path traversal",
    ]

    def scrape(self) -> list[RawResearchItem]:
        """Fetch recent public disclosures and filter for AI/ML relevance."""
        query = """
        query HacktivityPageQuery($cursor: String) {
          hacktivity_items(
            first: 50
            after: $cursor
            where: { disclosed_at: { _is_null: false } }
            order_by: { field: DISCLOSED_AT, direction: DESC }
          ) {
            edges {
              node {
                ... on HacktivityItem {
                  id
                  disclosed_at
                  reporter { username }
                  report {
                    title
                    url
                    severity_rating
                    vulnerability_information
                    weakness { name cwe_id }
                  }
                }
              }
            }
          }
        }
        """
        results: list[RawResearchItem] = []
        try:
            with httpx.Client(
                timeout=self._client_timeout, follow_redirects=True
            ) as client:
                resp = client.post(
                    self._GQL_URL,
                    json={"query": query, "variables": {}},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code != 200:
                    return results

                data = resp.json()
                edges = (
                    data.get("data", {}).get("hacktivity_items", {}).get("edges", [])
                )

                for edge in edges:
                    node = edge.get("node", {})
                    report = node.get("report") or {}
                    title = report.get("title", "")
                    content = report.get("vulnerability_information", "")

                    # Filter for relevant vulnerability classes
                    combined = (title + " " + content).lower()
                    if not any(kw in combined for kw in self._KEYWORDS):
                        continue

                    results.append(
                        RawResearchItem(
                            source=self.name,
                            url=report.get("url", "https://hackerone.com"),
                            title=title,
                            content=content[:4000],  # truncate for LLM context window
                        )
                    )
        except Exception:
            pass

        return results


class GitHubAdvisoryScraper(BaseScraper):
    """Scrapes GitHub Security Advisories for AI/ML packages.

    Uses the public REST API (/advisories endpoint, no auth needed for basic access).
    Targets ecosystems (pip, npm) and relevant CWE IDs.
    """

    name = "github_advisory"

    _BASE_URL = "https://api.github.com/advisories"
    _TARGET_CWES = ["CWE-918", "CWE-611", "CWE-78", "CWE-94", "CWE-502", "CWE-1236"]
    _AI_KEYWORDS = [
        "llm",
        "langchain",
        "openai",
        "anthropic",
        "huggingface",
        "transformers",
        "diffusers",
        "comfyui",
        "lobe",
        "dify",
        "ollama",
    ]

    def scrape(self) -> list[RawResearchItem]:
        """Fetch recent security advisories from GitHub's public advisory database."""
        results: list[RawResearchItem] = []
        try:
            gh_token = os.environ.get("GITHUB_TOKEN", "")
            headers = {"Accept": "application/vnd.github+json"}
            if gh_token:
                headers["Authorization"] = f"Bearer {gh_token}"

            params: dict[str, Any] = {
                "per_page": 100,
                "sort": "updated",
                "direction": "desc",
                "type": "reviewed",
            }

            with httpx.Client(timeout=self._client_timeout) as client:
                resp = client.get(self._BASE_URL, params=params, headers=headers)
                if resp.status_code != 200:
                    return results

                advisories = resp.json()
                for adv in advisories:
                    title = adv.get("summary", "")
                    desc = adv.get("description", "")
                    cwes = [c.get("cwe_id", "") for c in (adv.get("cwes") or [])]

                    # Filter by CWE or AI keyword
                    cwe_match = any(cwe in self._TARGET_CWES for cwe in cwes)
                    keyword_match = any(
                        k in (title + desc).lower() for k in self._AI_KEYWORDS
                    )

                    if not (cwe_match or keyword_match):
                        continue

                    results.append(
                        RawResearchItem(
                            source=self.name,
                            url=adv.get("html_url", "https://github.com/advisories"),
                            title=title,
                            content=desc[:4000],
                        )
                    )
        except Exception:
            pass

        return results


class NVDScraper(BaseScraper):
    """Scrapes the NIST NVD (National Vulnerability Database) for AI-relevant CVEs.

    Uses the public NVD 2.0 REST API to fetch recent CVEs in AI/ML packages.
    No API key required, but rate limits to 5 requests/30s unauthenticated.
    """

    name = "nvd_cve"

    _API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _AI_KEYWORDS = [
        "llm",
        "large language model",
        "machine learning",
        "ai agent",
        "comfyui",
        "langchain",
        "openai",
        "hugging face",
        "stable diffusion",
    ]

    def scrape(self) -> list[RawResearchItem]:
        """Fetch recent AI-relevant CVEs from NVD."""
        results: list[RawResearchItem] = []
        try:
            params = {
                "resultsPerPage": 50,
                "startIndex": 0,
                "keywordSearch": "AI agent LLM",
                "keywordExactMatch": False,
            }
            raw = self._get(
                self._API_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())
            )
            if not raw:
                return results

            data = json.loads(raw)
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"), ""
                )

                if not any(kw in desc.lower() for kw in self._AI_KEYWORDS):
                    continue

                results.append(
                    RawResearchItem(
                        source=self.name,
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        title=cve_id,
                        content=desc[:4000],
                    )
                )
            time.sleep(1)  # Respect NVD rate limits
        except Exception:
            pass

        return results


class SecurityBlogScraper(BaseScraper):
    """Scrapes curated security research blogs for AI vulnerability write-ups.

    Parses RSS/Atom feeds to extract new research articles. Configured with a
    curated list of high-signal Tier 1 security research feeds.
    """

    name = "security_blogs"

    # High-signal RSS feeds — updated 2026-05
    _FEEDS: list[dict[str, str]] = [
        {"name": "PortSwigger Research", "url": "https://portswigger.net/research/rss"},
        {
            "name": "Project Zero",
            "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        },
        {"name": "Trail of Bits", "url": "https://blog.trailofbits.com/rss"},
        {"name": "Snyk Security", "url": "https://snyk.io/blog/feed/"},
        {"name": "Embrace The Red", "url": "https://embracethered.com/blog/index.xml"},
    ]

    _AI_KEYWORDS = [
        "prompt injection",
        "ssrf",
        "llm",
        "jailbreak",
        "ai agent",
        "rag",
        "tool calling",
        "function calling",
        "mcp",
        "model context",
    ]

    def scrape(self) -> list[RawResearchItem]:
        """Parse RSS feeds and filter for AI security relevance."""
        results = []
        for feed in self._FEEDS:
            raw = self._get(
                feed["url"], headers={"User-Agent": "CrucibleResearchBot/0.4.0"}
            )
            if not raw:
                continue

            # Simple regex-based RSS item extraction (no external XML library needed)
            items = re.findall(
                r"<item>(.*?)</item>",
                raw,
                re.DOTALL,
            )
            for item_xml in items[:10]:  # cap at 10 per feed
                title_match = re.search(r"<title>(.*?)</title>", item_xml, re.DOTALL)
                link_match = re.search(r"<link>(.*?)</link>", item_xml, re.DOTALL)
                desc_match = re.search(
                    r"<description>(.*?)</description>", item_xml, re.DOTALL
                )
                if not title_match:
                    continue

                title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip()
                link = link_match.group(1).strip() if link_match else feed["url"]
                desc = (
                    re.sub(r"<[^>]+>", "", desc_match.group(1)).strip()
                    if desc_match
                    else ""
                )

                combined = (title + " " + desc).lower()
                if not any(kw in combined for kw in self._AI_KEYWORDS):
                    continue

                results.append(
                    RawResearchItem(
                        source=f"{self.name}::{feed['name']}",
                        url=link,
                        title=title,
                        content=desc[:4000],
                    )
                )

        return results


# ---------------------------------------------------------------------------
# Pattern Extractor (LLM-powered)
# ---------------------------------------------------------------------------


class PatternExtractor:
    """Uses an LLM to distil raw security research into structured AttackTemplates.

    Supports Google Gemini (default), OpenAI, and Groq. Falls back gracefully
    to a heuristic keyword-based extractor if no API key is available.
    """

    _SYSTEM_PROMPT = (
        "You are an elite offensive security researcher specializing in AI/ML systems. "
        "You will be given raw security research text and must extract a structured JSON "
        "object representing an actionable attack template. Be precise and technical. "
        "Output ONLY valid JSON, no markdown fencing."
    )

    _USER_PROMPT_TEMPLATE = """
Analyze the following security research and extract a structured attack template.

Research title: {title}
Source: {source}
Content:
{content}

Output a JSON object with these EXACT fields:
{{
  "vulnerability_class": "<SSRF | Prompt Injection | RCE | IDOR | SQLi | Path Traversal | Other>",
  "cwe_id": "<e.g. CWE-918>",
  "target_context": "<brief description of vulnerable component>",
  "attack_description": "<step-by-step attack description>",
  "payloads": ["<payload1>", "<payload2>"],
  "bypass_techniques": ["<technique1>", "<technique2>"],
  "detection_patterns": ["<string to look for in response that confirms exploit>"],
  "severity": "<CRITICAL | HIGH | MEDIUM | LOW>"
}}

If no clear attack template can be extracted, output: {{"skip": true}}
"""

    def __init__(self, provider: str = "gemini", api_key: str | None = None) -> None:
        self.provider = provider
        self.api_key = api_key or self._detect_api_key(provider)

    def _detect_api_key(self, provider: str) -> str | None:
        """Auto-detect API key from environment variables."""
        key_map = {
            "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
            "openai": ["OPENAI_API_KEY"],
            "groq": ["GROQ_API_KEY"],
        }
        for env_var in key_map.get(provider, []):
            val = os.environ.get(env_var)
            if val:
                return val
        return None

    def extract(self, item: RawResearchItem) -> AttackTemplate | None:
        """Extract an AttackTemplate from a RawResearchItem using an LLM.

        Falls back to heuristic extraction if no LLM is available.
        """
        if self.api_key:
            return self._extract_with_llm(item)
        return self._extract_heuristic(item)

    def _extract_with_llm(self, item: RawResearchItem) -> AttackTemplate | None:
        """Call the configured LLM provider to extract a structured template."""
        prompt = self._USER_PROMPT_TEMPLATE.format(
            title=item.title,
            source=item.source,
            content=item.content[:3000],
        )

        raw_json: str | None = None

        try:
            if self.provider == "gemini":
                raw_json = self._call_gemini(prompt)
            elif self.provider == "openai":
                raw_json = self._call_openai(prompt)
            elif self.provider == "groq":
                raw_json = self._call_groq(prompt)
        except Exception:
            return self._extract_heuristic(item)

        if not raw_json:
            return self._extract_heuristic(item)

        try:
            # Strip markdown fencing if model added it anyway
            raw_json = re.sub(r"^```[a-z]*\n?", "", raw_json.strip())
            raw_json = re.sub(r"\n?```$", "", raw_json.strip())
            data = json.loads(raw_json)

            if data.get("skip"):
                return None

            return AttackTemplate(
                id=AttackTemplate.make_id(item.source, item.title),
                source=item.source,
                url=item.url,
                title=item.title,
                vulnerability_class=data.get("vulnerability_class", "Unknown"),
                cwe_id=data.get("cwe_id", ""),
                target_context=data.get("target_context", ""),
                attack_description=data.get("attack_description", ""),
                payloads=data.get("payloads", []),
                bypass_techniques=data.get("bypass_techniques", []),
                detection_patterns=data.get("detection_patterns", []),
                severity=data.get("severity", "HIGH"),
            )
        except (json.JSONDecodeError, KeyError):
            return self._extract_heuristic(item)

    def _call_gemini(self, prompt: str) -> str | None:
        """Call Google Gemini 2.0 Flash API."""
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.0-flash:generateContent?key={self.api_key}"
        )
        body = {
            "contents": [{"parts": [{"text": f"{self._SYSTEM_PROMPT}\n\n{prompt}"}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024},
        }
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, json=body)
            resp.raise_for_status()
            return str(
                resp.json()
                .get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )

    def _call_openai(self, prompt: str) -> str | None:
        """Call OpenAI Chat Completions API."""
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": self._SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
            return str(resp.json()["choices"][0]["message"]["content"])

    def _call_groq(self, prompt: str) -> str | None:
        """Call Groq Llama API."""
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": "llama3-70b-8192",
                    "messages": [
                        {"role": "system", "content": self._SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
            return str(resp.json()["choices"][0]["message"]["content"])

    def _extract_heuristic(self, item: RawResearchItem) -> AttackTemplate | None:
        """Fallback heuristic extractor when no LLM is available.

        Uses keyword matching to classify the vulnerability and extract
        simple patterns without requiring an external API.
        """
        content_lower = (item.title + " " + item.content).lower()

        # Classify vulnerability class by keyword priority
        vuln_class = "Unknown"
        cwe = ""
        if any(
            k in content_lower
            for k in ["ssrf", "server-side request forgery", "internal request"]
        ):
            vuln_class, cwe = "SSRF", "CWE-918"
        elif any(
            k in content_lower
            for k in ["prompt injection", "jailbreak", "system prompt"]
        ):
            vuln_class, cwe = "Prompt Injection", "CWE-1048"
        elif any(
            k in content_lower
            for k in ["remote code execution", "rce", "arbitrary code"]
        ):
            vuln_class, cwe = "RCE", "CWE-94"
        elif any(
            k in content_lower
            for k in ["idor", "insecure direct object", "broken access"]
        ):
            vuln_class, cwe = "IDOR", "CWE-639"
        elif any(
            k in content_lower for k in ["path traversal", "directory traversal", "../"]
        ):
            vuln_class, cwe = "Path Traversal", "CWE-22"
        elif any(k in content_lower for k in ["sql injection", "sqli", "union select"]):
            vuln_class, cwe = "SQLi", "CWE-89"
        else:
            return None  # Not interesting enough without an LLM

        # Extract URL-like fragments as candidate payloads
        url_pattern = re.findall(r'https?://[^\s"\'<>]{10,80}', item.content)
        payloads = (
            url_pattern[:3]
            if url_pattern
            else [
                "http://169.254.169.254/latest/meta-data#",
                "http://127.0.0.1:6379/",
            ]
        )

        return AttackTemplate(
            id=AttackTemplate.make_id(item.source, item.title),
            source=item.source,
            url=item.url,
            title=item.title,
            vulnerability_class=vuln_class,
            cwe_id=cwe,
            target_context="Detected via heuristic analysis — verify manually",
            attack_description=item.content[:500],
            payloads=payloads,
            bypass_techniques=["URL fragment truncation (#)", "Hex IP encoding"],
            detection_patterns=["200 OK", "ami-id", "instance-id", "computeMetadata"],
            severity="HIGH",
        )


# ---------------------------------------------------------------------------
# Vector Store (local JSON index)
# ---------------------------------------------------------------------------


class VectorStore:
    """Simple local JSON-based store for AttackTemplates.

    Provides deduplication (by template ID), persistence, and filtered retrieval
    without requiring any external database.
    """

    def __init__(self, store_path: Path | None = None) -> None:
        self._path = store_path or Path.home() / ".crucible" / "research_store.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._templates: dict[str, AttackTemplate] = {}
        self._load()

    def _load(self) -> None:
        """Load existing templates from disk."""
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                for item_data in raw:
                    t = AttackTemplate(**item_data)
                    self._templates[t.id] = t
            except Exception:
                self._templates = {}

    def save(self) -> None:
        """Persist all templates to disk."""
        data = [asdict(t) for t in self._templates.values()]
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def add(self, template: AttackTemplate) -> bool:
        """Add a template. Returns True if new, False if duplicate."""
        if template.id in self._templates:
            return False
        self._templates[template.id] = template
        return True

    def get_all(self) -> list[AttackTemplate]:
        return list(self._templates.values())

    def query(
        self,
        vulnerability_class: str | None = None,
        severity: str | None = None,
        limit: int = 20,
    ) -> list[AttackTemplate]:
        """Filter templates by vulnerability class and/or severity."""
        results = list(self._templates.values())
        if vulnerability_class:
            results = [
                t
                for t in results
                if vulnerability_class.lower() in t.vulnerability_class.lower()
            ]
        if severity:
            results = [t for t in results if t.severity == severity.upper()]

        # Sort by success_count (descending) to prioritize "deadlier" templates
        results.sort(key=lambda x: x.success_count, reverse=True)
        return results[:limit]

    def record_finding(self, finding: Finding) -> None:
        """Update template stats based on scan results."""
        # Find templates that match the vulnerability class and have similar payloads
        # This is a heuristic match for the feedback loop
        for template in self._templates.values():
            if (
                template.vulnerability_class.lower() in finding.category.value.lower()
                and finding.payload in template.payloads
            ):
                # If the payload used is in this template's payload list, update it
                if not finding.passed:  # Bypass occurred
                    template.success_count += 1
                    template.last_success = datetime.now(timezone.utc).isoformat()
                else:
                    template.failure_count += 1
        self.save()

    @property
    def count(self) -> int:
        return len(self._templates)


# ---------------------------------------------------------------------------
# Research Engine (orchestrator)
# ---------------------------------------------------------------------------


class ResearchEngine:
    """Top-level orchestrator for Crucible's deep research capability.

    Usage:
        engine = ResearchEngine(api_key="your_gemini_key")
        new_count = engine.update()
        templates = engine.query(vulnerability_class="SSRF")
    """

    def __init__(
        self,
        provider: str = "gemini",
        api_key: str | None = None,
        store_path: Path | None = None,
        scrapers: list[BaseScraper] | None = None,
    ) -> None:
        self.store = VectorStore(store_path)
        self.extractor = PatternExtractor(provider=provider, api_key=api_key)
        self.scrapers: list[BaseScraper] = scrapers or [
            HackerOneScraper(),
            GitHubAdvisoryScraper(),
            NVDScraper(),
            SecurityBlogScraper(),
        ]

    def update(self, verbose: bool = True) -> int:
        """Run all scrapers, extract patterns, and update the local store.

        Returns the number of new templates added.
        """
        new_count = 0
        total_scraped = 0

        for scraper in self.scrapers:
            if verbose:
                print(f"  [*] Scraping {scraper.name}...", flush=True)

            items = scraper.scrape()
            total_scraped += len(items)

            if verbose:
                print(f"      Found {len(items)} relevant items", flush=True)

            for item in items:
                template = self.extractor.extract(item)
                if template:
                    added = self.store.add(template)
                    if added:
                        new_count += 1
                        if verbose:
                            print(
                                f"      [+] New template: [{template.severity}] "
                                f"{template.vulnerability_class} — {template.title[:60]}",
                                flush=True,
                            )

        self.store.save()

        if verbose:
            print(
                f"\n  Research update complete. "
                f"Scraped: {total_scraped} items | "
                f"New templates: {new_count} | "
                f"Total in store: {self.store.count}",
                flush=True,
            )

        return new_count

    def query(
        self,
        vulnerability_class: str | None = None,
        severity: str | None = None,
        limit: int = 20,
    ) -> list[AttackTemplate]:
        """Query the local store for templates matching the given filters."""
        return self.store.query(
            vulnerability_class=vulnerability_class,
            severity=severity,
            limit=limit,
        )

    def get_all_payloads(self, vulnerability_class: str | None = None) -> list[str]:
        """Flatten all payloads across matching templates into a single list."""
        templates = self.query(vulnerability_class=vulnerability_class)
        payloads: list[str] = []
        seen: set[str] = set()
        for t in templates:
            for p in t.payloads:
                if p not in seen:
                    payloads.append(p)
                    seen.add(p)
        return payloads

    def feedback_loop(self, findings: list[Finding]) -> None:
        """Close the loop by feeding scan results back into the research store."""
        for finding in findings:
            self.store.record_finding(finding)

    def summary(self) -> dict[str, Any]:
        """Return a summary of the current research store."""
        templates = self.store.get_all()
        by_class: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for t in templates:
            by_class[t.vulnerability_class] = by_class.get(t.vulnerability_class, 0) + 1
            by_severity[t.severity] = by_severity.get(t.severity, 0) + 1
        return {
            "total_templates": self.store.count,
            "by_vulnerability_class": by_class,
            "by_severity": by_severity,
            "store_path": str(self.store._path),
        }
