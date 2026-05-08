# Changelog

All notable changes to Crucible will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-05-05

### Added
- **Behavioral Drift Engine** (`crucible behavioral-audit`) — multi-turn conversation simulation
  with TF-cosine similarity drift detection across 3 audit phases (baseline, escalation, trust degradation)
- **Context-Aware Agent Profiler** (`crucible profile`) — auto-discovers agent type (SQL, HR, CS, etc.)
  and infers capabilities (code execution, web search, internal DB access); outputs `agent_profile.json`
- **Multi-turn Attack Engine** — `--strategy multi-turn` flag for `crucible scan` with two strategies:
  - *Crescendo* — incremental severity escalation across turns
  - *Context Confusion* — alternating benign/malicious turns to break context boundaries
- **EU AI Act 2024 Compliance Module** (`crucible compliance-report`) — maps findings to
  Articles 10, 14, 15, and 50 with automated remediation guidance
- **Compliance Reporter** — generates structured Markdown/JSON compliance reports
- `BehavioralEscalationSequence` attack with 10 trust-escalation payloads
- `--profile` flag for `crucible scan` to load profiler output and target attacks
- New Pydantic models: `BehavioralProfile`, `DriftScore`, `AgentProfile`,
  `ComplianceReport`, `ComplianceRequirement`, `ConversationHistory`, `ConversationTurn`

### Fixed
- Enum `str()` representation inconsistency across Python versions in bug bounty reporter
  (now uses `.value.upper()` for consistent output on Python 3.10–3.14)
- `jmespath` import type annotation in `response_extractor.py`

## [0.2.0] - 2026-05-05

### Added
- **Mutation Engine** (`--mutate`) — 6 payload obfuscation strategies to bypass WAFs and guardrails:
  Base64, URL encoding, Hex, Unicode escaping, Whitespace injection, Polyglot wrapping
- **Bug Bounty Report Generator** (`--generate-report`) — auto-generates Markdown PoC reports
  for Critical/High findings, formatted for HackerOne/Bugcrowd submission
- **HTML Reporter** — rich visual scan report with interactive findings table
- **Slack Reporter** — webhook integration for real-time scan notifications
- **Scan Cache** — TTL-based result caching to avoid redundant scans (`--cache`, `--cache-ttl`)
- **Verbose logging** (`--verbose`) — granular payload/response logs to stderr
- **Rate limiting** — `--delay` flag for respectful scanning of production APIs
- **Scope enforcement** — `--scope` flag to restrict scanning to defined URL patterns
- **Enterprise Graph attacks** — cross-agent trust exploitation vectors
- **Advanced Orchestration attacks** — A2A contagion, parser differential polyglot, URL hallucination
- **Memory Poisoning attacks** — persistent state manipulation across sessions
- **Infrastructure Escalation attacks** — SSRF and cloud metadata exfiltration tests
- **MCP Security module** — Model Context Protocol trust boundary testing
- **LangChain example** — ready-to-run integration test for LangChain/LangServe agents
- Body template presets (`--format-preset`) for OpenAI, Anthropic, Ollama API formats
- `--retry` and `--timeout` flags for resilient scanning

## [0.1.0] - 2026-04-21

### Added
- Core Pydantic data models: `AgentTarget`, `Finding`, `ModuleResult`, `ScanResult`
- 50 prompt injection attack vectors (PI-001 through PI-050)
- 20 goal hijacking attack vectors (GH-001 through GH-020)
- 20 jailbreak attack vectors (JB-001 through JB-020)
- Security modules: `PromptInjectionModule`, `GoalHijackingModule`, `JailbreakModule`
- Async scan runner with parallel module execution via `anyio`
- CVSS-inspired scoring engine with letter grading (A+ through F)
- Rich terminal reporter with color-coded findings and score visualization
- JSON reporter for CI/CD integration
- Typer CLI with `init`, `scan`, and `report` commands
- Full type annotations with strict mypy compliance
- Comprehensive test suite (88%+ coverage)
- GitHub Actions CI/CD pipelines (lint, test, publish)

[Unreleased]: https://github.com/crucible-security/crucible/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/crucible-security/crucible/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/crucible-security/crucible/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/crucible-security/crucible/releases/tag/v0.1.0
