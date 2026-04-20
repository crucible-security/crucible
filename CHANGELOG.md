# Changelog

All notable changes to Crucible will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-01

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

[Unreleased]: https://github.com/crucible-security/crucible/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/crucible-security/crucible/releases/tag/v0.1.0
