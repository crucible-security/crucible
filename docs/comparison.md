# Crucible vs Garak vs PyRIT — Security Tool Comparison

> **Last updated:** April 2025 · **Next review:** July 2025
>
> This document is reviewed quarterly to reflect changes in each tool's capabilities.
> If you spot an inaccuracy, please open an issue or submit a PR.

---

## Overview

| | **Crucible** | **Garak** (NVIDIA) | **PyRIT** (Microsoft) |
|---|---|---|---|
| **Primary focus** | HTTP AI agent security scanning | LLM model vulnerability probing | AI red-teaming automation framework |
| **Target audience** | Agent developers, AppSec engineers | ML researchers, model evaluators | Enterprise AI red teams |
| **Open source** | ✅ MIT | ✅ Apache 2.0 | ✅ MIT |
| **First release** | 2025 | 2023 | Feb 2024 |
| **Language** | Python | Python | Python |
| **Backed by** | Community | NVIDIA AI Red Team | Microsoft AI Red Team |

---

## Feature Matrix

### 🔒 Security Coverage

| Feature | Crucible | Garak | PyRIT |
|---------|----------|-------|-------|
| **OWASP LLM Top 10** | ✅ Full mapping | ✅ Taxonomy mapping | ⚠️ Partial (manual alignment) |
| **OWASP Agentic Top 10** | ✅ Native (ASI01–ASI10) | ❌ Not yet | ❌ Not yet |
| **Prompt Injection** | ✅ 127+ attack payloads | ✅ 50+ probe modules | ✅ Automated multi-turn |
| **Goal Hijacking** | ✅ Dedicated module | ✅ Via probes | ⚠️ Requires custom orchestration |
| **Jailbreaks (DAN-style)** | ✅ 40+ payloads | ✅ Comprehensive | ✅ Via converters |
| **Data Leakage / PII** | ✅ | ✅ (training data extraction) | ✅ |
| **MCP Security** | ✅ Native module | ❌ No native support | ❌ No native support |
| **Tool misuse / Excessive Agency** | ✅ Dedicated module | ⚠️ Limited | ⚠️ Limited |
| **Hallucination testing** | ❌ Out of scope | ✅ | ❌ |
| **Toxicity / Policy violations** | ❌ Out of scope | ✅ | ✅ Via scorers |
| **Multi-turn conversation attacks** | ❌ Single-turn HTTP | ❌ Single-turn by default | ✅ Native strength |

---

### 🎯 Target & Integration

| Feature | Crucible | Garak | PyRIT |
|---------|----------|-------|-------|
| **Target type** | Any HTTP endpoint | LLM APIs + local models | LLM APIs + Azure services |
| **Framework-agnostic** | ✅ Any agent over HTTP | ✅ Any model with a generator | ⚠️ Primarily Azure-centric |
| **LangChain agents** | ✅ Via HTTP wrapper | ⚠️ Via REST generator | ⚠️ Via custom orchestration |
| **OpenAI agents** | ✅ | ✅ | ✅ |
| **Anthropic Claude** | ✅ | ✅ | ✅ |
| **Local models (Ollama etc.)** | ⚠️ Via HTTP wrapper | ✅ Native | ⚠️ Via endpoints |
| **Hugging Face** | ⚠️ Via HTTP | ✅ Native | ✅ Native |

---

### 📦 Developer Experience

| Feature | Crucible | Garak | PyRIT |
|---------|----------|-------|-------|
| **pip installable** | ✅ `pip install crucible-security` | ✅ `pip install garak` | ✅ `pip install pyrit` |
| **CLI interface** | ✅ Rich terminal UI | ✅ CLI + config files | ❌ Python API only |
| **Zero-config quickstart** | ✅ One command | ⚠️ Requires generator config | ❌ Requires scripting |
| **Scan caching** | ✅ Built-in (`--cache`) | ❌ | ❌ |
| **VS Code extension** | ✅ (stub/alpha) | ❌ | ❌ |
| **CI/CD integration** | ✅ Exit codes + JSON output | ⚠️ JSONL reports | ⚠️ Requires scripting |
| **JSON report output** | ✅ `--output json` | ✅ JSONL | ⚠️ Via custom scorers |
| **Progress reporting** | ✅ Rich progress bar | ⚠️ Basic logging | ❌ |

---

### 📊 Scoring & Reporting

| Feature | Crucible | Garak | PyRIT |
|---------|----------|-------|-------|
| **CVSS-style severity scoring** | ✅ Per-finding severity + overall score | ❌ Pass/fail per probe | ⚠️ Via scoring engine |
| **A–F grade system** | ✅ | ❌ | ❌ |
| **OWASP mapping in reports** | ✅ | ✅ Taxonomy grouping | ⚠️ Manual |
| **HTML report** | ❌ (roadmap) | ✅ | ❌ |
| **Baseline comparison** | ❌ (roadmap) | ⚠️ | ⚠️ |

---

## Honest Assessment

### Where Crucible Leads

- **Agentic-first design**: Crucible is the only tool in this comparison with native OWASP Agentic Top 10 coverage and a dedicated MCP security module — reflecting the real-world shift from model-level to system-level agent security.
- **Zero-friction CLI**: `crucible scan --target <url>` is genuinely the fastest path from zero to a security grade. No configuration files, no boilerplate Python scripts.
- **Agent HTTP universality**: Because Crucible targets HTTP endpoints, it works with every stack — LangChain, AutoGen, CrewAI, custom FastAPI, LangServe — without any SDK dependency.
- **Scan caching**: Unique built-in caching (`--cache`, `--cache-ttl`) makes Crucible practical in CI/CD pipelines where scanning 500+ attacks per commit would be prohibitive.

### Where Garak Leads

- **Depth of model-level probing**: Garak has 50+ probe modules with extraordinary depth, covering hallucination, package hallucination, XSS injection, encoding-based bypasses, and more. If you need to audit a *model* (not just an agent endpoint), Garak is the gold standard.
- **Local model support**: Garak natively supports Ollama, Hugging Face local inference, and NVIDIA NIM — Crucible requires an HTTP wrapper.
- **Academic rigour**: Garak produces structured JSONL and HTML reports aligned to published research, making it preferred in ML research environments.

### Where PyRIT Leads

- **Multi-turn attack sophistication**: PyRIT was built specifically for complex, stateful attacks (Crescendo, PAIR, TAP) across multiple conversation turns. No other tool in this list matches its depth for multi-turn adversarial simulation.
- **Red-team flexibility**: PyRIT's modular orchestrators, converters, and scorers provide maximum flexibility for large enterprise red teams who need bespoke attack campaigns.
- **Azure ecosystem integration**: If your stack runs on Azure OpenAI, Azure ML endpoints, and Azure Content Safety, PyRIT integrates natively with the entire ecosystem.

---

## Decision Guide

```
Are you a developer who wants a quick security grade on your agent endpoint?
  → Crucible (fastest time-to-value, best for CI/CD)

Do you need to evaluate a raw LLM model's safety, not just an agent endpoint?
  → Garak (deepest model-level probe coverage)

Do you run an enterprise AI red team and need flexible, multi-turn attack campaigns?
  → PyRIT (most powerful orchestration for professional red teamers)

Are you scanning agents that use MCP tool calling?
  → Crucible (only tool with native MCP security module)
```

---

## Summary Table

| | Crucible | Garak | PyRIT |
|---|---|---|---|
| **Best for** | Agent endpoint security in CI/CD | Model-level red teaming | Enterprise AI red team campaigns |
| **Setup time** | ⚡ < 1 minute | 🕐 5–15 minutes | 🕑 30+ minutes |
| **OWASP Agentic Top 10** | ✅ Full | ❌ | ❌ |
| **MCP Security** | ✅ | ❌ | ❌ |
| **Multi-turn attacks** | ❌ | ❌ | ✅ |
| **Local model support** | ❌ | ✅ | ✅ |
| **Scan caching** | ✅ | ❌ | ❌ |
| **CLI UX** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |

---

*These tools are complementary, not mutually exclusive. Mature security programs may use all three:
Crucible for fast CI/CD agent scans, Garak for periodic deep model audits, and PyRIT for dedicated red-team exercises.*
