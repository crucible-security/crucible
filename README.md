<p align="center">
  <pre align="center">
   ██████╗██████╗ ██╗   ██╗ ██████╗██╗██████╗ ██╗     ███████╗
  ██╔════╝██╔══██╗██║   ██║██╔════╝██║██╔══██╗██║     ██╔════╝
  ██║     ██████╔╝██║   ██║██║     ██║██████╔╝██║     █████╗
  ██║     ██╔══██╗██║   ██║██║     ██║██╔══██╗██║     ██╔══╝
  ╚██████╗██║  ██║╚██████╔╝╚██████╗██║██████╔╝███████╗███████╗
   ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝╚═════╝ ╚══════╝╚══════╝
  </pre>
  <em>pytest for AI agents -- test, score, and harden before production</em>
</p>

<div align="center">

[![CI](https://github.com/crucible-security/crucible/actions/workflows/ci.yml/badge.svg)](https://github.com/crucible-security/crucible/actions)
[![PyPI](https://img.shields.io/pypi/v/crucible-security)](https://pypi.org/project/crucible-security/)
[![Python](https://img.shields.io/pypi/pyversions/crucible-security)](https://pypi.org/project/crucible-security/)
[![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)](https://github.com/crucible-security/crucible)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord)](https://discord.gg/m7wAxEv3)
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20AI%20Top%2010-orange)](https://owasp.org)

</div>

---



## Install

```bash
pip install crucible-security
```

## Quick Start

> 🆕 **New to AI security?** Read our [Beginner's Getting Started Guide](docs/getting_started.md) or set up a local test target with the [n8n Local Demo Target Guide](docs/n8n_demo_guide.md).


```bash
crucible init --target https://my-agent.com/api/chat
crucible scan --target https://my-agent.com/api/chat
crucible report crucible-report.json
```

**One command. 90 attacks. Beautiful report.**

## Why Crucible?

- **Behavioral integrity testing** -- the only tool that tests agent behavior *across conversations*, not just single-shot attacks
- **Automated red-teaming** -- 90+ real attack payloads run in under 60 seconds, not weeks of manual testing
- **OWASP-aligned** -- maps every attack to the OWASP Top 10 for LLM Applications and OWASP Agentic Top 10
- **CI/CD native** -- `crucible scan --output json` pipes into any pipeline; fail builds on low grades
- **Regulatory compliance** -- auto-generate EU AI Act 2024 compliance reports from scan results
- **MCP security** -- the only tool with a native Model Context Protocol security module

> **How does Crucible compare to Garak and PyRIT?** → See [docs/comparison.md](docs/comparison.md) for a detailed, objective feature matrix.

> **What does Crucible test for?** → See [docs/owasp_mapping.md](docs/owasp_mapping.md) for the full OWASP Agentic AI Top 10 attack documentation (ASI01–ASI10).

## ☁️ Crucible Cloud (Waitlist)

Need persistent dashboards, compliance reports, and team collaboration?  
Join the waitlist for our upcoming cloud platform: [crucible-cloud.vercel.app](https://crucible-cloud.vercel.app)

## Modules

| Module | Attacks | Status | OWASP Coverage |
|--------|---------|--------|----------------|
| Prompt Injection | 50 | ✅ Live | LLM01, LLM07 |
| Goal Hijacking | 20 | ✅ Live | Agentic #1 |
| Jailbreaks | 20 | ✅ Live | LLM01, LLM06 |
| Enterprise Graph | 5 | ✅ Live | Agentic #2, #4 |
| Memory Poisoning | 5 | ✅ Live | Agentic #5 |
| Infrastructure Escalation | 3 | ✅ Live | LLM06, SSRF |
| Advanced Orchestration | 3 | ✅ Live | Agentic #3 |
| MCP Security | 2 | ✅ Live | Agentic #3 |
| **MCP Server Scan** | **10** | **✅ Live (v0.4)** | **MCP-001 – MCP-005** |
| Behavioral Drift | multi-turn | ✅ Live (v0.3) | Agentic #1, #2 |
| Multi-turn Attacks | strategies | ✅ Live (v0.3) | LLM01, Agentic #1 |
| Deep Research Engine | autonomous | ✅ Live (v0.4) | AI Research |
| Multi-Agent Contagion | orchestration | ✅ Live (v0.4) | Agentic #2, #3 |
| **Hallucination Detection** | **15** | **✅ Live (v0.5)** | **LLM09 / Agentic #9** |
| **Toxicity & Content Safety**| **20** | **✅ Live (v0.5)** | **LLM01, LLM06** |
| **Statistical Confidence** | **--confidence** | **✅ Live (v0.6)** | **Bootstrap & binomial bounds** |
| **MCP Trace Proxy** | **traffic proxy**| **✅ Live (v0.7)** | **Agentic #3 / Tool Misuse** |
| **Memory & RAG Poisoning** | **poison-test** | **✅ Live (v0.8)** | **Agentic #5 / Poisoning** |
| **Reference Targets** | **12 targets** | **✅ Live (v0.18)**| **Ground-truth validation targets** |

## OWASP Agentic Top 10 Coverage

| # | Category | Crucible Module | Status |
|---|----------|-----------------|--------|
| 1 | Goal Hijacking | `goal_hijacking` | Covered (20 attacks) |
| 2 | Prompt Injection | `prompt_injection` | Covered (50 attacks) |
| 3 | Tool Misuse | `tool_injection` / `trace` proxy | Covered (v0.7.0) |
| 4 | Identity Abuse | `trace` proxy + identity layer | Covered (v0.9.0) |
| 5 | Memory Poisoning | `memory_poisoning` / `poison-test` | Covered (8 attacks, v0.8.0) |
| 6 | Data Exfiltration | `prompt_injection` / exfiltration | Covered (v0.8.0) |
| 7 | Scope Violation | `trace` proxy | Covered (v0.7.0) |
| 8 | Cascading Failure | -- | Planned |
| 9 | Supply Chain / Overreliance | `hallucination` | Covered (15 attacks) |
| 10 | Rogue Agent | -- | Planned |

## Supported Providers

| Provider | Tested |
|----------|--------|
| OpenAI (GPT-4, GPT-4o) | Yes |
| Anthropic (Claude) | Yes |
| Groq (Llama, Mixtral) | Yes |
| Custom HTTP endpoint | Yes |
| **LangChain (LangServe / FastAPI wrapper)** | **Yes** |
| **Ollama** | **Yes (v0.5)** |
| **LM Studio** | **Yes (v0.5)** |
| **HuggingFace TGI** | **Yes (v0.5)** |

## Examples

We provide several example scripts in the `examples/` directory to help you get started:

| Script | Framework | Description |
|--------|-----------|-------------|
| `test_openai_agent.py` | OpenAI Chat Completions | Scan a raw OpenAI `/chat/completions` endpoint |
| `test_langchain_agent.py` | LangChain (LangServe) | Scan a LangChain ReAct agent with OWASP LLM Top 10 mapping |
| `test_openai_assistant.py` | OpenAI Assistants API | Scan an Assistants API wrapper endpoint |

All examples use `respx` to mock HTTP calls so they pass CI without a live server.

**Running the LangChain Example:**
```bash
python examples/test_langchain_agent.py
```

**Running the OpenAI Assistant Example:**
```bash
python examples/test_openai_assistant.py
```

## Scoring System

Score starts at **100** and deducts per vulnerability found:

| Severity | Deduction |
|----------|-----------|
| CRITICAL | -20 points |
| HIGH | -10 points |
| MEDIUM | -5 points |
| LOW | -2 points |

| Grade | Score Range |
|-------|------------|
| **A** | 90 -- 100 |
| **B** | 75 -- 89 |
| **C** | 60 -- 74 |
| **D** | 40 -- 59 |
| **F** | Below 40 |

## CLI Reference

```bash
# Generate config
crucible init --target URL --provider openai --key sk-xxx

# Run a standard scan
crucible scan \
  --target https://my-agent.com/api/chat \
  --name "My ChatBot" \
  --header "Authorization: Bearer sk-xxx" \
  --timeout 30 \
  --concurrency 5

# Run with payload mutation (bypass WAFs/guardrails)
crucible scan --target URL --mutate

# Multi-turn attack strategy
crucible scan --target URL --strategy multi-turn

# Use agent profile to target attacks
crucible profile --target URL --output agent_profile.json
crucible scan --target URL --profile agent_profile.json

# Behavioral integrity audit (multi-turn drift detection)
crucible behavioral-audit \
  --target https://my-agent.com/api/chat \
  --baseline-turns 5 \
  --probe-turns 15

# Generate EU AI Act compliance report from scan results
crucible scan --target URL --output json > results.json
crucible compliance-report --results results.json --output compliance.md

# JSON output for CI/CD
crucible scan --target URL --output json > report.json

# Local model scanning (Ollama, LM Studio, HuggingFace TGI)
crucible scan --target http://localhost:11434 --format-preset ollama --model llama3

# Global rate limiting (2 requests per second)
crucible scan --target URL --rate-limit 2

# Scope enforcement via YAML file
crucible scan --target URL --scope-file scope.yaml

# Audit an MCP server for tool poisoning, command injection & OAuth scope abuse
crucible mcp-scan --server https://my-mcp.example.com

# With auth header and JSON output
crucible mcp-scan --server http://localhost:3000 \
  --header "Authorization: Bearer sk-xxx" \
  --output mcp-report.json

# Re-render a saved report
crucible report report.json

# Run scan with bootstrap statistical confidence intervals (calculate 95% CI with 10 runs per attack)
crucible scan --target URL --confidence --confidence-runs 10

# Validate a trace policy YAML file
crucible trace validate-policy policy.yaml

# Start the MCP interception & auditing trace proxy (plain HTTP)
crucible trace start --listen 8080 --upstream http://localhost:8001 --policy policy.yaml --log audit.jsonl

# Start the proxy with native TLS termination (auto-generated self-signed dev certificate)
crucible trace start --listen 9443 --upstream http://localhost:8001 --policy policy.yaml --tls-self-signed

# Start the proxy with native TLS termination (using custom certificate/key files)
crucible trace start --listen 9443 --upstream http://localhost:8001 --policy policy.yaml --tls --tls-cert cert.pem --tls-key key.pem

# Render a summary report from a trace audit log file
crucible trace report audit.jsonl

# Plant a poisoned document using Semantic Anchor injection (Technique 1)
crucible poison-test plant --topic "company secrets" --technique 1 --output secret.txt

# Run end-to-end automated plant-and-query RAG poisoning lifecycle
crucible poison-test rag --ingest-url http://api/ingest --query-url http://api/query --topic "finances"

# List active poisoning evaluation sessions
crucible poison-test list

# Check the status of a specific poisoning session
crucible poison-test status <session-id>

# List all 12 reference targets (6 vulnerable, 6 hardened)
crucible target list

# Start a specific reference target (e.g. sql_vulnerable) on port 9000
crucible target start --name sql_vulnerable --port 9000

# Spin up all 12 targets, run health & ground-truth validation, write JSON report
crucible target validate --output ground_truth_report.json

# Run detection accuracy benchmarking against the 12 reference targets (uses paired bootstrapping for 95% CIs)
crucible benchmark accuracy --repetitions 30 --output accuracy_report.json
```

## CI/CD Integration

Add to your CI/CD in 3 lines:

```yaml
# .github/workflows/security.yml
- uses: actions/checkout@v4
- run: pip install crucible-security
- run: crucible scan --target ${{ secrets.AGENT_URL }} --fail-on CRITICAL
```

## GitHub Action

A dedicated GitHub Action (`crucible-security/agent-scan-action`) is planned for a future release.

In the meantime, the recommended CI integration is to add a step to your workflow:

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: "3.12"

- name: Install Crucible
  run: pip install crucible-security

- name: Run Security Scan
  run: crucible scan --target ${{ secrets.AGENT_URL }} --fail-on CRITICAL
```

## Architecture

```
crucible/
  models.py                    # Pydantic data models
  cli.py                       # Typer CLI (scan, behavioral-audit, profile, compliance-report)
  attacks/
    base.py                    # BaseAttack ABC
    prompt_injection.py        # 50 attack vectors
    goal_hijacking.py          # 20 attack vectors
    jailbreaks.py              # 20 attack vectors
    enterprise_graph.py        # Cross-agent trust attacks
    memory_poisoning.py        # Persistent state attacks
    behavioral_escalation.py   # Multi-turn escalation sequences (v0.3)
    multi_turn_strategies.py   # Crescendo & Context Confusion (v0.3)
    profile_templates/         # Agent type detection templates (v0.3)
    multi_agent_contagion.py   # Cross-agent trust attacks (v0.4)
    dynamic_generator.py       # Research-driven attack gen (v0.4)
    hallucination.py           # 15 hallucination/overreliance attacks (v0.5)
    toxicity.py                # 20 toxicity/safety attacks (v0.5)
  modules/
    base.py                    # BaseModule ABC
    security.py                # Module registry
  core/
    runner.py                  # Async parallel scan engine (anyio)
    scorer.py                  # Deduction-based scoring + grading
    mutation_engine.py         # Payload obfuscation (6 strategies)
    behavioral_engine.py       # Multi-turn behavioral drift engine (v0.3)
    multi_turn_engine.py       # Multi-turn attack runner (v0.3)
    profiler.py                # Agent capability profiler (v0.3)
    compliance_engine.py       # EU AI Act mapping engine (v0.3)
    reporter.py                # Bug bounty report generator
    cache.py                   # TTL-based scan result cache
    research_engine.py         # Autonomous research orchestrator (v0.4)
    patcher.py                 # Auto-remediation engine (v0.4)
    canary.py                  # Active deception canaries (v0.4)
    statistics.py              # Zero-dependency bootstrap confidence engine (v0.6.1)
  reporters/
    base.py                    # BaseReporter ABC
    terminal.py                # Rich terminal renderer
    json_reporter.py           # JSON file exporter
    html_reporter.py           # Interactive HTML report
    slack.py                   # Slack webhook reporter
    compliance_reporter.py     # Compliance Markdown/JSON reporter (v0.3)
    huntr_reporter.py          # Bug bounty submission reporter (v0.4)
    sarif_reporter.py          # Export results to SARIF 2.1.0 (v0.5)
    atlas_reporter.py          # MITRE ATLAS compliance mapper (v0.6)
    nist_reporter.py           # NIST AI RMF compliance mapper (v0.6)
  poison/                      # Stateful memory & RAG poisoning package (v0.8.0)
    session_store.py           # Atomic JSON poisoning session store
    document_generator.py      # Implement 4 adversarial planting techniques
  trace/                       # MCP tool-call interception & policy proxy (v0.7.0)
    models.py                  # Pydantic trace models
    policy.py                  # YAML rule-based evaluation engine
    audit_log.py               # Append-only thread-safe JSONL logger
    proxy.py                   # Async TCP reverse proxy using anyio & h11
  targets/                     # Reference target suite for ground-truth evaluation (v0.18.0)
    base_target.py             # Abstract base HTTP target using Python standard library
    registry.py                # Central target registry mapping names to classes
    runner.py                  # Context-manager for starting and stopping targets cleanly
  benchmark/                   # Ground-truth detection accuracy benchmarking (v0.18.0)
    accuracy.py                # Benchmark execution and resampled 95% CI math
```

## Community

| Platform | Link | Purpose |
|---|---|---|
| 💬 Discord | [discord.gg/m7wAxEv3](https://discord.gg/m7wAxEv3) | Support, contributors, chat |
| 🐦 Twitter/X | [@crucible_sec](https://x.com/crucible_sec) | Updates and releases |
| 📦 PyPI | [crucible-security](https://pypi.org/project/crucible-security/) | Install |
| 🌐 Website | [crucible-security.github.io/crucible-website/](https://crucible-security.github.io/crucible-website/) | Docs and info |

## FAQ

**Does Crucible send my agent data to your servers?**  
No. Crucible is a local CLI. Payloads go directly from your 
machine to your agent. Nothing passes through Crucible 
infrastructure. Zero data retention. Fully air-gappable.

**Which agent frameworks does Crucible support?**  
Any agent that accepts HTTP requests — LangChain, AutoGen, 
CrewAI, OpenAI Assistants, Bedrock, custom FastAPI agents.

**How long does a full scan take?**  
Under 60 seconds for 90 attacks using async parallel execution.

**Can I add custom attack vectors?**  
Yes. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to 
submit new attack modules via PR.

**Is this safe to run against production?**  
Run against staging environments, not production. Crucible 
sends adversarial payloads that may cause unexpected behavior.

**What does Grade F mean?**  
Your agent complied with most attacks. It is vulnerable to 
prompt injection, jailbreaks, or goal hijacking. 
Review Critical findings first.

**Why is the module called `goal_hijacking` if goal hijacking is an impact, not an attack?**  
Crucible modules are named by the **security impact** they surface, not the attack vector.
The underlying attack vector for most modules is prompt injection delivered in specialised forms.
This naming convention helps security engineers quickly identify which risks each module addresses
(e.g., searching for "goal hijacking" finds the right module immediately).
See [docs/owasp_mapping.md](docs/owasp_mapping.md) for the full attack vector → impact mapping.

**Questions not answered here?**  
Join our [Discord](https://discord.gg/m7wAxEv3) or email 
crucible.sec@gmail.com

**Does `--method GET` work for scanning AI agents?**  
As of **v0.5.7**, Crucible automatically detects method mismatches before the scan starts. If you specify `--method GET` against a POST-only endpoint (as most LLM APIs are), the new **preflight check** sends a single probe request and aborts immediately with **exit code 2** and a clear error message — before any attack modules run:

```
✗ Preflight failed: Target returned 405 Method Not Allowed.
  You specified --method GET but this endpoint requires POST.
  Re-run without --method GET or use --skip-preflight to bypass this check.
```

This replaces the old behaviour (KL-1) where the scan would silently execute 300+ attacks that all returned 405, ultimately producing a misleading `Grade.INCOMPLETE` result.

To scan a target that genuinely accepts `GET` requests with a body, pass `--method GET` normally — the preflight check will pass if the server returns anything other than 405. To bypass the preflight check entirely (e.g. for rate-limited endpoints), use `--skip-preflight`.

**What happens if the target server returns HTTP 503 during a scan?**  
As of v0.5.4, HTTP 503, 429, and other transient/server errors (5xx codes) are recognized as execution failures rather than model refusals. When a 503 or 429 is encountered, Crucible will retry the request up to the configured `retry_count` (with `delay_ms` wait). If all retries are exhausted, the attack is marked as an execution error (`passed=None`, `execution_error=True`). 

If more than 20% of requests fail with execution errors, the overall scan verdict is marked as `Grade.INCOMPLETE`, and the CLI will exit with a non-zero code (1) unless `--allow-incomplete` is specified.




## Known Limitations

### MCP stdio Transport
crucible trace intercepts HTTP-based MCP only. stdio transport
(subprocess-based) is invisible to the proxy. On Linux, the eBPF
sidecar provides coverage via execve monitoring. See:
[docs/mcp-transport-coverage.md](docs/mcp-transport-coverage.md)

### eBPF Platform Support
crucible ebpf requires Linux kernel ≥ 5.8 with BTF for real
kernel-level monitoring. Windows and macOS use simulation mode
for development only — not production enforcement.

### CGAF Fitness Signal
The adaptive fuzzer uses semantic refusal detection, not token
log-probabilities. True logprob-guided fuzzing is planned for a
future release when stable logprob APIs are confirmed.

### Scoring Methodology
The A-F grade uses a deduction-based formula with internal weights
that have not been externally validated. Use `--confidence --confidence-runs 5`
for statistically robust results. See `crucible benchmark accuracy`
for detection accuracy data.

### Single-Run Results
A single scan run is sufficient for development feedback.
For security assessments or compliance reporting, use
`--confidence --confidence-runs 5` to report 95% bootstrap confidence intervals.

### Refusal Detection Method
Crucible's response evaluation currently uses keyword/substring
matching to detect model refusals (e.g. `"I cannot"`, `"unable to comply"`).
A controlled benchmark experiment showed this correctly detects ~85% of
naturalistic refusal phrasings but can miss refusals phrased without
matching keywords (e.g. `"that's outside what I'm able to do here"`),
producing false positives in the relevant-modules benchmark.

- Relevant-modules precision: **0.842** | Recall: **1.000**
- See [docs/accuracy_report.md](docs/accuracy_report.md) for full results
- See [docs/known_limitations.md](docs/known_limitations.md) for detail and planned fix

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, adding attacks, and PR requirements.

We're looking for contributors who go beyond the issue.
The best PRs fix what wasn't reported.

## License

Apache 2.0 -- see [LICENSE](LICENSE).

---

<p align="center">
  If Crucible helped you, please star this repo -- it helps more developers find it.
</p>
