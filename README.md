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

<p align="center">
  <a href="https://pypi.org/project/crucible-security/"><img src="https://img.shields.io/badge/pypi-v0.1.0-blueviolet?style=flat-square" alt="PyPI"></a>
  <a href="https://pypi.org/project/crucible-security/"><img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square" alt="Python 3.9+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/crucible-security/crucible/stargazers"><img src="https://img.shields.io/github/stars/crucible-security/crucible?style=flat-square" alt="Stars"></a>
</p>

---



## Install

```bash
pip install crucible-security
```

## Quick Start

```bash
crucible init --target https://my-agent.com/api/chat
crucible scan --target https://my-agent.com/api/chat
crucible report crucible-report.json
```

**One command. 90 attacks. Beautiful report.**

## Why Crucible?

- **Automated red-teaming** -- 90 real attack payloads run in under 60 seconds, not weeks of manual testing
- **OWASP-aligned** -- maps every attack to the OWASP Top 10 for LLM Applications and OWASP Agentic Top 10
- **CI/CD native** -- `crucible scan --output json` pipes into any pipeline; fail builds on low grades

## Modules

| Module | Attacks | Status | OWASP Coverage |
|--------|---------|--------|----------------|
| Prompt Injection | 50 | Live | LLM01, LLM07 |
| Goal Hijacking | 20 | Live | Agentic #1 |
| Jailbreaks | 20 | Live | LLM01, LLM06 |
| Tool Misuse | -- | Coming | Agentic #3 |
| Identity Abuse | -- | Coming | Agentic #4 |
| Memory Poisoning | -- | Coming | Agentic #5 |
| Data Exfiltration | -- | Coming | LLM06 |
| Hallucination | -- | Coming | LLM09 |

## OWASP Agentic Top 10 Coverage

| # | Category | Crucible Module | Status |
|---|----------|-----------------|--------|
| 1 | Goal Hijacking | `goal_hijacking` | Covered (20 attacks) |
| 2 | Prompt Injection | `prompt_injection` | Covered (50 attacks) |
| 3 | Tool Misuse | -- | Planned |
| 4 | Identity Abuse | -- | Planned |
| 5 | Memory Poisoning | -- | Planned |
| 6 | Data Exfiltration | `prompt_injection` | Partial (via PI-005, PI-006) |
| 7 | Scope Violation | -- | Planned |
| 8 | Cascading Failure | -- | Planned |
| 9 | Supply Chain | -- | Planned |
| 10 | Rogue Agent | -- | Planned |

## Supported Providers

| Provider | Tested |
|----------|--------|
| OpenAI (GPT-4, GPT-4o) | Yes |
| Anthropic (Claude) | Yes |
| Groq (Llama, Mixtral) | Yes |
| Custom HTTP endpoint | Yes |

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

# Run a full scan
crucible scan \
  --target https://my-agent.com/api/chat \
  --name "My ChatBot" \
  --header "Authorization: Bearer sk-xxx" \
  --timeout 30 \
  --concurrency 5

# JSON output for CI/CD
crucible scan --target URL --output json > report.json

# Re-render a saved report
crucible report report.json
```

## CI/CD Integration

```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    pip install crucible-security
    crucible scan \
      --target ${{ secrets.AGENT_URL }} \
      --header "Authorization: Bearer ${{ secrets.AGENT_KEY }}" \
      --output json > crucible-report.json

- name: Check Grade
  run: |
    grade=$(python -c "import json; print(json.load(open('crucible-report.json'))['grade'])")
    if [ "$grade" = "F" ] || [ "$grade" = "D" ]; then
      echo "Security grade $grade -- failing pipeline"
      exit 1
    fi
```

## Architecture

```
crucible/
  models.py             # Pydantic data models
  cli.py                # Typer CLI (init, scan, report)
  attacks/
    base.py             # BaseAttack ABC
    prompt_injection.py # 50 attack vectors
    goal_hijacking.py   # 20 attack vectors
    jailbreaks.py       # 20 attack vectors
  modules/
    base.py             # BaseModule ABC
    security.py         # Module registry
  core/
    runner.py           # Async parallel scan engine (anyio)
    scorer.py           # Deduction-based scoring + grading
  reporters/
    base.py             # BaseReporter ABC
    terminal.py         # Rich terminal renderer
    json_reporter.py    # JSON file exporter
```

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
