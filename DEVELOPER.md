# Developer Guide

## Architecture Overview

Crucible is organized into four layers:
CLI Layer       crucible/cli.py          — Typer command interface
Attack Layer    crucible/attacks/        — 90+ adversarial payloads
Module Layer    crucible/modules/        — Attack orchestration
Reporter Layer  crucible/reporters/      — Output formatting
Core Layer      crucible/core/           — Runner and scorer

### Attack Vectors vs Impacts — Important Distinction

Crucible's module naming follows a deliberate convention that is important to understand when
reading findings, writing new attacks, or mapping to OWASP:

> **Modules are named by the IMPACT they surface, not the attack vector used to produce it.**

| Concept | Definition | Examples in Crucible |
|---------|-----------|----------------------|
| **Attack Vector** | The *method of delivery* — how malicious input enters the system | Prompt injection (direct/indirect), MCP trust boundary violation |
| **Impact** | The *security consequence* of a successful attack | Goal hijacking, data exfiltration, safety bypass, privilege escalation |

**Key examples:**
- `prompt_injection` module → **attack vector:** direct/indirect prompt injection → **impact tested:** goal hijacking + data exfiltration
- `goal_hijacking` module → **attack vector:** prompt injection (objective-redirect variant) → **impact tested:** goal hijacking (OWASP-AGENT-003)
- `jailbreaks` module → **attack vector:** prompt injection (safety-constraint bypass variant) → **impact tested:** safety bypass (OWASP-AGENT-006)
- `mcp_security` module → **attack vector:** MCP trust boundary violation → **impact tested:** privilege escalation (OWASP-AGENT-004, 007)

This naming convention was reviewed by [OWASP AI Exchange](https://owaspai.org/) contributors
and is documented with full technical rationale in
[docs/owasp_mapping.md](docs/owasp_mapping.md).

When adding a new attack, consider:
1. What is the **attack vector** (how does the payload reach the agent)?
2. What is the **impact** being tested (what does a successful attack achieve)?
3. Which OWASP Agentic AI risk category maps to that impact?

See [docs/owasp_mapping.md](docs/owasp_mapping.md) for the authoritative attack vector → impact
mapping table.

## Setting Up Your Development Environment

```bash
# Clone the repo
git clone https://github.com/crucible-security/crucible
cd crucible

# Create virtual environment
python -m venv .venv

# Activate it
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Install in dev mode
pip install -e ".[dev]"
```

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=crucible --cov-report=term-missing

# Single file
pytest tests/test_attacks.py -v
```

## Code Quality Checks

```bash
# Type checking (must pass strict)
mypy crucible/ --strict

# Linting
ruff check crucible/ tests/

# Formatting
black crucible/ tests/
```

All four must pass before submitting a PR.

## Adding a New Attack Vector

1. Open `crucible/attacks/prompt_injection.py` 
   (or `goal_hijacking.py` / `jailbreaks.py` / `mcp_attacks.py`)
2. Add your class inheriting from `BaseAttack`
3. Set the `owasp_ref` field — e.g. `"OWASP-AGENT-001"`
4. Set severity: `Severity.CRITICAL / HIGH / MEDIUM / LOW`
5. Write a test in `tests/test_attacks.py`
6. Run full test suite — must stay above 90% coverage
7. Submit a PR

## Project Structure
crucible/
__init__.py
cli.py              — Entry point (Typer)
models.py           — Pydantic data models
attacks/
base.py           — BaseAttack ABC
prompt_injection.py  — 50 vectors
goal_hijacking.py    — 20 vectors
jailbreaks.py        — 20 vectors
mcp_attacks.py       — 8 vectors
modules/
base.py           — BaseModule ABC
security.py       — Module orchestration
core/
runner.py         — Async parallel execution
scorer.py         — CVSS-style scoring
reporters/
base.py           — BaseReporter ABC
terminal.py       — Rich terminal output
json_reporter.py  — JSON export
tests/
conftest.py
test_models.py
test_attacks.py
test_scorer.py
test_cli.py
test_runner.py

## Questions?

Open a GitHub issue or email crucible.sec@gmail.com
