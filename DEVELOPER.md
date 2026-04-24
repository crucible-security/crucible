# Developer Guide

## Architecture Overview

Crucible is organized into four layers:
CLI Layer       crucible/cli.py          — Typer command interface
Attack Layer    crucible/attacks/        — 90+ adversarial payloads
Module Layer    crucible/modules/        — Attack orchestration
Reporter Layer  crucible/reporters/      — Output formatting
Core Layer      crucible/core/           — Runner and scorer

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

Open a GitHub issue or email Crucible.sec@gmail.com
