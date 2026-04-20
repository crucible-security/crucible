# Contributing to Crucible

Thank you for your interest in contributing to Crucible! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/crucible-security/crucible.git
cd crucible

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install in development mode
pip install -e ".[dev]"
```

### Verify Installation

```bash
crucible --help
crucible --version
```

## Development Workflow

### Code Quality

We enforce strict code quality standards. Before submitting a PR, ensure:

```bash
# Format code
black crucible/ tests/

# Lint
ruff check crucible/ tests/

# Type check (strict mode)
mypy crucible/

# Run tests
pytest tests/ -v --cov=crucible
```

### Running a Scan

```bash
# Generate a config scaffold
crucible init

# Run a scan
crucible scan --target https://your-agent.com/api --name "My Agent"
```

## Architecture

```
crucible/
  __init__.py           # Package root, public API
  models.py             # Pydantic data models
  cli.py                # Typer CLI interface
  attacks/
    base.py             # BaseAttack ABC
    prompt_injection.py # 50 PI attack vectors
    goal_hijacking.py   # 20 GH attack vectors
    jailbreaks.py       # 20 JB attack vectors
  modules/
    base.py             # BaseModule ABC
    security.py         # Module registry
  core/
    runner.py           # Async scan runner (anyio)
    scorer.py           # Scoring + grading engine
  reporters/
    terminal.py         # Rich terminal output
    json_reporter.py    # JSON file export
tests/
  conftest.py           # Shared fixtures
  test_models.py        # Model validation tests
  test_scorer.py        # Scoring engine tests
  test_attacks.py       # Attack + module tests
  test_cli.py           # CLI integration tests
```

## Adding a New Attack

1. Create a new class in the appropriate attack module (e.g., `prompt_injection.py`):

```python
class MyNewAttack(BaseAttack):
    name = "PI-051"
    title = "My New Attack"
    category = AttackCategory.PROMPT_INJECTION
    severity = Severity.HIGH
    description = "What this attack tests."
    remediation = "How to fix the vulnerability."

    def get_payloads(self) -> list[str]:
        return ["payload 1", "payload 2"]

    def get_detection_patterns(self) -> list[str]:
        return ["pattern_to_detect"]
```

2. Add the class to the attack registry list (e.g., `ALL_PROMPT_INJECTION_ATTACKS`).
3. Add tests in `test_attacks.py`.
4. Run the quality gate: `black`, `mypy`, `pytest`.

## Adding a New Module

1. Create a new class in `crucible/modules/security.py`:

```python
class MyModule(BaseModule):
    name = "my_module"
    description = "Description of what this module tests."
    category = AttackCategory.PROMPT_INJECTION

    def get_attacks(self) -> list[BaseAttack]:
        return [MyAttack1(), MyAttack2()]
```

2. Add it to `ALL_SECURITY_MODULES`.
3. Add tests in `test_attacks.py`.

## Pull Request Guidelines

- **One PR per feature/fix** -- keep changes focused.
- **Include tests** for all new functionality.
- **Pass all quality gates** before requesting review.
- **Write descriptive commit messages** following [Conventional Commits](https://www.conventionalcommits.org/).
- **Update CHANGELOG.md** with your changes under `[Unreleased]`.

## Commit Message Format

```
<type>: <description>

feat: add new XSS attack vectors
fix: handle timeout in scan runner
test: add scorer edge case tests
docs: update contributing guide
```

## Reporting Issues

Use [GitHub Issues](https://github.com/crucible-security/crucible/issues) to report bugs or request features. Please include:

- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS
- Crucible version (`crucible --version`)

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
