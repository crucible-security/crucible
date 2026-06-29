from __future__ import annotations

import json
import pytest
import httpx
import respx

from crucible.core.statistics import (
    bootstrap_confidence_interval,
    interpret_significance,
)
from crucible.models import ConfidenceInterval, AgentTarget, ScanStatus
from crucible.core.runner import run_scan
from crucible.modules.security import GoalHijackingModule


def test_bootstrap_ci_all_successes() -> None:
    """CI for 5/5 successes should have high lower bound."""
    ci = bootstrap_confidence_interval(5, 5, n_bootstrap=1000)
    assert ci.lower > 0.3  # shouldn't be near zero


def test_bootstrap_ci_all_failures() -> None:
    """CI for 0/5 successes should have low upper bound."""
    ci = bootstrap_confidence_interval(0, 5, n_bootstrap=1000)
    assert ci.upper < 0.7


def test_bootstrap_ci_fifty_fifty() -> None:
    """CI for 5/10 should straddle 0.5 (inconclusive)."""
    ci = bootstrap_confidence_interval(5, 10, n_bootstrap=1000)
    assert ci.lower < 0.5 < ci.upper


def test_significance_clear_pass() -> None:
    """CI entirely below 0.5 is significant."""
    ci = ConfidenceInterval(lower=0.1, upper=0.4)
    assert interpret_significance(ci) is True


def test_significance_inconclusive() -> None:
    """CI straddling 0.5 is not significant."""
    ci = ConfidenceInterval(lower=0.3, upper=0.7)
    assert interpret_significance(ci) is False


def test_pure_python_no_numpy() -> None:
    """Confirm statistics.py does not import numpy or scipy."""
    import crucible.core.statistics as s
    import inspect
    source = inspect.getsource(s)
    assert "import numpy" not in source
    assert "from numpy" not in source
    assert "import scipy" not in source
    assert "from scipy" not in source


@respx.mock
@pytest.mark.asyncio
async def test_confidence_mode_runs_each_attack_n_times() -> None:
    """With --samples 3, each attack runs exactly 3 times in confidence mode."""
    target = AgentTarget(
        name="test-agent",
        url="https://agent.test/chat",  # type: ignore[arg-type]
    )
    # mock target response
    route = respx.post("https://agent.test/chat").mock(
        return_value=httpx.Response(200, text="I cannot do that.")
    )

    module = GoalHijackingModule()
    # Total attacks and payloads in GoalHijackingModule
    n_attacks = len(module.get_attacks())
    total_payloads = sum(len(a.get_payloads()) for a in module.get_attacks())

    result = await run_scan(
        target,
        modules=[module],
        concurrency=1,
        timeout=5.0,
        quiet=True,
        verbose=False,
        skip_preflight=True,
        confidence=True,
        samples=3,
    )

    # Check total calls
    assert route.call_count == total_payloads * 3
    assert result.status == ScanStatus.COMPLETED
    assert len(result.modules[0].statistical_findings) == n_attacks
    
    attacks_dict = {a.name: a for a in module.get_attacks()}
    for sf in result.modules[0].statistical_findings:
        attack_obj = attacks_dict[sf.attack_id]
        expected_samples = len(attack_obj.get_payloads()) * 3
        assert sf.sample_count == expected_samples
        # Check that we populated bypass/pass rate
        assert sf.bypass_rate >= 0.0
        assert sf.pass_rate >= 0.0


@respx.mock
@pytest.mark.asyncio
async def test_statistical_finding_in_json_output() -> None:
    """JSON serialization includes statistical findings in confidence mode."""
    target = AgentTarget(
        name="test-agent-json",
        url="https://agent.test/chat",  # type: ignore[arg-type]
    )
    respx.post("https://agent.test/chat").mock(
        return_value=httpx.Response(200, text="I cannot do that.")
    )

    module = GoalHijackingModule()
    result = await run_scan(
        target,
        modules=[module],
        concurrency=1,
        timeout=5.0,
        quiet=True,
        verbose=False,
        skip_preflight=True,
        confidence=True,
        samples=2,
    )

    # Serialize to JSON model_dump_json()
    serialized = result.model_dump_json()
    data = json.loads(serialized)

    assert "statistical_findings" in data
    assert len(data["statistical_findings"]) > 0
    first_sf = data["statistical_findings"][0]
    assert "confidence_interval" in first_sf
    assert "lower" in first_sf["confidence_interval"]
    assert "upper" in first_sf["confidence_interval"]
    assert "bypass_rate" in first_sf
