import pytest
from crucible.models import AgentTarget
from crucible.core.runner import run_scan
from crucible.modules.security import get_all_modules
import anyio

@pytest.mark.anyio
async def test_dry_run_no_requests(monkeypatch):
    # Mock httpx.AsyncClient.request to fail if called
    def mock_request(*args, **kwargs):
        pytest.fail("httpx.AsyncClient.request was called during a dry run!")
    
    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)
    
    target = AgentTarget(
        name="test-agent",
        url="http://localhost:8080/chat",
        dry_run=True
    )
    
    # Run only one module to save time
    modules = get_all_modules()[:1]
    
    result = await run_scan(target, modules=modules, dry_run=True)
    
    assert result.is_dry_run is True
    assert result.status == "completed"
    for mod in result.modules:
        for finding in mod.findings:
            assert finding.response_snippet == "[DRY RUN] Request skipped"
            assert finding.passed is True
