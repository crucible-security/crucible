"""crucible/core/doctor.py — Pre-flight diagnostics and target validation.

Validates provider configuration, API key formats, target endpoint reachability,
and runs a live 1-token probe request to ensure Crucible can scan without blind
execution errors.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse

import httpx

from crucible.core.redactor import redact_secrets
from crucible.core.response_extractor import extract_response
from crucible.models import PROVIDER_PRESETS, AgentTarget

CheckStatus = Literal["PASS", "FAIL", "WARN"]


@dataclass
class DoctorCheck:
    name: str
    status: CheckStatus
    message: str
    details: str = ""

    def __post_init__(self) -> None:
        self.message = redact_secrets(self.message)
        self.details = redact_secrets(self.details)


@dataclass
class DoctorReport:
    target_url: str
    provider: str
    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.status != "FAIL" for c in self.checks)


def validate_api_key_format(provider: str, key: str) -> tuple[CheckStatus, str]:
    """Validate common key prefixes for known LLM providers."""
    cleaned = key.strip()
    if not cleaned:
        return "FAIL", "API key is empty"

    prov = provider.lower()
    if "anthropic" in prov:
        if cleaned.startswith("sk-ant-"):
            return (
                "PASS",
                f"Valid Anthropic key format ({cleaned[:7]}...{cleaned[-4:]})",
            )
        return (
            "WARN",
            f"Key does not start with standard 'sk-ant-' prefix ({cleaned[:4]}...)",
        )
    elif "openai" in prov:
        if cleaned.startswith("sk-"):
            return "PASS", f"Valid OpenAI key format ({cleaned[:7]}...{cleaned[-4:]})"
        return (
            "WARN",
            f"Key does not start with standard 'sk-' prefix ({cleaned[:4]}...)",
        )
    elif "openrouter" in prov:
        if cleaned.startswith("sk-or-"):
            return (
                "PASS",
                f"Valid OpenRouter key format ({cleaned[:7]}...{cleaned[-4:]})",
            )
        return (
            "WARN",
            f"Key does not start with standard 'sk-or-' prefix ({cleaned[:4]}...)",
        )
    elif "groq" in prov:
        if cleaned.startswith("gsk_"):
            return "PASS", f"Valid Groq key format ({cleaned[:5]}...{cleaned[-4:]})"
        return (
            "WARN",
            f"Key does not start with standard 'gsk_' prefix ({cleaned[:4]}...)",
        )
    return "PASS", f"Key provided ({cleaned[:4]}...{cleaned[-4:]})"


def resolve_api_key(
    provider: str, explicit_key: str | None, headers: dict[str, str]
) -> tuple[str | None, str]:
    """Resolve API key from explicit flag, headers, or environment variables."""
    if explicit_key:
        return explicit_key, "CLI argument (--key)"

    for h_name, h_val in headers.items():
        if h_name.lower() in ("authorization", "x-api-key"):
            if h_val.lower().startswith("bearer "):
                return h_val[7:].strip(), f"Header ({h_name})"
            return h_val.strip(), f"Header ({h_name})"

    env_vars = {
        "anthropic": ["ANTHROPIC_API_KEY"],
        "openai": ["OPENAI_API_KEY"],
        "openrouter": ["OPENROUTER_API_KEY"],
        "groq": ["GROQ_API_KEY"],
        "mistral": ["MISTRAL_API_KEY"],
    }
    for env in env_vars.get(provider.lower(), []):
        val = os.environ.get(env)
        if val:
            return val, f"Environment variable ({env})"

    for generic_env in ["CRUCIBLE_API_KEY", "LLM_API_KEY", "API_KEY"]:
        val = os.environ.get(generic_env)
        if val:
            return val, f"Environment variable ({generic_env})"

    return None, "Not found"


async def run_doctor(
    target_url: str,
    provider: str = "custom",
    key: str | None = None,
    model: str | None = None,
    headers: dict[str, str] | None = None,
    body_template: str | None = None,
    response_path: str | None = None,
    timeout: float = 15.0,
    client: httpx.AsyncClient | None = None,
) -> DoctorReport:
    """Run all pre-flight diagnostic checks against a target and provider."""
    req_headers = dict(headers or {})
    checks: list[DoctorCheck] = []
    report = DoctorReport(target_url=target_url, provider=provider, checks=checks)

    # 1. URL Structure Check
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        checks.append(
            DoctorCheck(
                name="Target URL Validation",
                status="FAIL",
                message=f"Invalid URL: '{target_url}'. Must include http:// or https:// and a valid host.",
            )
        )
        return report
    if parsed.scheme not in ("http", "https"):
        checks.append(
            DoctorCheck(
                name="Target URL Validation",
                status="FAIL",
                message=f"Unsupported URL scheme '{parsed.scheme}'. Must be http or https.",
            )
        )
        return report

    checks.append(
        DoctorCheck(
            name="Target URL Validation",
            status="PASS",
            message=f"Valid {parsed.scheme.upper()} endpoint ({parsed.netloc})",
        )
    )

    # 2. Preset & Configuration Resolution
    preset = PROVIDER_PRESETS.get(provider.lower())
    resolved_url = target_url
    resolved_body_template = body_template or '{"message": "{payload}"}'
    resolved_response_path = response_path or ""
    resolved_model = model

    if preset:
        if not body_template:
            resolved_body_template = preset.body_template
        if not response_path:
            resolved_response_path = preset.response_path
        if preset.extra_headers:
            for k, v in preset.extra_headers.items():
                if k not in req_headers:
                    req_headers[k] = v
        if preset.url_suffix and not resolved_url.rstrip("/").endswith(
            preset.url_suffix.rstrip("/")
        ):
            resolved_url = resolved_url.rstrip("/") + preset.url_suffix

        if preset.requires_model and not resolved_model:
            defaults = {
                "anthropic": "claude-3-5-sonnet-20241022",
                "openai": "gpt-4o-mini",
                "openrouter": "anthropic/claude-3.5-sonnet",
                "groq": "llama-3.3-70b-versatile",
                "mistral": "mistral-small-latest",
                "ollama": "llama3",
            }
            resolved_model = defaults.get(provider.lower(), "gpt-4o-mini")
            checks.append(
                DoctorCheck(
                    name="Model Configuration",
                    status="WARN",
                    message=f"No --model specified for {provider}; using default '{resolved_model}'",
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    name="Model Configuration",
                    status="PASS",
                    message=f"Configured model: {resolved_model or 'N/A'}",
                )
            )

    if resolved_model and "{model}" in resolved_body_template:
        resolved_body_template = resolved_body_template.replace(
            "{model}", resolved_model
        )

    # 3. API Key & Authentication Check
    resolved_key, key_source = resolve_api_key(provider, key, req_headers)
    is_local_provider = provider.lower() in ("ollama", "lmstudio", "generic", "raw")

    if resolved_key:
        status, msg = validate_api_key_format(provider, resolved_key)
        checks.append(
            DoctorCheck(
                name="API Key Validation",
                status=status,
                message=f"{msg} [source: {key_source}]",
            )
        )
        # Ensure authorization headers are attached if not already present
        if "anthropic" in provider.lower():
            if "x-api-key" not in req_headers:
                req_headers["x-api-key"] = resolved_key
        else:
            if "authorization" not in req_headers:
                req_headers["authorization"] = f"Bearer {resolved_key}"
    elif not is_local_provider:
        checks.append(
            DoctorCheck(
                name="API Key Validation",
                status="FAIL",
                message=f"No API key detected for provider '{provider}'. Pass --key or set {provider.upper()}_API_KEY.",
            )
        )
        return report
    else:
        checks.append(
            DoctorCheck(
                name="API Key Validation",
                status="PASS",
                message="Local provider does not require authentication",
            )
        )

    # 4. Live Probe Request
    target_obj = AgentTarget(
        name=f"doctor-{provider}",
        url=resolved_url,  # type: ignore[arg-type]
        body_template=resolved_body_template,
        response_path=resolved_response_path,
        headers=req_headers,
        timeout=timeout,
    )

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout)
        close_client = True

    try:
        probe_body = target_obj.build_payload_body("Ping test. Respond with 'Pong'.")
        probe_headers = {"Content-Type": "application/json", **req_headers}

        resp = await client.request(
            method="POST",
            url=str(resolved_url),
            content=probe_body.encode("utf-8"),
            headers=probe_headers,
            timeout=timeout,
        )

        status_code = resp.status_code

        if status_code == 200:
            extracted = extract_response(resp.text, resolved_response_path)
            snippet = extracted.strip()[:100]
            checks.append(
                DoctorCheck(
                    name="Target Connectivity & DNS",
                    status="PASS",
                    message="TCP connect and TLS handshake succeeded",
                )
            )
            checks.append(
                DoctorCheck(
                    name="Live 1-Token Probe Request",
                    status="PASS",
                    message=f"HTTP 200 OK. Response: '{snippet}'",
                )
            )
        elif status_code in (401, 403):
            checks.append(
                DoctorCheck(
                    name="Target Connectivity & DNS",
                    status="PASS",
                    message="Server reachable",
                )
            )
            checks.append(
                DoctorCheck(
                    name="Live 1-Token Probe Request",
                    status="FAIL",
                    message=f"Authentication failed: HTTP {status_code} {resp.reason_phrase}",
                    details=f"Response body: {resp.text[:300]}\nCheck your API key and permissions.",
                )
            )
        elif status_code == 400:
            checks.append(
                DoctorCheck(
                    name="Target Connectivity & DNS",
                    status="PASS",
                    message="Server reachable",
                )
            )
            checks.append(
                DoctorCheck(
                    name="Live 1-Token Probe Request",
                    status="FAIL",
                    message=f"Bad Request: HTTP 400 {resp.reason_phrase}",
                    details=f"Payload rejected by provider: {resp.text[:300]}\nCheck model name and body template format.",
                )
            )
        elif status_code == 404:
            checks.append(
                DoctorCheck(
                    name="Target Connectivity & DNS",
                    status="PASS",
                    message="Server reachable",
                )
            )
            checks.append(
                DoctorCheck(
                    name="Live 1-Token Probe Request",
                    status="FAIL",
                    message=f"Endpoint Not Found: HTTP 404 for URL {resolved_url}",
                    details="Verify target path and provider URL suffix.",
                )
            )
        elif status_code == 429:
            checks.append(
                DoctorCheck(
                    name="Target Connectivity & DNS",
                    status="PASS",
                    message="Server reachable",
                )
            )
            checks.append(
                DoctorCheck(
                    name="Live 1-Token Probe Request",
                    status="WARN",
                    message=f"Rate Limited: HTTP 429 {resp.reason_phrase}",
                    details=f"Provider quota or rate limit exceeded: {resp.text[:300]}",
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    name="Live 1-Token Probe Request",
                    status="FAIL",
                    message=f"HTTP {status_code} {resp.reason_phrase}",
                    details=f"Response: {resp.text[:300]}",
                )
            )

    except httpx.ConnectError as exc:
        checks.append(
            DoctorCheck(
                name="Target Connectivity & DNS",
                status="FAIL",
                message=f"Connection refused / DNS lookup failed: {exc}",
            )
        )
    except httpx.TimeoutException as exc:
        checks.append(
            DoctorCheck(
                name="Live 1-Token Probe Request",
                status="FAIL",
                message=f"Request timed out after {timeout}s: {exc}",
            )
        )
    except Exception as exc:
        checks.append(
            DoctorCheck(
                name="Live 1-Token Probe Request",
                status="FAIL",
                message=f"Unexpected error: {type(exc).__name__}: {exc}",
            )
        )
    finally:
        if close_client:
            await client.aclose()

    return report
