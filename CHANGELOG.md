# Changelog

All notable changes to Crucible will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.1] - 2026-07-11

### Added — Phase 12: Inter-Agent Trust Testing (ASI07)

- **Inter-Agent Trust Attack Module (`crucible/attacks/inter_agent_trust.py`)**:
  - Implemented 15 distinct trust boundary and communication attack classes (`IAC-001` through `IAC-015`).
  - Added mappings for MITRE ATLAS technique (`AML.T0054` - Indirect Prompt Injection), NIST function (`MANAGE`), and OWASP ref (`ASI07`).
- **Inter-Agent Trust Security Module (`crucible/modules/security.py`)**:
  - Registered `InterAgentTrustModule` and added to default scanning module list.
- **Documentation (`docs/owasp_mapping.md`)**:
  - Documented inter-agent trust communication (A2A) vectors and exfiltration paths under OWASP Top 10 ASI07 mapping rules.
- **Tests**:
  - Added 7 unit/integration tests in `tests/test_inter_agent_trust.py`.
  - Updated existing runner and attack registry test suites to account for the new module.
  - Total test suite: **431 passed, 0 failed**.

## [0.10.0] - 2026-07-11

### Added — Phase 11: Web Dashboard MVP

- **Offline Web Dashboard (`crucible/dashboard/`)**:
  - Implementation of offline threat and vulnerability dashboard.
  - `templates/dashboard.html` — premium single-file HTML/JS/CSS app with tabs for Overview, Scan Details, Compare (Diff), Watch Feed, and Compliance.
  - Includes custom pure HTML5 Canvas trend plotting and OWASP Agentic AI Top 10 heatmap.
  - `server.py` — Python stdlib-only HTTP server to host scans and watch logs.
- **CLI Commands (`crucible/cli.py`)**:
  - `crucible dashboard` command added supporting `--scan-dir`, `--port`, `--host`, and `--open`.
- **Tests**:
  - Added 7 integration tests in `tests/test_dashboard.py` verifying server startup, HTML service, JSON list and detail endpoints, watch logs, and stdlib dependency purity.
  - Total test suite: **424 passed, 0 failed** (417 baseline + 7 new).

## [0.9.1] - 2026-07-11

### Added — Phase 10: Dynamic Payload Generation

- **Dynamic Attack Generation Hooks (`crucible/attacks/base.py`)**:
  - `generate_dynamic_payloads()` — queries an external generator LLM (Ollama, OpenAI, LM Studio, etc.) at scan time to create novel, structurally diverse attack variants.
  - Automatically handles preset formatting, JSON array parsing, markdown code-block cleaning, and duplicates filtering.
  - Graceful fallback: connection or parsing errors print warnings to stderr but do not abort the scan.
- **Finding Source Tagging (`crucible/models.py`)**:
  - Added `payload_source` (`static` or `dynamic`) and `payload_index` fields to `Finding` model to track payload lineage in scans.
- **CLI Options & Warnings (`crucible/cli.py`)**:
  - Extended `crucible scan` with `--dynamic-payloads`, `--generator-endpoint`, `--generator-model`, `--generator-format-preset`, `--dynamic-count`, and `--dynamic-seed`.
  - Added terminal warnings to alert users about increased scan time and dynamic generation settings.
- **Scan Progress Adjustments (`crucible/core/runner.py`)**:
  - Updated `_module_payload_count()` and progress bar tracking to correctly account for dynamic counts.
- **Tests**:
  - Added 8 unit/integration tests in `tests/test_dynamic_payloads.py` verifying template rendering, parameter compliance, graceful failures, and static-first ordering.
  - Total test suite: **417 passed, 0 failed** (409 baseline + 8 new).

## [0.9.0] - 2026-07-11

### Added — Phase 9: Identity & Privilege Layer (ASI04)

#### Data models (`crucible/models.py`)
- `AgentIdentity` — named agent identity with tool allowlist/denylist, per-session/hourly call limits, unique-tool cap, and UTC hour window restriction.
- `IdentityCallRecord` — single-call behavioral log entry written to `~/.crucible/identity-logs/{agent_id}.jsonl`.
- `IdentityViolation` — structured violation record (type, severity, evidence).
- `IdentityBehaviorSummary` — aggregate audit result with risk score (0.0–1.0), per-tool call counts, violations, and findings.

#### Policy YAML v2 (`crucible/trace/policy.py`)
- Backward-compatible v1/v2 detection via optional `version: "2"` field. All v1 policies load identically with zero changes required.
- New v2 `agents:` section: load `AgentIdentity` objects keyed by `agent_id`.
- New rule fields: `agent_id` (rule only matches specified agent) and `tool_name_not_in_allowlist: true` (deny tools outside agent's allowlist).
- `evaluate_policy()` extended with `agent_id` and `agent_allowed_tools` parameters (optional, defaults keep existing callers unchanged).

#### Agent ID extraction (`crucible/trace/proxy.py`)
- `extract_agent_id()` — reads `X-Crucible-Agent-Id` HTTP header first, falls back to `agent_id` JSON body field, then `'unknown'` with a one-time WARNING.
- `_extract_headers()` — h11-based HTTP header extractor (lowercase-keyed dict).
- `TraceEntry.agent_id` — new field (default `'unknown'`) in JSONL audit log for backward compat.
- `TraceProxy` accepts `identity_store` parameter; wires limit checking and call recording into `_process()` pipeline.

#### Identity store (`crucible/trace/identity_store.py`) — new module
- `IdentityStore` — per-agent JSONL behavioral log with atomic `tmp→replace()` writes (Windows-safe).
- `record_call()` — async, non-blocking (runs via `anyio.to_thread.run_sync`). Write failures are silently logged, never propagated.
- `check_limits()` — checks hour-window, session cap, hourly cap, unique-tool cap in order; returns violation description or `None`.
- `approaching_limit_warnings()` — prints 80%/90% threshold warnings to console before hard enforcement.
- `generate_summary()` — produces `IdentityBehaviorSummary` with risk score and violation list for `crucible identity audit`.
- `list_agents()`, `clear_agent_log()` for management.
- `_sanitise_agent_id()` — strips Windows/Linux filename-illegal characters to prevent path traversal.

#### CLI subapp (`crucible identity`)
- `crucible identity audit <agent_id>` — Rich-formatted risk report with tool table, violations, findings.
- `crucible identity baseline <agent_id>` — Save behaviour snapshot to `~/.crucible/identity-baselines/{agent_id}.json`.
- `crucible identity diff <agent_id>` — Compare current behaviour against saved baseline; exit 1 on drift ≥ 0.2.
- `crucible identity list` — List all agents with recorded logs.
- `crucible identity clear <agent_id>` — Delete an agent's log file.

#### Documentation
- `docs/owasp_mapping.md` — Added identity layer row to module-to-OWASP table; updated ASI04 coverage row; expanded `trace proxy + identity layer` section.

### Tests
- 18 new tests in `tests/test_identity_layer.py` covering all 6 implementation layers.
- Total test suite: **409 passed, 0 failed** (391 baseline + 18 new).

## [0.8.4] - 2026-06-30

### Fixed
- **CI Dependency Resolution** — Added `cryptography` to dev dependencies in `pyproject.toml` so that x509 cert tests and mypy type checks compile successfully in clean CI environments.

## [0.8.3] - 2026-06-30

### Fixed
- **Mypy type-checking** — Resolved Union public key type attribute error (`union-attr` on `public_numbers()`) in `tests/test_tls_listener.py` by adding explicit RSAPublicKey assertions.
- **CI Test Suite Flakiness** — Increased connection timeout in `_wait_for_tls_port` from `0.2` to `2.0` seconds to prevent connection timeouts on slow or busy GitHub Actions VM runners.
- **Version output** — Dynamically print the package version in `crucible trace start` CLI using the `__version__` variable.

## [0.8.2] - 2026-06-30

### Added
- **TLS Listener for `crucible trace` proxy** — Native TLS termination for the agent → proxy hop (first hop) using anyio's `TLSListener`.
  - `--tls` / `--no-tls` flag to enable TLS.
  - `--tls-cert` and `--tls-key` flags to specify paths to existing PEM certificate/key files.
  - `--tls-self-signed` flag to auto-generate a development RSA 2048 key + self-signed x509 certificate on startup.
  - `--tls-handshake-timeout` flag to configure the TLS handshake timeout (default 30 seconds).
- **10 new tests** (`tests/test_tls_listener.py`) covering self-signed generation, SSL context construction, TLS allowance/denial over HTTPS, plain HTTP regression guard, handshake timeout configurability, and invalid handshake resilience.

## [0.8.0] - 2026-06-29

### Added
- **`crucible poison-test` suite** — Stateful memory and RAG poisoning evaluation tool for AI agents.
  - `crucible poison-test plant` — Generates a poisoned document using one of four configurable techniques with a unique activation signal (8-char token) and registers it in the local session store.
  - `crucible poison-test verify` — Sends the trigger query to the target agent and detects if the activation signal appears in the response.
  - `crucible poison-test rag` — Runs an automated end-to-end plant-and-query lifecycle against independent ingest and query endpoints.
  - `crucible poison-test list` — Renders a Rich table of all poisoning sessions with status, topic, and technique details.
  - `crucible poison-test status` — Prints detailed status properties of a single poisoning session.
- **`crucible/poison/` package** — Core modules for poisoning evaluation:
  - `session_store.py` — Atomic session file storage manager (`PoisonSessionStore`) supporting loading, listing, deleting, status updates, and directory creation on Windows.
  - `document_generator.py` — Implements 4 document poisoning techniques: Semantic Anchor Injection, Authority Impersonation with zero-width characters, Semantic Sleeper response template, and RAG-specific semantic index injection.
- **Data Models** — Introduced `MemoryType`, `PoisonStatus`, `PoisonPlantRecord`, and `PoisonTestResult` Pydantic models.
- **13 new tests** (`tests/test_poison.py`) verifying document generator output, signal uniqueness, store serialization, CLI commands, and verification checks.

## [0.7.0] - 2026-06-29


### Added
- **`crucible trace` proxy** — New sub-command group for MCP tool-call interception and auditing.
  - `crucible trace start` — Start an async HTTP reverse proxy that sits between an MCP client and server, evaluating every `tools/call` against a YAML policy.
  - `crucible trace validate-policy` — Load and validate a policy YAML file (including regex compilation). Exits 0/1.
  - `crucible trace report` — Render a Rich terminal table from a JSONL audit log with summary counts.
- **`crucible/trace/` package** — New sub-package with four modules:
  - `models.py` — `PolicyAction`, `PolicyRule`, `Policy`, `TraceEntry` Pydantic models.
  - `policy.py` — YAML loader with strict validation (unknown keys → error, bad regex → `PolicyError` at load time). First-match-wins evaluation via `evaluate_policy()`.
  - `audit_log.py` — Thread-safe, append-only JSONL writer (`AuditLog`). Every request (tool call or not) gets an entry.
  - `proxy.py` — Async TCP server (`TraceProxy`) using `anyio` + `h11` + `httpx`. No new mandatory dependencies (all three are already transitive deps of `crucible`).
- **Policy actions** — `allow` (forward silently), `deny` (return JSON-RPC error, never touch upstream), `alert` (forward + print console warning).
- **JSON-RPC 200 OK for denials** — Denied calls return HTTP 200 with a JSON-RPC error body (`code: -32600`, `message: "blocked_by_policy"`). Note: deny actions return HTTP 200 with JSON-RPC error body (code -32600) rather than HTTP 403, for MCP client compatibility.
- **Audit log schema** — Each JSONL entry records: `timestamp`, `request_id` (UUID4), `tool_name`, `parameters`, `policy_action`, `policy_rule_matched`, `upstream_status_code`, `upstream_latency_ms`, `request_size_bytes`, `caller_ip`.
- **15 new tests** (`tests/test_trace_proxy.py`) covering policy loading, regex validation, evaluation logic, `is_tool_call()` detection, audit log round-trip, and full integration tests (deny + allow) against a mock MCP server.
- **Mock MCP server fixture** (`tests/fixtures/mock_mcp_server.py`) — Minimal `http.server`-based stub using OS-assigned port (no hardcoded port), daemon thread, clean context-manager shutdown.

### Known Limitations (v0.7.0)
- HTTP only — TLS termination is planned for v0.8.0.
- No Slack/webhook alerts in v1 (planned for v0.8.0).
- Windows: `anyio` is run with `backend="asyncio"` explicitly (trio not supported on Windows).

## [0.6.1] - 2026-06-29


### Added
- **Statistical Confidence Intervals (`--confidence`)** — New scan mode to run each attack multiple times (default 5, max 20) and calculate bootstrap confidence intervals.
- **Pure Python Bootstrap CI** — Integrated a zero-dependency bootstrap CI implementation (`crucible/core/statistics.py`) that uses `random.Random(42)` for reproducibility, capping bootstrap samples at 1,000 for large scans (>100 trials) to ensure high performance.
- **Extended Models** — Added `ConfidenceInterval` and `StatisticalFinding` models to `crucible/models.py`. Grouped module/scan results to populate `statistical_findings` lists.
- **Terminal Statistical Table** — Rich terminal tables displaying `Bypass Rate`, `95% CI` bounds, and a significance flag (`✅ Yes` / `❌ No ⚠️`), with inconclusive warning messages.
- **Performance Warnings Heuristic** — Logs time-to-run estimates before scan starts and runtime warnings if bootstrap CI calculation exceeds 5s.
- **8 new tests** (`tests/test_statistics.py`) covering all CI logic, binomial bounds, significance, and CLI confidence scan outputs.

## [0.6.0] - 2026-06-29

### Added
- **`crucible watch` daemon** — New sub-command for continuous behavioral drift monitoring.
  - `crucible watch set-baseline` — Run a full scan and store the result as the reference baseline (stored at `~/.crucible/baselines/<sha256(url)[:16]>.json`).
  - `crucible watch check` — Run a single on-demand check and compare against the baseline. Prints score delta and lists regressions. Exits code 1 if `--fail-on-alert` is set and an alert fires.
  - `crucible watch start` — Start the daemon loop with a configurable interval (`5m`, `15m`, `1h`, `6h`, `12h`, `24h`). Runs until Ctrl+C.
  - `crucible watch status` — Show a summary of the most recent watch session by reading `~/.crucible/watch_log.jsonl`.
  - `crucible watch list-baselines` — List all stored baselines with target URL, score, grade, and version.
  - `crucible watch delete-baseline` — Delete the stored baseline for a target URL.
- **`WatchStore`** (`crucible/core/watch_store.py`) — Persistent baseline storage with `save_baseline()`, `load_baseline()`, `delete_baseline()`, and `list_baselines()` methods. Baselines named by `sha256(url)[:16]` to prevent collisions.
- **`CrucibleWatcher`** (`crucible/core/watcher.py`) — The core daemon. Uses `asyncio.sleep()` loop (no external scheduler dependency). Integrates directly with `compute_diff()` from Phase 2.
- **Alert system** — `WatchAlert` fires when `score_delta < -score_threshold` or `total_regressed > 0`. Severity: `CRITICAL` for drops ≥20pts, `WARNING` otherwise.
- **Slack Block Kit alerts** — Rich actionable payloads with target, score delta, grade change, and top 5 regressions listed by attack ID.
- **SIGINT/SIGTERM graceful shutdown** — On Ctrl+C: watcher completes the current scan cycle, prints a summary (`N checks, M alerts, final score`), then exits cleanly. No corrupt baseline or partial JSONL entry is left behind.
- **Watch log** — `~/.crucible/watch_log.jsonl` append-only log of every check cycle. Each line is a valid `WatchCheckResult` JSON object.
- **New models** — `WatchInterval`, `WatchConfig`, `WatchBaseline`, `WatchAlert`, `WatchCheckResult`, `WatchStatus` in `crucible/models.py`.
- **10 new tests** in `tests/test_watcher.py` covering all critical paths.

### Architecture notes
- Behavioral drift engine (`adaptive_fingerprinter.py`) runs **in-memory only** — its `BehavioralFingerprint` output is stored inside `WatchBaseline.behavioral_profile` for future comparison.
- The diff engine (`compute_diff`) compares `ScanResult` objects, not raw fingerprints. Watch uses this directly, making the baseline simply a stored `ScanResult`.
- `--skip-preflight` is forwarded through `WatchConfig` and `run_scan()` to allow CI usage against endpoints that rate-limit the preflight probe.

## [0.5.7] - 2026-06-29


### Fixed
- **KL-1: `--method GET` against POST-only endpoints now exits code 2 immediately** — Previously, running `crucible scan --method GET` against a POST-only LLM endpoint (such as Ollama's `/api/chat`) silently executed 300+ attacks that all returned HTTP 405, ultimately producing a misleading `Grade.INCOMPLETE` result with zero actionable findings. The new preflight check sends a single probe request before the main scan loop and detects the 405 immediately, printing a clear red error message and aborting with exit code 2 before any attack modules run.

### Added
- **`preflight_check()`** — New async function in `crucible/core/runner.py` that validates three things before each scan: (1) target reachability, (2) HTTP method acceptance (405 → hard fail), (3) LLM-like response format (non-JSON → warning only, scan continues).
- **`PreflightResult` model** — New Pydantic model in `crucible/models.py` with fields `reachable`, `method_accepted`, `looks_like_llm_endpoint`, `status_code`, `warnings`, `errors`.
- **`--skip-preflight` CLI flag** — `crucible scan --skip-preflight` bypasses the preflight check entirely, useful for rate-limited endpoints or non-standard targets where the preflight request itself would be costly.
- **`skip_preflight` parameter on `run_scan()`** — Public API change; callers can set `skip_preflight=True` to bypass programmatically.
- **5 new tests** in `tests/test_preflight.py` covering 405 rejection, non-LLM warning, clean pass, skip-preflight bypass, and CLI exit-code-2 behaviour.

## [0.5.6] - 2026-06-29

### Added
- **`crucible diff` CLI Command** — Added a git-diff-like command to compare two scan results: `crucible diff scan_a.json scan_b.json`.
- **FindingStatus Enumeration** — Added `FindingStatus` enum with `FIXED`, `REGRESSED`, `NEW`, `RESOLVED`, `UNCHANGED_FAIL`, `UNCHANGED_PASS`, and `EXECUTION_ERROR` statuses.
- **Diff Models** — Added `FindingDiff`, `ModuleDiff`, and `DiffResult` models in `models.py`.
- **Diff Reporters** — Implemented console/terminal (with rich formatting), json, markdown, and html diff reports in `crucible/reporters/diff_reporter.py`.
- **GitHub Action Template** — Added a reference workflow template at `crucible/templates/github_action_diff.yml` for automated PR security diff comments.
- **15 new tests** in `tests/test_differ.py` testing different status assignments, delta computations, CLI output formats, and edge cases.

## [0.5.5] - 2026-06-29

### Added
- **MITRE ATLAS v2.1.0 Mapping** — Every attack category now maps to a MITRE ATLAS technique ID and tactic ID via `ATLAS_TECHNIQUE_MAP` in `crucible/attacks/base.py`. All 12 `AttackCategory` values are mapped. Individual attacks can override with `atlas_technique`, `atlas_tactic`, `atlas_url` class attributes.
- **NIST AI RMF 1.0 Mapping** — Every attack category maps to a NIST AI RMF function (GOVERN/MAP/MEASURE/MANAGE) and category via `NIST_MAP` in `crucible/attacks/base.py`. All 12 `AttackCategory` values are mapped.
- **MITRE ATLAS fields on `Finding`** — `atlas_technique` and `atlas_tactic` fields added to the `Finding` Pydantic model. Populated automatically from the parent attack's category mapping when a finding is created.
- **NIST AI RMF fields on `Finding`** — `nist_function` and `nist_category` fields added to the `Finding` Pydantic model.
- **SARIF 2.1.0 — ATLAS + NIST properties** — `atlas_technique`, `atlas_tactic`, `nist_function`, `nist_category` added to both `rules[].properties` and `results[].properties` in SARIF output.
- **HTML report — ATLAS + NIST columns** — ATLAS Technique (clickable link to atlas.mitre.org) and NIST Category columns added to the findings table.
- **`crucible/reporters/atlas_reporter.py`** — New `ATLASReporter` class generating Markdown/HTML MITRE ATLAS coverage reports.
- **`crucible/reporters/nist_reporter.py`** — New `NISTReporter` class generating Markdown/HTML NIST AI RMF coverage reports.
- **`crucible compliance-report --framework atlas|nist|all`** — Extended the `compliance-report` CLI command with a `--framework` option. Supports: `eu` (EU AI Act, default), `atlas` (MITRE ATLAS), `nist` (NIST AI RMF), `all` (generates all three reports with `_eu`, `_atlas`, `_nist` suffixes).
- **11 new tests** in `tests/test_atlas_mapping.py` covering mapping completeness, format validation, Finding model fields, reporter output, and SARIF properties.

## [0.5.4] - 2026-06-21

### Fixed
- **Bug 5 (Critical) — HTTP Non-2xx Responses Silent Passes (status-code branching)**: Resolved a critical issue where non-2xx HTTP responses (e.g., 503, 401, 405, 429) were passed to the response evaluator as if they were valid model output, producing false "safe/passed" security verdicts. Added `_HttpRetryableError` and explicit status-code branching in `BaseAttack.execute`: 5xx and 429 responses are retried up to `retry_count` times then flagged as `execution_error=True`; 3xx/4xx (except 429) are immediately flagged as `execution_error=True`; 2xx responses proceed to normal evaluation. This is the same root-cause family as Bugs 1 & 2 (non-network-level failures producing false passes), now fully closed.
- **Bug 6 (High) — Response Body Pre-Truncation Causes Raw JSON Leak in Snippets**: Resolved a response parsing bug where `response.text` was truncated to 2000 characters *before* being passed to `json.loads` in `extract_response`. For responses with long model content (>2000 chars in the Ollama JSON envelope), this produced invalid JSON, causing the extractor to fall back to the raw truncated Ollama envelope as the `response_snippet` instead of the extracted model text. Fix: pass the full `response.text` to `extract_response`, then truncate only the final extracted string to 2000 chars for display.
- **Bug 7 (Low) — Auto-Detection Response Path Ordering for Ollama**: Inserted `"message.content"` before `"message"` in `DEFAULT_RESPONSE_PATHS` so that auto-detection (when no explicit `response_path` is configured) correctly extracts the nested content string from Ollama `/api/chat` responses rather than the full message dict.

### Tests
- Added unit test `test_execute_handles_http_500_exhausted_retries` — verifies 500 retry-exhaustion yields `execution_error=True`, `passed=None`.
- Added unit test `test_execute_handles_http_400_client_error_no_retry` — verifies 4xx non-retryable errors yield `execution_error=True` immediately.
- Added unit test `test_execute_handles_http_429_transient_retries` — verifies 429 is retried and succeeds on a subsequent 200.
- Added unit test `test_execute_handles_http_200_html_refusal` — verifies 200 HTML block pages are evaluated as refusals (`passed=True`), not execution errors.
- Added regression test `test_execute_long_ollama_response_extracts_content_not_raw_json` — guards against the pre-truncation bug: Ollama JSON responses with content >2000 chars must yield extracted model text in `response_snippet`, not the raw JSON envelope.

### Documentation
- Bumped stale `v0.5.3` version references in module docstrings for `exfiltration_kit.py`, `zero_day_hunter.py`, `adaptive_fingerprinter.py`, and `shadow_payload_generator.py` to `v0.5.4`.

## [0.5.3] - 2026-06-20

### Fixed
- **Bug 1 (Critical) — Network/Timeout Errors Silent Passes**: Resolved a critical issue where connection errors or timeouts during scans were silently recorded as complying with security policies (marked as `passed`). Introduced `Grade.INCOMPLETE` when more than 20% of attacks fail, and enforced a non-zero exit code (1) unless `--allow-incomplete` is specified.
- **Bug 2 (Critical) — MCP Scanner Empty Manifest Fallback**: Fixed `mcp-scan` command to immediately fail and exit with code 2 when fetching or parsing the MCP server's manifest fails, instead of falling back to an empty manifest and reporting a perfect 100/100 Grade A.
- **Bug 3 — Windows UTF-8 Terminal Encoding**: Reconfigured terminal standard output/error streams to UTF-8 on startup to prevent encoding crashes (e.g. CP1252) when printing unicode characters.
- **Bug 4 — Dynamic Versioning**: Resolved the Crucible package version dynamically for `ScanResult` rather than returning a hardcoded `0.1.0` placeholder.

### Documentation
- Bumped stale `v0.5.0` version references in module docstrings for `exfiltration_kit.py`, `zero_day_hunter.py`, `adaptive_fingerprinter.py`, and `shadow_payload_generator.py` to `v0.5.3`.
- Added two FAQ entries to README documenting known limitations: (1) `--method GET` against POST-only endpoints silently produces all-pass results; (2) HTTP 503 responses are scored as refusals rather than execution errors. Both are tracked for v0.5.4.

## [0.5.0] - 2026-06-02

### Added
- **Hallucination Detection Module** (`crucible/attacks/hallucination.py`) — 15 new deterministic attack vectors testing misinformation, memory fabrication, fake citations, fake API calls, and resource scope oversteps (OWASP-LLM09 / AttackCategory.OVERRELIANCE).
- **Toxicity and Content Safety Module** (`crucible/attacks/toxicity.py`) — 20 new deterministic safety/jailbreak vectors mapping to role-play escalation, authority bypass, academic/creative framing, and translation bypasses. Checks for known harmful keywords and contains a response length heuristic where responses > 200 words are flagged.
- **Local Model Presets** — richer `ProviderPreset` configurations added for **Ollama**, **LM Studio**, and **HuggingFace TGI** with default response JMESPaths, default timeouts (120s), and custom templates.
- **CLI --model Flag** — specify target model name (e.g. `llama3`) for local model formatting.
- **CLI --fail-on Flag** — fully verified exit code 1 / gate capability when findings matching or exceeding specified severity are detected (CRITICAL, HIGH, MEDIUM, LOW, INFO).
- **SARIF 2.1.0 Reporter** — export Crucible scan results in standard SARIF 2.1.0 format for GitHub Security integration.
- **CLI --scope-file Flag** — enforce whitelisted target domains defined in a YAML configuration.
- **CLI --rate-limit Flag** — enforce global request rate limiting (in requests per second).
- **CLI --turns Flag** — specify turn limits for multi-turn scan strategies.

### Fixed
- **`mcp-scan` path bug** — resolved crash where local file paths passed to `--server` were parsed as HTTP URLs.
- **Dynamic Versioning** — resolve package version dynamically via `importlib.metadata` rather than a hardcoded old string.
- **UTF-8 Encoding** — enforce UTF-8 file/report encoding for Windows compatibility.
- **Global Rate Limiting Lock** — fixed async event loop hang by lazily initializing lock.

## [0.3.0] - 2026-05-05

### Added
- **Behavioral Drift Engine** (`crucible behavioral-audit`) — multi-turn conversation simulation
  with TF-cosine similarity drift detection across 3 audit phases (baseline, escalation, trust degradation)
- **Context-Aware Agent Profiler** (`crucible profile`) — auto-discovers agent type (SQL, HR, CS, etc.)
  and infers capabilities (code execution, web search, internal DB access); outputs `agent_profile.json`
- **Multi-turn Attack Engine** — `--strategy multi-turn` flag for `crucible scan` with two strategies:
  - *Crescendo* — incremental severity escalation across turns
  - *Context Confusion* — alternating benign/malicious turns to break context boundaries
- **EU AI Act 2024 Compliance Module** (`crucible compliance-report`) — maps findings to
  Articles 10, 14, 15, and 50 with automated remediation guidance
- **Compliance Reporter** — generates structured Markdown/JSON compliance reports
- `BehavioralEscalationSequence` attack with 10 trust-escalation payloads
- `--profile` flag for `crucible scan` to load profiler output and target attacks
- New Pydantic models: `BehavioralProfile`, `DriftScore`, `AgentProfile`,
  `ComplianceReport`, `ComplianceRequirement`, `ConversationHistory`, `ConversationTurn`

### Fixed
- Enum `str()` representation inconsistency across Python versions in bug bounty reporter
  (now uses `.value.upper()` for consistent output on Python 3.10–3.14)
- `jmespath` import type annotation in `response_extractor.py`

## [0.2.0] - 2026-05-05

### Added
- **Mutation Engine** (`--mutate`) — 6 payload obfuscation strategies to bypass WAFs and guardrails:
  Base64, URL encoding, Hex, Unicode escaping, Whitespace injection, Polyglot wrapping
- **Bug Bounty Report Generator** (`--generate-report`) — auto-generates Markdown PoC reports
  for Critical/High findings, formatted for HackerOne/Bugcrowd submission
- **HTML Reporter** — rich visual scan report with interactive findings table
- **Slack Reporter** — webhook integration for real-time scan notifications
- **Scan Cache** — TTL-based result caching to avoid redundant scans (`--cache`, `--cache-ttl`)
- **Verbose logging** (`--verbose`) — granular payload/response logs to stderr
- **Rate limiting** — `--delay` flag for respectful scanning of production APIs
- **Scope enforcement** — `--scope` flag to restrict scanning to defined URL patterns
- **Enterprise Graph attacks** — cross-agent trust exploitation vectors
- **Advanced Orchestration attacks** — A2A contagion, parser differential polyglot, URL hallucination
- **Memory Poisoning attacks** — persistent state manipulation across sessions
- **Infrastructure Escalation attacks** — SSRF and cloud metadata exfiltration tests
- **MCP Security module** — Model Context Protocol trust boundary testing
- **LangChain example** — ready-to-run integration test for LangChain/LangServe agents
- Body template presets (`--format-preset`) for OpenAI, Anthropic, Ollama API formats
- `--retry` and `--timeout` flags for resilient scanning

## [0.1.0] - 2026-04-21

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

[Unreleased]: https://github.com/crucible-security/crucible/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/crucible-security/crucible/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/crucible-security/crucible/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/crucible-security/crucible/releases/tag/v0.1.0
