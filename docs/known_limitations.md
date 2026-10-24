# Known Limitations

This document tracks known constraints, gaps, and planned improvements in Crucible.
See the [README Known Limitations section](../README.md#known-limitations) for the condensed summary.

---

## MCP stdio Transport

Crucible's trace proxy intercepts **HTTP-based MCP only**.
`stdio` transport (subprocess-based) is invisible to the HTTP proxy.
On Linux, the eBPF sidecar provides coverage via `execve` monitoring.

**Workaround:** Use the `--transport http` flag when configuring targets, or enable the eBPF sidecar on Linux.

See: [docs/mcp-transport-coverage.md](mcp-transport-coverage.md)

---

## eBPF Platform Support

`crucible ebpf` requires Linux kernel ≥ 5.8 with BTF for real kernel-level monitoring.
Windows and macOS use simulation mode for development purposes only — this is **not** production-grade enforcement.

**Planned:** Investigate `ETW`-based kernel monitoring for Windows in a future release.

---

## CGAF Fitness Signal

The adaptive fuzzer (CGAF) uses semantic refusal detection rather than token log-probabilities.
True logprob-guided fuzzing is planned for a future release when stable logprob APIs are confirmed across providers.

---

## Refusal Detection Method & Heuristic Calibration

As of v0.19.0, Crucible uses a 3-tier hybrid pipeline for refusal detection:
1. Fast-Path Pre-Filter: Regex matching against standard refusals and HTTP/gateway error signatures.
2. Weighted Lexicon Scorer (`weighted_lexicon`): Computes token-weight heuristic ratios between refusal and compliance vocabulary.
3. Character N-Gram Jaccard Fallback (`char_ngram_similarity`): Evaluates n-gram similarity against canonical refusal anchors when lexicon confidence is in the uncertainty interval (score between 0.25 and 0.75).

### Calibration Disclosure & Heuristic Limits

- **Uncalibrated Thresholds**: The decision thresholds (refusal threshold $\ge 0.75$, compliance threshold $\le 0.25$) and individual token weights are hand-curated heuristics.
- **Corpus Provenance**: They were hand-tuned on canonical refusal phrases and synthetic paraphrases. They were **not** mathematically fitted or trained on external benchmark corpora like HarmBench or AdvGLUE.
- **Out-of-Vocabulary Risk**: Paraphrased refusals that do not share vocabulary with the curated token weights or n-gram anchors may fall back to `INCONCLUSIVE` or result in false classifications.

---

## Target Capability Modeling & Pure LLM Defaults

Crucible's scan suite includes attacks targeting tool integration, operating system interaction, file access, and multi-agent delegation.

- When `--capabilities` is omitted, Crucible defaults to assuming a pure LLM target without external tools, filesystem, shell, or MCP access.
- In pure LLM mode, module attacks that require specific system capabilities evaluate to `N/A` (Inapplicable) and are never sent over the network.
- To scan tool-enabled agents, you must explicitly declare capabilities using `--capabilities` (e.g. `--capabilities shell,file_system,mcp`).

---

## Scoring Methodology

Crucible does not use letter grades (A–F) or subjective assurance labels (e.g., "Robust"). The score represents an internal deduction-based index over Crucible's open-source test suite.

**Recommendation:** For CI pipelines, use `--min-coverage <PERCENT>` to verify sufficient applicable test coverage, and assess targets based on `Tests Passed: X/Y` and the severity breakdown of failed findings.

---

## Provider-Specific Constraints

| Provider | Limitation |
|---|---|
| Ollama (local) | No rate limiting — scans complete faster than cloud providers. |
| Groq | Rate limits may cause 429 errors on large scans; use `--delay` flag. |
| HuggingFace Inference | Free-tier models may timeout on long prompts. |

---

*This document is updated as limitations are discovered or resolved.*
*Last updated: 2026-10-24*
