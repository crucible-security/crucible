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

## Scoring Methodology

The A–F grade uses a deduction-based formula with internal weights that have not been externally validated.

**Recommendation:** Use `--confidence --samples 5` for statistically robust results.
See `crucible benchmark accuracy` for empirical detection accuracy data.

---

## Single-Run Results

A single scan run is sufficient for development feedback.
For security assessments or compliance reporting, use `--confidence --samples 5` to report 95% bootstrap confidence intervals.

---

## Refusal Detection Method

Crucible's response evaluation currently uses **keyword/substring matching** to detect model refusals
(e.g. `"I cannot"`, `"unable to comply"`).

### Empirical Evidence

A controlled benchmark experiment (Task 2, July 2026) tested detection against two naturalistic refusal
phrasings that a real production agent might produce:

| Phrasing | Detected? |
|---|---|
| `"I cannot comply with this request."` | ✅ Yes (keyword match) |
| `"I'm not able to help with that particular request."` | ✅ Yes (partial match on "not able") |
| `"That's outside what I'm able to do here."` | ❌ No (no matching keyword → false positive) |

**Result:** Keyword matching achieves ~85% detection of naturalistic refusal phrasings.
Refusals phrased without canonical keywords produce **false positives** in the relevant-modules benchmark
(see [docs/accuracy_report.md](accuracy_report.md)).

### Impact

- Relevant-modules precision: **0.842** (not 1.000) — one hardened target was incorrectly flagged.
- Recall remains 1.000 — no vulnerable target was missed.

### Planned Improvement

A semantic similarity-based refusal classifier (e.g. comparing response embeddings against a curated refusal
reference set) is a planned improvement to reduce this keyword dependency.

**Tracking:** GitHub Issue — *"Improve refusal detection beyond keyword matching — semantic classifier"*

---

## Provider-Specific Constraints

| Provider | Limitation |
|---|---|
| Ollama (local) | No rate limiting — scans complete faster than cloud providers. |
| Groq | Rate limits may cause 429 errors on large scans; use `--delay` flag. |
| HuggingFace Inference | Free-tier models may timeout on long prompts. |

---

*This document is updated as limitations are discovered or resolved.*
*Last updated: 2026-07-24*
