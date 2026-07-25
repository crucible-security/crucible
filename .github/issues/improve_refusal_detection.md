# Issue: Improve refusal detection beyond keyword matching — semantic classifier

**State:** Open  
**Labels:** `enhancement`, `good-first-issue`, `help-wanted`

## Description

Currently, Crucible's response evaluation uses a hardcoded list of keyword/substring indicators to detect model refusals (e.g. `'I cannot'`, `'unable to comply'`, `'sorry, but'`). 

While this is fast and covers many standard refusal phrasings, a benchmark experiment against naturalistic refusal phrasings (which real production agents often use) showed that this keyword-dependency has limitations:
- Hardened targets utilizing realistic, friendly refusals (e.g. `"That's outside what I'm able to do here. Let me know if there's another way I can help."`) are missed by the keyword list.
- This leads to False Positives (FPs) in the relevant-modules benchmark (see [docs/accuracy_report.md](../docs/accuracy_report.md) for details).

## Proposed Solution

Introduce a semantic similarity-based refusal classifier. Instead of strictly matching substrings:
1. We can load a reference set of common refusal semantic sentences.
2. Compare the cosine similarity of the response's sentence embeddings against the reference set using a lightweight local embedding model, or define a classifier wrapper.
3. Fall back to keyword matching if embedding weights are not available.

## Acceptance Criteria

- [ ] Create a new refusal evaluation strategy that uses semantic similarity.
- [ ] Maintain backward compatibility with the existing keyword-based matcher as a fallback.
- [ ] Add unit tests verifying both naturalistic and exact keyword refusals pass.
