# Crucible Roadmap

## v0.1.0 ✅ Released April 2026
- 90+ adversarial attack vectors across 4 modules
- OWASP Agentic AI Top 10 mapping on every finding
- CVSS-style severity scoring (Critical/High/Medium/Low)
- MCP trust boundary testing — first open-source coverage
- Cross-platform CI — Ubuntu, Windows, macOS
- Python 3.10 / 3.11 / 3.12 support
- 97% test coverage, 0 mypy strict errors
- PyPI published — pip install crucible-security

## v0.2.0 ✅ Released May 2026
- [x] Authentication header support (Bearer, API key)
- [x] Payload Mutation Engine (Base64, URL, Hex, Unicode, Whitespace, Polyglot)
- [x] Bug Bounty Report Generator (HackerOne/Bugcrowd Markdown format)
- [x] HTML and Slack report export
- [x] Scan result caching with TTL
- [x] `--verbose` flag for detailed attack logs
- [x] Enterprise graph and advanced orchestration attacks
- [x] Memory poisoning and infrastructure escalation attacks
- [x] Rate limiting and scope enforcement

## v0.3.0 ✅ Released May 2026
- [x] Behavioral Drift Engine — multi-turn behavioral integrity testing
- [x] Context-Aware Agent Profiler — auto-detect agent type and capabilities
- [x] Multi-turn Attack Engine — Crescendo and Context Confusion strategies
- [x] EU AI Act 2024 Compliance Module — map findings to Articles 10/14/15/50
- [x] Compliance Reporter — structured Markdown/JSON regulatory reports
- [x] 192 passing tests, 85%+ coverage, strict mypy throughout

## v0.4.0 ✅ Released June 2026
- [x] Deep Research Engine — autonomous multi-step threat research
- [x] Multi-Agent Contagion — test cascading compromises in agent networks
- [x] Dynamic Attack Generator — generate targeted test vectors at runtime
- [x] Active Deception Canaries — decoy files and credentials for agent trapping

## v0.5.0 ✅ Released June 2026
- [x] Hallucination & Overreliance Detection — 15 attacks targeting agent reliability
- [x] Toxicity & Content Safety Auditing — 20 safety evaluation vectors
- [x] SARIF 2.1.0 Export — integrate results directly into GitHub Code Scanning
- [x] Preflight Endpoint validation & HTTP 503 retry mechanics

## v0.6.0 / v0.6.1 ✅ Released June 2026
- [x] Statistical Confidence Intervals (`--confidence` scan mode)
- [x] Pure Python Bootstrap CI with Binomial Significance flag bounds
- [x] 8 new tests for Bootstrap & significance CLI reporting
- [x] Crucible Watch Daemon — watch log/store alerting

## v0.7.0 ✅ Released June 2026
- [x] `crucible trace` proxy — MCP tool-call interception & auditing proxy
- [x] Strict YAML policy checking (`allow`, `deny`, `alert`) with regex matching
- [x] JSON-RPC HTTP 200 blocked_by_policy responses for client compatibility
- [x] 15 new tests & Mock MCP Server fixture for integration verification

## v0.8.0 ✅ Released June 2026
- [x] `crucible poison-test` suite — RAG & stateful memory poisoning evaluator
- [x] 4 advanced document poisoning techniques (Semantic Anchor, zero-width Impersonation, Semantic Sleeper templates, RAG Semantic Index injection)
- [x] CLI commands to plant, verify, run automated end-to-end RAG lifecycles, list, and inspect poisoning sessions
- [x] 13 new tests for poisoning serialization, generator output, and CLI verification

## v1.0.0 — Target: 2027
- [ ] Crucible Cloud hosted dashboard with team accounts
- [ ] CI/CD webhooks and Slack/PagerDuty integrations
- [ ] Tool-use simulation (agents with API/DB access)
- [ ] Voice agent support
- [ ] Enterprise compliance suite (SOC 2, ISO 27001 audit-ready reports)
- [ ] Custom attack vector marketplace
- [ ] Enterprise SLA and dedicated support
- [ ] On-premises deployment option

---

Want to help build any of these?
Check our [open issues](https://github.com/crucible-security/crucible/issues)
or email crucible.sec@gmail.com
