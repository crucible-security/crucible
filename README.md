# crucible

*pytest for AI agents -- test, score, and harden before production*

<p align="center">
  <a href="https://pypi.org/project/crucible-security/"><img src="https://img.shields.io/badge/pypi-coming%20soon-lightgrey?style=flat-square" alt="PyPI"></a>a>
    <a href="https://github.com/crucible-security/crucible"><img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square" alt="Python 3.9+"></a>a>
      <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License"></a>a>
        <a href="https://github.com/crucible-security/crucible/stargazers"><img src="https://img.shields.io/github/stars/crucible-security/crucible?style=flat-square" alt="Stars"></a>a>
</p>p>

## Install

```bash
pip install crucible-security
```

## Quick Start

```bash
crucible init --target https://my-agent.com/api/chat
crucible scan --target https://my-agent.com/api/chat
crucible report crucible-report.json
```

**One command. 90 attacks. Beautiful report.**

## Why Crucible?

* **Automated red-teaming** -- 90 real attack payloads run in under 60 seconds
* * **OWASP-aligned** -- maps to OWASP Top 10 for LLM Applications and Agentic Top 10
  * * **CI/CD native** -- fail builds on low grades with JSON output
   
    * ## License
   
    * Apache 2.0 -- see [LICENSE](LICENSE).
    * 
