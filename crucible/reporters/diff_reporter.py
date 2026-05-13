from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crucible.core.comparator import ComparisonResult

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: #0f172a;
  color: #e2e8f0;
  padding: 2rem;
  line-height: 1.6;
}
h1 { font-size: 2rem; font-weight: 700; margin-bottom: 0.25rem; }
h2 { font-size: 1.25rem; font-weight: 600; color: #94a3b8; margin: 2rem 0 1rem; }
.meta { font-size: 0.875rem; color: #64748b; margin-top: 0.25rem; }
.summary-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 1rem; margin-bottom: 2rem;
}
.card {
  background: #1e293b; border-radius: 0.75rem; padding: 1.25rem;
  border: 1px solid #334155;
}
.card .label { font-size: 0.75rem; text-transform: uppercase;
  letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.5rem; }
.card .value { font-size: 1.75rem; font-weight: 700; }
table {
  width: 100%; border-collapse: collapse; font-size: 0.875rem;
  background: #1e293b; border-radius: 0.75rem; overflow: hidden;
  border: 1px solid #334155; margin-bottom: 1rem;
}
th {
  background: #0f172a; text-align: left; padding: 0.75rem 1rem;
  font-size: 0.75rem; text-transform: uppercase;
  letter-spacing: 0.05em; color: #64748b; border-bottom: 1px solid #334155;
}
td { padding: 0.75rem 1rem; border-bottom: 1px solid #1e293b; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #263348; }
.badge {
  display: inline-block; padding: 0.2rem 0.6rem;
  border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
}
.badge-fixed { background: #14532d; color: #86efac; }
.badge-remaining { background: #450a0a; color: #fca5a5; }
.badge-regression { background: #4c1d95; color: #c4b5fd; }
.badge-new { background: #1e3a5f; color: #93c5fd; }
.sev-critical { background: #7f1d1d; color: #fca5a5; }
.sev-high { background: #7c2d12; color: #fdba74; }
.sev-medium { background: #713f12; color: #fde047; }
.sev-low { background: #1e3a5f; color: #93c5fd; }
.sev-info { background: #1f2937; color: #d1d5db; }
.payload { font-family: monospace; font-size: 0.75rem;
  background: #0f172a; padding: 0.25rem 0.5rem;
  border-radius: 0.25rem; max-width: 300px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
footer {
  margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #334155;
  font-size: 0.75rem; color: #475569; text-align: center;
}
.section-title { font-size: 1rem; font-weight: 600; margin: 1.5rem 0 0.75rem; }
"""


def _esc(value: str) -> str:
    return html.escape(str(value))


def _severity_class(severity: str) -> str:
    s = severity.lower()
    return f"sev-{s}" if s in ("critical", "high", "medium", "low", "info") else "sev-info"


def _status_badge(status: str) -> str:
    cls = f"badge-{status}"
    return f'<span class="badge {cls}">{status.upper()}</span>'


def _finding_row(finding: dict, status: str) -> str:
    title = _esc(finding.get("title", "—"))
    attack = _esc(finding.get("attack_name", "—"))
    severity = finding.get("severity", {})
    if isinstance(severity, dict):
        severity = severity.get("value", "info")
    sev_badge = f'<span class="badge {_severity_class(severity)}">{_esc(severity.upper())}</span>'
    category = _esc(finding.get("category", {}) or "—")
    if isinstance(finding.get("category"), dict):
        category = _esc(finding["category"].get("value", "—"))
    payload = finding.get("payload", "")[:80]
    if len(finding.get("payload", "")) > 80:
        payload += "…"

    return f"""
      <tr>
        <td>{_status_badge(status)}</td>
        <td>{sev_badge}</td>
        <td><strong>{title}</strong>
          <div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem;">{attack}</div>
        </td>
        <td><span style="color:#94a3b8;font-size:0.8rem;">{category}</span></td>
        <td><span class="payload">{_esc(payload)}</span></td>
      </tr>"""


class DiffReporter:
    """Generates an HTML diff report comparing two scan results."""

    def write(self, result: ComparisonResult, path: str | Path) -> Path:
        output = Path(path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_html(result), encoding="utf-8")
        return output

    def to_html(self, result: ComparisonResult) -> str:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        summary = result.summary

        s = f"Summary: {summary['fixed']} fixed, {summary['remaining']} remaining, {summary['regressions']} regression"

        # Build rows for each section
        fixed_rows = "".join(_finding_row(f, "fixed") for f in result.fixed)
        remaining_rows = "".join(
            _finding_row(f.get("after", f.get("before", {})), "remaining")
            for f in result.remaining
        )
        regression_rows = "".join(_finding_row(f, "regression") for f in result.regressions)

        sections = ""

        if result.fixed:
            sections += f"""
  <div class="section-title" style="color:#86efac;">✅ Fixed ({summary['fixed']})</div>
  <table>
    <thead>
      <tr><th>Status</th><th>Severity</th><th>Finding</th><th>Category</th><th>Payload</th></tr>
    </thead>
    <tbody>{fixed_rows}</tbody>
  </table>"""

        if result.remaining:
            sections += f"""
  <div class="section-title" style="color:#fca5a5;">🔄 Remaining ({summary['remaining']})</div>
  <table>
    <thead>
      <tr><th>Status</th><th>Severity</th><th>Finding</th><th>Category</th><th>Payload</th></tr>
    </thead>
    <tbody>{remaining_rows}</tbody>
  </table>"""

        if result.regressions:
            sections += f"""
  <div class="section-title" style="color:#c4b5fd;">📈 Regressions ({summary['regressions']})</div>
  <table>
    <thead>
      <tr><th>Status</th><th>Severity</th><th>Finding</th><th>Category</th><th>Payload</th></tr>
    </thead>
    <tbody>{regression_rows}</tbody>
  </table>"""

        if not sections:
            sections = '<div class="section-title">No differences detected between scans.</div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Crucible Diff Report</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>Crucible Diff Report</h1>
  <div class="meta">Generated {generated_at}</div>
  <div style="font-size:1rem;color:#94a3b8;margin: 0.5rem 0 1.5rem;">{s}</div>

  <div class="summary-grid">
    <div class="card">
      <div class="label">Fixed</div>
      <div class="value" style="color:#16a34a;">{summary['fixed']}</div>
    </div>
    <div class="card">
      <div class="label">Remaining</div>
      <div class="value" style="color:#ea580c;">{summary['remaining']}</div>
    </div>
    <div class="card">
      <div class="label">Regressions</div>
      <div class="value" style="color:#a78bfa;">{summary['regressions']}</div>
    </div>
  </div>

  {sections}

  <footer>
    Powered by <strong>Crucible</strong> &mdash;
    <a href="https://github.com/crucible-security/crucible" style="color:#60a5fa;">
      github.com/crucible-security/crucible
    </a>
  </footer>
</body>
</html>"""
