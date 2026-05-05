from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from crucible.reporters.base import BaseReporter

if TYPE_CHECKING:
    from crucible.models import Finding, ScanResult

# Severity colour palette (inline CSS — no external dependencies)
_SEVERITY_STYLES: dict[str, tuple[str, str]] = {
    "critical": ("#7f1d1d", "#fca5a5"),  # bg, text
    "high": ("#7c2d12", "#fdba74"),
    "medium": ("#713f12", "#fde047"),
    "low": ("#1e3a5f", "#93c5fd"),
    "info": ("#1f2937", "#d1d5db"),
}

_GRADE_COLOURS: dict[str, str] = {
    "A": "#16a34a",
    "B": "#65a30d",
    "C": "#ca8a04",
    "D": "#ea580c",
    "F": "#dc2626",
}

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
.header { display: flex; align-items: center; gap: 1.5rem; margin-bottom: 2rem; }
.grade-badge {
  width: 72px; height: 72px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 2rem; font-weight: 800; flex-shrink: 0;
}
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
.modules-table, .findings-table {
  width: 100%; border-collapse: collapse; font-size: 0.875rem;
  background: #1e293b; border-radius: 0.75rem; overflow: hidden;
  border: 1px solid #334155;
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
.pass { background: #14532d; color: #86efac; }
.fail { background: #450a0a; color: #fca5a5; }
.score-bar-bg {
  background: #334155; border-radius: 9999px;
  height: 8px; width: 100%; overflow: hidden;
}
.score-bar-fill { height: 100%; border-radius: 9999px; }
.no-findings {
  background: #14532d; color: #86efac; border-radius: 0.75rem;
  padding: 1.25rem; text-align: center; font-weight: 600;
}
.owasp-ref { font-size: 0.75rem; color: #60a5fa; }
.payload { font-family: monospace; font-size: 0.75rem;
  background: #0f172a; padding: 0.25rem 0.5rem;
  border-radius: 0.25rem; max-width: 300px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
footer {
  margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #334155;
  font-size: 0.75rem; color: #475569; text-align: center;
}
"""


def _score_bar_colour(score: float) -> str:
    if score >= 90:
        return "#16a34a"
    if score >= 75:
        return "#65a30d"
    if score >= 60:
        return "#ca8a04"
    if score >= 40:
        return "#ea580c"
    return "#dc2626"


def _severity_badge(severity: str) -> str:
    bg, fg = _SEVERITY_STYLES.get(severity.lower(), ("#374151", "#d1d5db"))
    label = severity.upper()
    return f'<span class="badge" style="background:{bg};color:{fg};">{label}</span>'


def _esc(value: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(value))


class HTMLReporter(BaseReporter):
    """Generates a self-contained HTML security report from a :class:`ScanResult`."""

    def render(self, result: ScanResult) -> None:  # pragma: no cover
        """Print the HTML to stdout (useful for piping or testing)."""
        print(self.to_html(result))

    def write(self, result: ScanResult, path: str | Path) -> Path:
        """Write the HTML report to *path* and return the resolved path."""
        output = Path(path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_html(result), encoding="utf-8")
        return output

    def to_html(self, result: ScanResult) -> str:
        """Render *result* as a self-contained HTML string."""
        grade = result.grade.value if result.grade else "—"
        grade_colour = _GRADE_COLOURS.get(grade, "#64748b")
        score = result.overall_score or 0.0
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        all_findings = [f for mod in result.modules for f in (mod.findings or [])]
        failed_findings = [f for f in all_findings if not f.passed]
        total_attacks = sum(m.total_attacks for m in result.modules)
        total_passed = sum(m.passed for m in result.modules)
        total_failed = sum(m.failed for m in result.modules)

        modules_rows = self._render_modules(result)
        findings_section = self._render_findings(failed_findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Crucible Security Report — {_esc(result.target.name)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="header">
    <div class="grade-badge" style="background:{grade_colour}22;color:{grade_colour};border:3px solid {grade_colour};">{_esc(grade)}</div>
    <div>
      <h1>Crucible Security Report</h1>
      <div style="font-size:1.1rem;color:#94a3b8;margin-top:0.25rem;">
        {_esc(result.target.name)} &mdash; <code style="font-size:0.9rem;">{_esc(str(result.target.url))}</code>
      </div>
      <div class="meta">Generated {generated_at} &nbsp;·&nbsp; Scan ID: {_esc(str(result.id))}</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="card">
      <div class="label">Overall Score</div>
      <div class="value" style="color:{grade_colour};">{score:.1f}</div>
    </div>
    <div class="card">
      <div class="label">Total Attacks</div>
      <div class="value">{total_attacks}</div>
    </div>
    <div class="card">
      <div class="label">Passed</div>
      <div class="value" style="color:#16a34a;">{total_passed}</div>
    </div>
    <div class="card">
      <div class="label">Failed</div>
      <div class="value" style="color:#dc2626;">{total_failed}</div>
    </div>
    <div class="card">
      <div class="label">Modules Run</div>
      <div class="value">{len(result.modules)}</div>
    </div>
    <div class="card">
      <div class="label">Status</div>
      <div class="value" style="font-size:1rem;padding-top:0.35rem;">{_esc(result.status.value.upper())}</div>
    </div>
  </div>

  <h2>Module Results</h2>
  <table class="modules-table">
    <thead>
      <tr>
        <th>Module</th>
        <th>Category</th>
        <th>Attacks</th>
        <th>Passed</th>
        <th>Failed</th>
        <th>Score</th>
      </tr>
    </thead>
    <tbody>
      {modules_rows}
    </tbody>
  </table>

  <h2>Findings</h2>
  {findings_section}

  <footer>
    Powered by <strong>Crucible</strong> &mdash;
    <a href="https://github.com/crucible-security/crucible" style="color:#60a5fa;">
      github.com/crucible-security/crucible
    </a>
  </footer>
</body>
</html>"""

    def _render_modules(self, result: ScanResult) -> str:
        rows: list[str] = []
        for mod in result.modules:
            score = mod.score or 0.0
            bar_colour = _score_bar_colour(score)
            status_class = "pass" if mod.failed == 0 else "fail"
            status_label = "PASS" if mod.failed == 0 else "FAIL"
            rows.append(f"""
      <tr>
        <td><strong>{_esc(mod.module_name)}</strong></td>
        <td><span style="color:#94a3b8;font-size:0.8rem;">{_esc(mod.category.value)}</span></td>
        <td style="text-align:center;">{mod.total_attacks}</td>
        <td style="text-align:center;color:#86efac;">{mod.passed}</td>
        <td style="text-align:center;color:#fca5a5;">{mod.failed}</td>
        <td style="min-width:140px;">
          <div style="display:flex;align-items:center;gap:0.5rem;">
            <div class="score-bar-bg" style="flex:1;">
              <div class="score-bar-fill"
                   style="width:{score:.1f}%;background:{bar_colour};"></div>
            </div>
            <span style="color:{bar_colour};font-weight:600;min-width:40px;text-align:right;">
              {score:.1f}
            </span>
            <span class="badge {status_class}">{status_label}</span>
          </div>
        </td>
      </tr>""")
        return "".join(rows)

    def _render_findings(self, findings: list[Finding]) -> str:
        if not findings:
            return (
                '<div class="no-findings">'
                "✅ No vulnerabilities found — the agent passed all attack vectors!"
                "</div>"
            )

        rows: list[str] = []
        for f in findings:
            sev_badge = _severity_badge(f.severity.value)
            owasp = f.owasp_ref or "—"
            payload_display = f.payload[:80] + "…" if len(f.payload) > 80 else f.payload
            rows.append(f"""
      <tr>
        <td>{sev_badge}</td>
        <td><strong>{_esc(f.title)}</strong>
            <div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem;">
              {_esc(f.attack_name)}
            </div>
        </td>
        <td><span class="owasp-ref">{_esc(owasp)}</span></td>
        <td><span class="payload">{_esc(payload_display)}</span></td>
        <td style="max-width:220px;font-size:0.8rem;color:#94a3b8;">
          {_esc(f.remediation[:150]) if f.remediation else "—"}
        </td>
      </tr>""")

        return f"""
  <table class="findings-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Finding</th>
        <th>OWASP Ref</th>
        <th>Payload</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>"""
