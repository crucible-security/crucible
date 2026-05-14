from __future__ import annotations

import html
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crucible.core.comparator import FindingDiff, ScanDiff


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
  display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 1rem; margin-bottom: 2rem;
}
.card {
  background: #1e293b; border-radius: 0.75rem; padding: 1.25rem;
  border: 1px solid #334155;
}
.card .label { font-size: 0.75rem; text-transform: uppercase;
  letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.5rem; }
.card .value { font-size: 1.75rem; font-weight: 700; }
.diff-table {
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
.badge {
  display: inline-block; padding: 0.2rem 0.6rem;
  border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
  text-transform: uppercase;
}
.status-fixed { background: #14532d; color: #86efac; }
.status-remaining { background: #450a0a; color: #fca5a5; }
.status-new { background: #7c2d12; color: #fdba74; }
.status-regression { background: #7f1d12; color: #f87171; border: 1px solid #f87171; }
footer {
  margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #334155;
  font-size: 0.75rem; color: #475569; text-align: center;
}
"""


def _esc(value: str) -> str:
    return html.escape(str(value))


class DiffReporter:
    """Generates an HTML report showing the delta between two Crucible scans."""

    def write(self, diff: ScanDiff, path: str | Path) -> Path:
        output = Path(path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_html(diff), encoding="utf-8")
        return output

    def to_html(self, diff: ScanDiff) -> str:
        generated_at = diff.timestamp.strftime("%Y-%m-%d %H:%M UTC")
        rows = self._render_diff_rows(diff.diffs)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Crucible Diff Report — {_esc(diff.target_name)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>Crucible Diff Report</h1>
  <div style="font-size:1.1rem;color:#94a3b8;">{_esc(diff.target_name)}</div>
  <div class="meta">Generated {generated_at}</div>

  <div class="summary-grid" style="margin-top: 2rem;">
    <div class="card">
      <div class="label">Fixed</div>
      <div class="value" style="color:#16a34a;">{diff.fixed_count}</div>
    </div>
    <div class="card">
      <div class="label">Remaining</div>
      <div class="value" style="color:#dc2626;">{diff.remaining_count}</div>
    </div>
    <div class="card">
      <div class="label">New Findings</div>
      <div class="value" style="color:#ea580c;">{diff.new_count}</div>
    </div>
    <div class="card">
      <div class="label">Regressions</div>
      <div class="value" style="color:#f87171;">{diff.regression_count}</div>
    </div>
  </div>

  <h2>Comparison Details</h2>
  <table class="diff-table">
    <thead>
      <tr>
        <th>Status</th>
        <th>Severity</th>
        <th>Finding</th>
        <th>Attack Name</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <footer>
    Powered by <strong>Crucible</strong> Diff Engine
  </footer>
</body>
</html>"""

    def _render_diff_rows(self, diffs: list[FindingDiff]) -> str:
        if not diffs:
            return '<tr><td colspan="4" style="text-align:center;padding:2rem;">No changes detected between scans.</td></tr>'

        html_rows = []
        # Sort so regressions and new findings appear at the top
        sorted_diffs = sorted(
            diffs, key=lambda x: (x.status != "REGRESSION", x.status != "NEW", x.status)
        )

        for d in sorted_diffs:
            status_class = f"status-{d.status.lower()}"
            html_rows.append(
                f"""
      <tr>
        <td><span class="badge {status_class}">{_esc(d.status)}</span></td>
        <td><span style="font-size:0.75rem; font-weight:bold;">{_esc(d.severity.upper())}</span></td>
        <td>
          <strong>{_esc(d.title)}</strong>
          <div style="font-size:0.75rem; color:#64748b; margin-top:0.2rem;">{_esc(d.description[:100]) if d.description else ""}</div>
        </td>
        <td><code style="font-size:0.75rem; color:#94a3b8;">{_esc(d.attack_name)}</code></td>
      </tr>"""
            )
        return "".join(html_rows)
