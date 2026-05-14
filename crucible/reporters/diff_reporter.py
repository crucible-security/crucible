from __future__ import annotations

import html
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crucible.core.comparator import ScanDiff

_CSS = """
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 2rem;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  background: #0f172a;
  color: #e2e8f0;
  line-height: 1.55;
}
h1 { margin: 0 0 0.25rem; font-size: 2rem; }
.meta { color: #94a3b8; margin-bottom: 2rem; }
.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem;
  margin: 1.5rem 0 2rem;
}
.card {
  border: 1px solid #334155;
  background: #1e293b;
  border-radius: 0.8rem;
  padding: 1rem;
}
.card .label { color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; }
.card .value { font-size: 2rem; font-weight: 800; }
section { margin-top: 2rem; }
h2 { color: #f8fafc; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
table { width: 100%; border-collapse: collapse; background: #111827; border-radius: 0.75rem; overflow: hidden; }
th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #1f2937; vertical-align: top; }
th { background: #020617; color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
.badge { display: inline-block; border-radius: 999px; padding: 0.15rem 0.55rem; font-size: 0.75rem; font-weight: 700; }
.critical { background: #7f1d1d; color: #fecaca; }
.high { background: #7c2d12; color: #fed7aa; }
.medium { background: #713f12; color: #fef08a; }
.low { background: #1e3a8a; color: #bfdbfe; }
.info { background: #374151; color: #e5e7eb; }
.empty { color: #94a3b8; font-style: italic; }
"""


class DiffReporter:
    """Render Crucible scan diffs as standalone HTML."""

    def to_html(self, diff: ScanDiff) -> str:
        summary = diff.summary
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Crucible Scan Diff</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>Crucible Scan Diff</h1>
  <div class="meta">Target: {html.escape(diff.after.target.name)} · Before grade {html.escape(diff.before.grade.value)} / After grade {html.escape(diff.after.grade.value)}</div>
  <div class="summary">
    {self._summary_card("Fixed", summary["fixed"])}
    {self._summary_card("Still failing", summary["still_failing"])}
    {self._summary_card("New findings", summary["new_findings"])}
    {self._summary_card("Severity changes", summary["severity_changed"])}
  </div>
  {self._table("Fixed", [(item.finding.title, item.finding.severity.value, item.finding.description) for item in diff.fixed])}
  {self._table("Still failing", [(item.finding.title, item.finding.severity.value, item.finding.description) for item in diff.still_failing])}
  {self._table("New findings", [(item.finding.title, item.finding.severity.value, item.finding.description) for item in diff.new_findings])}
  {self._severity_changes(diff)}
</body>
</html>
"""

    def write(self, diff: ScanDiff, path: str | Path) -> Path:
        output = Path(path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_html(diff), encoding="utf-8")
        return output

    def _summary_card(self, label: str, value: int) -> str:
        return f'<div class="card"><div class="label">{html.escape(label)}</div><div class="value">{value}</div></div>'

    def _table(self, title: str, rows: list[tuple[str, str, str]]) -> str:
        if not rows:
            return f'<section><h2>{html.escape(title)}</h2><p class="empty">No findings.</p></section>'
        body = "\n".join(
            "<tr>"
            f"<td>{html.escape(name)}</td>"
            f'<td><span class="badge {html.escape(severity)}">{html.escape(severity.upper())}</span></td>'
            f"<td>{html.escape(description or '')}</td>"
            "</tr>"
            for name, severity, description in rows
        )
        return f"""<section>
  <h2>{html.escape(title)}</h2>
  <table>
    <thead><tr><th>Finding</th><th>Severity</th><th>Description</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
</section>"""

    def _severity_changes(self, diff: ScanDiff) -> str:
        if not diff.severity_changed:
            return '<section><h2>Severity changes</h2><p class="empty">No severity changes.</p></section>'
        rows = "\n".join(
            "<tr>"
            f"<td>{html.escape(change.after.title)}</td>"
            f'<td><span class="badge {html.escape(change.before.severity.value)}">{html.escape(change.before.severity.value.upper())}</span></td>'
            f'<td><span class="badge {html.escape(change.after.severity.value)}">{html.escape(change.after.severity.value.upper())}</span></td>'
            "</tr>"
            for change in diff.severity_changed
        )
        return f"""<section>
  <h2>Severity changes</h2>
  <table>
    <thead><tr><th>Finding</th><th>Before</th><th>After</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""
