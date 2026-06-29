# reporters/html_reporter.py
from dataclasses import asdict
from pathlib import Path
import json, html

HTML_TMPL = """<!doctype html>
<html><head><meta charset="utf-8"><title>GhostHunter Report</title>
<style>
body{{font-family:system-ui;background:#0e0e12;color:#cdd}} 
h1{{color:#00ffaa}}
table{{width:100%;border-collapse:collapse;margin-top:1em}}
th,td{{border:1px solid #2a2a3a;padding:8px;text-align:left;vertical-align:top}}
th{{background:#1a1a2a;color:#00ffaa}}
.critical{{background:#3a0000;color:#ff6b6b}}
.high{{background:#3a2a00;color:#ffd06b}}
.medium{{background:#00303a;color:#6be3ff}}
.low{{background:#1a2a1a;color:#a0ff9a}}
.info{{background:#222;color:#999}}
code{{white-space:pre-wrap;word-break:break-all}}
</style></head><body>
<h1>👻 GhostHunter Report</h1>
<p>Total findings: {count}</p>
<table>
<tr><th>Severity</th><th>Category</th><th>Title</th><th>Endpoint</th>
<th>Method</th><th>Payload</th><th>Evidence</th><th>Confidence</th><th>CWE</th></tr>
{rows}
</table></body></html>"""

class HTMLReporter:
    def dump(self, findings, path: Path):
        rows = []
        for f in findings:
            sev = f.severity.lower()
            rows.append(
                f"<tr class='{sev}'><td>{f.severity}</td><td>{f.category}</td>"
                f"<td>{html.escape(f.title)}</td><td><code>{html.escape(f.endpoint)}</code></td>"
                f"<td>{f.method}</td><td><code>{html.escape(str(f.payload or ''))[:200]}</code></td>"
                f"<td><code>{html.escape(f.evidence or '')[:500]}</code></td>"
                f"<td>{f.confidence:.2f}</td><td>{f.cwe}</td></tr>"
            )
        path.write_text(HTML_TMPL.format(count=len(findings), rows="".join(rows)))
