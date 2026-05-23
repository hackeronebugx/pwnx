"""HTML/JSON report generation."""

import json
import os
from datetime import datetime
from pwnx.config import XSS_REPORT_DIR

def generate_report(results: dict, format: str = "json") -> str:
    """Generate scan report."""
    os.makedirs(XSS_REPORT_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if format == "json":
        filepath = os.path.join(XSS_REPORT_DIR, f"report_{timestamp}.json")
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
        return filepath

    elif format == "html":
        filepath = os.path.join(XSS_REPORT_DIR, f"report_{timestamp}.html")
        html = _generate_html(results)
        with open(filepath, "w") as f:
            f.write(html)
        return filepath

    return ""

def _generate_html(results: dict) -> str:
    """Generate HTML report."""
    findings = results.get("findings", [])
    confirmed = [f for f in findings if f.get("success")]

    html = f"""<!DOCTYPE html>
<html>
<head><title>PwnX Report - {results.get("target", "")}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
h1 {{ color: #e94560; }}
.finding {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 5px; }}
.poc {{ background: #0f3460; padding: 10px; border-radius: 3px; word-break: break-all; }}
.success {{ color: #4ecca3; }}
.fail {{ color: #e94560; }}
</style>
</head>
<body>
<h1>🎯 PwnX Scan Report</h1>
<p><strong>Target:</strong> {results.get("target", "N/A")}</p>
<p><strong>Duration:</strong> {results.get("scan_duration_seconds", 0)}s</p>
<p><strong>Confirmed:</strong> <span class="success">{len(confirmed)}</span></p>

<h2>Findings</h2>
"""

    for finding in confirmed:
        for f in finding.get("findings", []):
            html += f"""
<div class="finding">
    <h3 class="success">✓ {finding.get("param", "N/A")} - {f.get("context", "N/A")}</h3>
    <p><strong>Payload:</strong> <code>{f.get("payload", "N/A")}</code></p>
    <p><strong>PoC URL:</strong></p>
    <div class="poc">{f.get("poc_url", "N/A")}</div>
</div>
"""

    html += "</body></html>"
    return html
