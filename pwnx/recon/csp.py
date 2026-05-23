"""CSP header and meta tag parsing."""

import re
from typing import List, Dict, Optional

def parse_csp(response_headers: dict, html: str) -> Dict:
    """Parse Content-Security-Policy."""
    result = {
        "present": False,
        "directives": [],
        "script_src": None,
        "unsafe_inline": False,
        "unsafe_eval": False,
    }

    # Check headers
    csp_header = response_headers.get("content-security-policy", "")
    if not csp_header:
        csp_header = response_headers.get("content-security-policy-report-only", "")

    # Check meta tags
    if not csp_header:
        match = re.search(r'<meta[^>]+http-equiv="Content-Security-Policy"[^>]+content="([^"]+)"', html, re.I)
        if match:
            csp_header = match.group(1)

    if csp_header:
        result["present"] = True
        directives = csp_header.split(";")
        for d in directives:
            d = d.strip()
            if d:
                result["directives"].append(d)
                if d.startswith("script-src"):
                    result["script_src"] = d
                    if "'unsafe-inline'" in d:
                        result["unsafe_inline"] = True
                    if "'unsafe-eval'" in d:
                        result["unsafe_eval"] = True

    return result
