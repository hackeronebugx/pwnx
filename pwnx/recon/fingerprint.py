"""Framework and technology fingerprinting."""

import re
from typing import List, Dict

def detect_frameworks(html: str) -> List[str]:
    """Detect web frameworks from HTML."""
    frameworks = []
    html_lower = html.lower()

    if any(x in html for x in ["reactroot", "data-reactid", "__REACT__"]):
        frameworks.append("react")
    if any(x in html for x in ["ng-app", "ng-controller", "data-ng-", "ng-"]):
        frameworks.append("angular")
    if any(x in html for x in ["v-if", "v-for", "data-v-", "vue-"]):
        frameworks.append("vue")
    if "jquery" in html_lower:
        frameworks.append("jquery")
    if "dompurify" in html_lower or "purify.min.js" in html_lower:
        frameworks.append("dompurify")
    if "bootstrap" in html_lower:
        frameworks.append("bootstrap")

    return frameworks

def detect_server(response_headers: dict) -> str:
    """Detect server technology from headers."""
    server = response_headers.get("server", "").lower()
    powered = response_headers.get("x-powered-by", "").lower()

    if "apache" in server:
        return "apache"
    elif "nginx" in server:
        return "nginx"
    elif "cloudflare" in server:
        return "cloudflare"
    elif "php" in powered:
        return "php"
    elif "express" in powered:
        return "express"

    return "unknown"
