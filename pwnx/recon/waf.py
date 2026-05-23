"""WAF detection."""

import httpx
from typing import Optional

def detect_waf(response: httpx.Response) -> Optional[str]:
    """Detect WAF from response headers and body."""
    headers = response.headers
    body = response.text.lower()

    # Cloudflare
    if "cf-ray" in headers or "__cfduid" in str(headers):
        return "cloudflare"
    if "cloudflare" in body:
        return "cloudflare"

    # Akamai
    if "akamai" in str(headers).lower():
        return "akamai"

    # Incapsula
    if "x-iinfo" in headers or "incap_ses" in str(headers):
        return "incapsula"

    # Sucuri
    if "sucuri" in body or "x-sucuri" in str(headers).lower():
        return "sucuri"

    # AWS WAF
    if "aws-waf" in str(headers).lower():
        return "aws_waf"

    # ModSecurity
    if "mod_security" in body or "modsecurity" in body:
        return "modsecurity"

    # Generic 403 with security message
    if response.status_code == 403 and any(x in body for x in ["blocked", "forbidden", "security"]):
        return "generic_waf"

    return None
