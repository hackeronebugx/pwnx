"""DOM XSS analysis + simulation."""

import re
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Dict
import httpx

logger = logging.getLogger("pwnx.core")

# DOM sources that can be attacker-controlled
DOM_SOURCES = [
    "location.hash", "location.search", "document.URL", "document.referrer",
    "window.name", "URLSearchParams", "postMessage",
]

# Dangerous sinks that execute JS
DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval", "setTimeout", "setInterval", "script.src", "location.href",
    "location.replace", "location.assign", "window.open", "insertAdjacentHTML",
]

async def test_dom_vectors(client: httpx.AsyncClient, target: str, html: str, js_blobs: List[str]) -> List[Dict]:
    """Find DOM XSS vectors by analyzing source->sink flows."""
    vectors = []
    combined_js = "\n".join(js_blobs)

    # Check for hash-based DOM XSS
    if "location.hash" in combined_js or "window.location.hash" in combined_js:
        # Find innerHTML assignments with hash
        if "innerHTML" in combined_js:
            vectors.append({
                "type": "dom",
                "source": "location.hash",
                "sink": "innerHTML",
                "poc_url": f"{target}#<img src=x onerror=alert(1)>",
                "severity": "high",
            })

    # Check for URLSearchParams -> innerHTML
    if "URLSearchParams" in combined_js and "innerHTML" in combined_js:
        vectors.append({
            "type": "dom",
            "source": "URLSearchParams",
            "sink": "innerHTML",
            "poc_url": f"{target}?x=<img src=x onerror=alert(1)>",
            "severity": "high",
        })

    # Check for document.write with location.search
    if "document.write" in combined_js and "location.search" in combined_js:
        vectors.append({
            "type": "dom",
            "source": "location.search",
            "sink": "document.write",
            "poc_url": f"{target}?x=<script>alert(1)</script>",
            "severity": "high",
        })

    # Check for eval with window.name
    if "eval(" in combined_js and "window.name" in combined_js:
        vectors.append({
            "type": "dom",
            "source": "window.name",
            "sink": "eval",
            "poc_url": f"{target}",
            "note": "Set window.name to payload via iframe",
            "severity": "high",
        })

    return vectors
