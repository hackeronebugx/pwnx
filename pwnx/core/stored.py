"""POST form testing with persistence verification."""

import logging
from urllib.parse import urljoin
import httpx
from bs4 import BeautifulSoup
from pwnx.ai.selector import get_payloads
from pwnx.config import XSS_CANDIDATE_LIMIT

logger = logging.getLogger("pwnx.core")

async def test_stored_forms(client: httpx.AsyncClient, target: str, forms: list,
                            selector_mode: str, headless: bool = False) -> list:
    """Test POST forms for stored XSS."""
    results = []

    for form in forms:
        if form.get("method", "").upper() != "POST":
            continue

        result = {
            "type": "stored",
            "form_action": form.get("action"),
            "fields_tested": [],
            "success": False,
        }

        action = urljoin(target, form.get("action", ""))
        fields = form.get("fields", [])

        for field in fields:
            if field.get("type") in ["submit", "button", "hidden"]:
                continue

            field_name = field.get("name")
            if not field_name:
                continue

            # Send probe
            probe = "XSSSTOREDPROBE789"
            data = {f["name"]: probe for f in fields if f.get("name")}

            try:
                await client.post(action, data=data, timeout=15)

                # Check if probe appears on follow-up GET
                check_resp = await client.get(target, timeout=15)
                if probe in check_resp.text:
                    # Test payload
                    payloads = get_payloads("html_body", "plain", XSS_CANDIDATE_LIMIT)
                    for p, tag, event, action_type in payloads[:3]:
                        data[field_name] = p
                        await client.post(action, data=data, timeout=15)

                        verify_resp = await client.get(target, timeout=15)
                        if p in verify_resp.text:
                            result["fields_tested"].append({
                                "field": field_name,
                                "payload": p,
                                "confirmed": True,
                            })
                            result["success"] = True
                            break
            except Exception as e:
                logger.warning(f"Stored form test failed: {e}")

        results.append(result)

    return results
