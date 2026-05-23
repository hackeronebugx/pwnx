"""GET parameter testing with context detection + mutation."""

import asyncio
import logging
from urllib.parse import quote, urlparse, parse_qs, urlencode
import httpx
from pwnx.ai.selector import get_payloads, ai_select_payload
from pwnx.ai.xssgai_bridge import XSSGAIBridge
from pwnx.utils.mutate import analyze_failure, mutate_payload
from pwnx.utils.confirm import confirm_xss
from pwnx.config import XSS_CANDIDATE_LIMIT

logger = logging.getLogger("pwnx.core")

async def test_param(client: httpx.AsyncClient, target: str, param: str, selector_mode: str,
                     xssgai: XSSGAIBridge = None, target_analysis: dict = None,
                     strategy: dict = None, headless: bool = False) -> dict:
    """Test a single GET parameter for reflected XSS."""
    result = {
        "type": "reflected",
        "param": param,
        "findings": [],
        "payloads_tested": 0,
        "success": False,
        "context_detected": None,
        "payload_selector": None,
        "strategy": strategy or {"strategy": "direct_injection", "confidence": 0.5},
        "discovery_sources": [],
    }

    # Log AI reasoning
    if strategy:
        logger.info(f"🧠 AI Reasoning for '{param}': {strategy.get('strategy', 'direct_injection')} (confidence: {strategy.get('confidence', 0.5)})")
        logger.info(f"📝 Reasoning: {strategy.get('reasoning', 'No reasoning provided')}")

    # Build probe URL
    parsed = urlparse(target)
    base_params = parse_qs(parsed.query)

    # Send probe
    probe = "XSSPROBE123"
    probe_params = base_params.copy()
    probe_params[param] = [probe]
    probe_query = urlencode(probe_params, doseq=True)
    probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{probe_query}"

    try:
        resp = await client.get(probe_url, timeout=15, follow_redirects=True)
        html = resp.text

        if probe not in html:
            logger.info(f"❌ Parameter '{param}' not reflected in response")
            return result

        logger.info(f"✅ Parameter '{param}' is reflected! Analyzing context...")

        # Detect context
        ctx = analyze_context(html, probe)
        result["context_detected"] = ctx
        logger.info(f"🔍 Context detected: {ctx}")

        # Generate payloads
        candidates = []
        payload_source = "database_fallback"

        if xssgai and xssgai.available:
            logger.info("🤖 Generating payloads with XSSGAI Transformer...")
            generated = xssgai.generate_for_context(ctx, count=5)
            if generated:
                candidates = [(p, "ai", "generated", "alert") for p in generated]
                payload_source = "xssgai_generated"
                logger.info(f"✨ Generated {len(generated)} novel payloads")
                for i, p in enumerate(generated, 1):
                    logger.info(f"   [{i}] {p[:60]}...")

        if not candidates and selector_mode in ["groq", "ollama"]:
            logger.info("📡 Fetching payloads from database...")
            candidates = get_payloads(ctx, "plain", XSS_CANDIDATE_LIMIT)
            if candidates:
                payload_source = "database"

        if not candidates:
            candidates = get_payloads(ctx, "plain", XSS_CANDIDATE_LIMIT)
            payload_source = "database"

        if not candidates:
            logger.warning(f"⚠️ No payloads available for context '{ctx}'")
            return result

        result["payload_selector"] = payload_source

        # Test payloads
        for payload_tuple in candidates[:XSS_CANDIDATE_LIMIT]:
            result["payloads_tested"] += 1

            if isinstance(payload_tuple, tuple):
                payload, tag, event, action = payload_tuple
            else:
                payload = payload_tuple
                tag, event, action = "img", "onerror", "alert"

            logger.info(f"🚀 Testing payload: {payload[:50]}...")

            # Build test URL with RAW payload (not URL-encoded for PoC)
            test_params = base_params.copy()
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

            # poc_payload is the raw payload for display
            poc_payload = payload

            try:
                test_resp = await client.get(test_url, timeout=15, follow_redirects=True)
                test_html = test_resp.text

                # Confirm XSS
                confirmed = await confirm_xss(test_html, payload, ctx, headless=headless, poc_url=test_url)

                if confirmed:
                    logger.info(f"🎉 XSS CONFIRMED on '{param}'!")
                    logger.info(f"💉 Payload: {payload}")
                    logger.info(f"🔗 PoC URL: {test_url}")

                    result["findings"].append({
                        "payload": payload,
                        "context": ctx,
                        "tag": tag,
                        "event": event,
                        "action": action,
                        "confirmed": True,
                        "confirmation": "headless" if headless else "heuristic",
                        "severity": "high",
                        "selected_by": payload_source,
                        "poc_url": test_url,  # RAW payload in URL for browser execution
                    })
                    result["success"] = True
                    break
                else:
                    logger.info(f"❌ Payload did not execute. Analyzing failure...")
                    # Try mutation
                    feedback = analyze_failure(test_html, payload, ctx)
                    if feedback["suggestion"] != "retry":
                        mutated = mutate_payload(payload, feedback, ctx)
                        if mutated != payload:
                            logger.info(f"🔄 Mutating payload: {mutated[:50]}...")
                            test_params[param] = [mutated]
                            test_query = urlencode(test_params, doseq=True)
                            mutated_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                            mutated_resp = await client.get(mutated_url, timeout=15, follow_redirects=True)
                            mutated_confirmed = await confirm_xss(mutated_resp.text, mutated, ctx, headless=headless, poc_url=mutated_url)

                            if mutated_confirmed:
                                logger.info(f"🎉 XSS CONFIRMED with mutated payload!")
                                logger.info(f"💉 Mutated: {mutated}")
                                logger.info(f"🔗 PoC URL: {mutated_url}")

                                result["findings"].append({
                                    "payload": mutated,
                                    "context": ctx,
                                    "tag": tag,
                                    "event": event,
                                    "action": action,
                                    "confirmed": True,
                                    "confirmation": "headless" if headless else "heuristic",
                                    "severity": "high",
                                    "selected_by": f"{payload_source}_mutated",
                                    "poc_url": mutated_url,
                                    "mutation_reason": feedback["suggestion"],
                                })
                                result["success"] = True
                                break

            except Exception as e:
                logger.warning(f"⚠️ Payload test failed for {param}: {e}")
                continue

    except Exception as e:
        logger.warning(f"⚠️ Probe failed for {param}: {e}")

    return result

def analyze_context(html: str, probe: str) -> str:
    """Determine injection context."""
    idx = html.find(probe)
    if idx == -1:
        return "unknown"

    # Check surrounding context
    before = html[max(0, idx-50):idx]
    after = html[idx:idx+50]

    # Script context
    if "<script" in before.lower() and "</script>" in after.lower():
        return "script_context"

    # HTML attribute
    if "=" in before and (before.rfind(""") > before.rfind("<") or before.rfind("'") > before.rfind("<")):
        return "html_attribute"

    # URL context
    if "href=" in before.lower() or "src=" in before.lower():
        return "url_context"

    # Default: HTML body
    return "html_body"
