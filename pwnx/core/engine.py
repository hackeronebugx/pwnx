"""Main orchestrator (8-phase workflow)."""

import asyncio
import logging
import time
from datetime import datetime
from typing import Optional
import httpx
from pwnx.config import XSS_MAX_CONCURRENT, XSS_TIMEOUT, XSS_CHECKPOINT_DIR
from pwnx.recon.params import discover_params_concurrent, extract_script_urls, fetch_js_blobs
from pwnx.recon.waf import detect_waf
from pwnx.recon.fingerprint import detect_frameworks, detect_server
from pwnx.recon.csp import parse_csp
from pwnx.ai.reasoning import ai_reasoning_phase
from pwnx.ai.xssgai_bridge import XSSGAIBridge
from pwnx.core.reflected import test_param
from pwnx.core.stored import test_stored_forms
from pwnx.core.dom import test_dom_vectors
from pwnx.utils.checkpoint import save_checkpoint
from pwnx.utils.report import generate_report

logger = logging.getLogger("pwnx.engine")

async def hunt_xss(target: str, selector_mode: str = "heuristic",
                   use_xssgai: bool = False, headless: bool = False,
                   verbose: bool = False) -> dict:
    """Main XSS hunting orchestrator."""
    start_time = time.time()
    results = {
        "tool": "pwnx",
        "version": "2.0.0",
        "target": target,
        "scan_started": datetime.utcnow().isoformat() + "Z",
        "reconnaissance": {},
        "params_discovered": [],
        "param_discovery": {},
        "forms_discovered": [],
        "findings": [],
        "dom_vectors": [],
        "success": False,
        "selector_mode": selector_mode,
        "scan_types": ["reflected", "stored", "dom"],
    }

    # Create checkpoint dir
    import os
    os.makedirs(XSS_CHECKPOINT_DIR, exist_ok=True)

    async with httpx.AsyncClient(
        timeout=XSS_TIMEOUT,
        limits=httpx.Limits(max_connections=50),
        follow_redirects=True
    ) as client:

        # PHASE 1: Reconnaissance
        logger.info("🔍 Phase 1: Reconnaissance")
        try:
            resp = await client.get(target, timeout=15)
            html = resp.text
            headers = dict(resp.headers)

            waf = detect_waf(resp)
            frameworks = detect_frameworks(html)
            server = detect_server(headers)
            csp = parse_csp(headers, html)

            results["reconnaissance"] = {
                "waf": waf,
                "framework": frameworks[0] if frameworks else None,
                "csp_present": csp["present"],
                "csp_directives": csp["directives"],
                "tech_stack": frameworks + [server],
                "server": server,
            }

            logger.info(f"🛡️  WAF: {waf or 'None'}, Framework: {frameworks[0] if frameworks else 'None'}, CSP: {csp['present']}")
        except Exception as e:
            logger.warning(f"⚠️ Recon failed: {e}")
            results["reconnaissance"] = {"error": str(e)}

        # PHASE 2: Parameter Discovery
        logger.info("📡 Phase 2: Parameter Discovery")
        try:
            params, discovery = await discover_params_concurrent(client, target)
            results["params_discovered"] = params
            results["param_discovery"] = discovery

            # Also discover forms
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            soup = BeautifulSoup(html, "lxml")
            forms = []
            for form in soup.find_all("form"):
                form_info = {
                    "action": urljoin(target, form.get("action", "")),
                    "method": form.get("method", "get").lower(),
                    "fields": [],
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    field = {
                        "name": inp.get("name"),
                        "type": inp.get("type", "text"),
                    }
                    if field["name"]:
                        form_info["fields"].append(field)
                        # Add form fields as parameters too
                        if field["name"] not in params:
                            params.append(field["name"])
                            discovery[field["name"]] = ["html_form"]

                forms.append(form_info)

            results["forms_discovered"] = forms
            results["params_discovered"] = params  # Updated with form fields
            results["param_discovery"] = discovery

            logger.info(f"📋 Discovered {len(params)} parameters, {len(forms)} forms")
            for p in params:
                sources = discovery.get(p, ["unknown"])
                logger.info(f"   • '{p}' from: {', '.join(sources)}")
        except Exception as e:
            logger.warning(f"⚠️ Parameter discovery failed: {e}")

        # Fetch JS blobs
        script_urls = await extract_script_urls(client, target, html)
        js_blobs = await fetch_js_blobs(client, script_urls)

        # PHASE 3: AI Reasoning
        logger.info("🧠 Phase 3: AI Reasoning")
        strategies = {}
        if selector_mode in ["groq", "ollama"]:
            try:
                logger.info("🤖 Consulting AI for attack strategy...")
                strategies = await ai_reasoning_phase(html, js_blobs, params, results["reconnaissance"])

                # Display AI reasoning for each parameter
                for param, strategy in strategies.items():
                    logger.info(f"🎯 Parameter '{param}':")
                    logger.info(f"   Strategy: {strategy.get('strategy', 'direct_injection')}")
                    logger.info(f"   Confidence: {strategy.get('confidence', 0.5)}")
                    logger.info(f"   Reasoning: {strategy.get('reasoning', 'N/A')}")

                    if strategy.get("error"):
                        logger.warning(f"   ⚠️ AI Error: {strategy['error']}")
                        logger.info(f"   🔄 Falling back to heuristic strategy")

            except Exception as e:
                logger.warning(f"⚠️ AI reasoning failed: {e}")
                logger.info("🔄 Using heuristic fallback for all parameters")
        else:
            logger.info("📊 Using heuristic mode (no AI)")

        # Initialize XSSGAI
        xssgai = None
        if use_xssgai:
            xssgai = XSSGAIBridge()
            results["xssgai_status"] = "loaded" if xssgai.available else "unavailable"
            if xssgai.available:
                logger.info("✅ XSSGAI model loaded successfully")
            else:
                logger.warning("⚠️ XSSGAI not available, falling back to database")

        # PHASE 4-6: Test Reflected XSS
        logger.info("⚔️  Phase 4-6: Testing Reflected XSS")
        semaphore = asyncio.Semaphore(XSS_MAX_CONCURRENT)

        async def bounded_test(param):
            async with semaphore:
                strategy = strategies.get(param, {"strategy": "direct_injection", "confidence": 0.5})
                return await test_param(
                    client, target, param, selector_mode,
                    xssgai=xssgai,
                    target_analysis=results["reconnaissance"],
                    strategy=strategy,
                    headless=headless
                )

        if params:
            logger.info(f"🚀 Testing {len(params)} parameters...")
            param_results = await asyncio.gather(*[bounded_test(p) for p in params])
            results["findings"].extend(param_results)

        # PHASE 7: Test Stored XSS
        logger.info("💾 Phase 7: Testing Stored XSS")
        if results["forms_discovered"]:
            stored_results = await test_stored_forms(
                client, target, results["forms_discovered"],
                selector_mode, headless=headless
            )
            results["stored_forms_tested"] = len(stored_results)
            results["findings"].extend(stored_results)
        else:
            results["stored_forms_tested"] = 0

        # PHASE 8: Test DOM XSS
        logger.info("🌐 Phase 8: Testing DOM XSS")
        dom_vectors = await test_dom_vectors(client, target, html, js_blobs)
        results["dom_vectors"] = dom_vectors
        if dom_vectors:
            logger.info(f"⚠️  Found {len(dom_vectors)} potential DOM XSS vectors")
            for v in dom_vectors:
                logger.info(f"   • {v['source']} → {v['sink']}: {v['poc_url']}")

        # Finalize
        results["scan_duration_seconds"] = round(time.time() - start_time, 2)
        results["total_params_tested"] = len(params)
        results["vulnerable_params"] = sum(1 for f in results["findings"] if f.get("success"))
        results["success"] = results["vulnerable_params"] > 0

        results["summary"] = {
            "reflected": sum(1 for f in results["findings"] if f.get("type") == "reflected" and f.get("success")),
            "stored": sum(1 for f in results["findings"] if f.get("type") == "stored" and f.get("success")),
            "dom": len(dom_vectors),
            "total_confirmed": results["vulnerable_params"],
            "total_params_tested": len(params),
        }

        # Save checkpoint
        checkpoint_path = save_checkpoint(results, target)
        results["checkpoint_saved"] = checkpoint_path

        # Final summary
        logger.info("=" * 60)
        logger.info("📊 SCAN COMPLETE")
        logger.info(f"⏱️  Duration: {results['scan_duration_seconds']}s")
        logger.info(f"🎯 Parameters tested: {len(params)}")
        logger.info(f"🎉 Vulnerabilities found: {results['vulnerable_params']}")
        logger.info("=" * 60)

    return results
