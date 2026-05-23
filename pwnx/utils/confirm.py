"""Headless browser + heuristic confirmation."""

import logging
from typing import Optional

logger = logging.getLogger("pwnx.utils")

async def confirm_xss(html: str, payload: str, context: str, headless: bool = False, poc_url: str = "") -> bool:
    """Confirm XSS execution."""
    if headless:
        return await confirm_with_browser(poc_url, payload)
    else:
        return confirm_heuristic(html, payload, context)

def confirm_heuristic(html: str, payload: str, context: str) -> bool:
    """Heuristic confirmation without browser."""
    import html as html_module

    # Decode HTML entities
    decoded = html_module.unescape(html)

    # Check if payload exists in decoded form (not as entities)
    if payload not in decoded:
        return False

    # Check for event handlers
    event_handlers = ["onerror=", "onload=", "onmouseover=", "onfocus=", "onclick="]
    has_event = any(e in decoded for e in event_handlers)

    # Check for script tags
    has_script = "<script>" in decoded and "</script>" in decoded

    # Check for javascript: protocol
    has_js_proto = "javascript:" in decoded.lower()

    return has_event or has_script or has_js_proto

async def confirm_with_browser(poc_url: str, payload: str) -> bool:
    """Confirm XSS using Playwright headless browser."""
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            dialog_triggered = False

            async def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)
            await page.goto(poc_url)
            await page.wait_for_timeout(2000)
            await browser.close()

            return dialog_triggered
    except ImportError:
        logger.warning("Playwright not installed. Falling back to heuristic.")
        return False
    except Exception as e:
        logger.warning(f"Headless browser failed: {e}")
        return False
