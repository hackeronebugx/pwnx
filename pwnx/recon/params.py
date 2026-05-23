"""Multi-source parameter discovery."""

import asyncio
import re
import subprocess
import logging
from typing import List, Dict, Tuple
from urllib.parse import urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("pwnx.recon")

async def discover_params_concurrent(client: httpx.AsyncClient, target: str, manual_params: List[str] = None) -> Tuple[List[str], Dict]:
    """Discover parameters from multiple sources concurrently."""
    discovery = {}

    # Start all discovery tasks
    tasks = [
        _discover_from_url(target),
        _discover_from_html(client, target),
        _discover_from_arjun(target),
        _discover_from_katana(target),
        _discover_from_gau(target),
        _discover_from_hakrawler(target),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_params = set(manual_params or [])

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.warning(f"Discovery task {i} failed: {result}")
            continue
        for param, sources in result.items():
            if param not in discovery:
                discovery[param] = []
            discovery[param].extend(sources)
            all_params.add(param)

    return sorted(list(all_params)), discovery

async def _discover_from_url(target: str) -> Dict[str, List[str]]:
    """Extract parameters from URL query string."""
    parsed = urlparse(target)
    params = parse_qs(parsed.query)
    return {k: ["target_url"] for k in params.keys()}

async def _discover_from_html(client: httpx.AsyncClient, target: str) -> Dict[str, List[str]]:
    """Parse HTML for forms and inputs."""
    try:
        resp = await client.get(target, timeout=15)
        html = resp.text
        soup = BeautifulSoup(html, "lxml")

        found = {}

        # Find all forms and their inputs
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    found[name] = found.get(name, []) + ["html_form"]

        # Find all input tags anywhere (not just in forms)
        for inp in soup.find_all("input"):
            name = inp.get("name")
            if name:
                found[name] = found.get(name, []) + ["html_input"]

        # Find links with query parameters
        for link in soup.find_all("a", href=True):
            parsed = urlparse(link["href"])
            if parsed.query:
                for k in parse_qs(parsed.query):
                    found[k] = found.get(k, []) + ["html_link"]

        return found
    except Exception as e:
        logger.warning(f"HTML parsing failed: {e}")
        return {}

async def _discover_from_arjun(target: str) -> Dict[str, List[str]]:
    """Run Arjun for parameter brute-forcing."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "arjun", "-u", target, "-m", "GET", "-oT", "/dev/stdout",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode()

        found = {}
        for line in output.split("\n"):
            if line.strip() and not line.startswith("["):
                param = line.strip().split(":")[0].strip()
                if param:
                    found[param] = ["arjun"]
        return found
    except Exception as e:
        logger.warning(f"Arjun failed: {e}")
        return {}

async def _discover_from_katana(target: str) -> Dict[str, List[str]]:
    """Crawl with katana."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "katana", "-u", target, "-silent", "-f", "qurl",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

        found = {}
        for line in stdout.decode().split("\n"):
            if "?" in line:
                parsed = urlparse(line.strip())
                for k in parse_qs(parsed.query):
                    found[k] = found.get(k, []) + ["katana"]
        return found
    except Exception as e:
        logger.warning(f"Katana failed: {e}")
        return {}

async def _discover_from_gau(target: str) -> Dict[str, List[str]]:
    """Get URLs from Wayback/CommonCrawl."""
    try:
        parsed = urlparse(target)
        domain = parsed.netloc

        proc = await asyncio.create_subprocess_exec(
            "gau", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

        found = {}
        for line in stdout.decode().split("\n"):
            if "?" in line:
                parsed = urlparse(line.strip())
                for k in parse_qs(parsed.query):
                    found[k] = found.get(k, []) + ["gau"]
        return found
    except Exception as e:
        logger.warning(f"Gau failed: {e}")
        return {}

async def _discover_from_hakrawler(target: str) -> Dict[str, List[str]]:
    """Crawl with hakrawler."""
    try:
        parsed = urlparse(target)
        domain = parsed.netloc

        proc = await asyncio.create_subprocess_exec(
            "hakrawler", "-url", domain, "-plain",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

        found = {}
        for line in stdout.decode().split("\n"):
            if "?" in line:
                parsed = urlparse(line.strip())
                for k in parse_qs(parsed.query):
                    found[k] = found.get(k, []) + ["hakrawler"]
        return found
    except Exception as e:
        logger.warning(f"Hakrawler failed: {e}")
        return {}

async def extract_script_urls(client: httpx.AsyncClient, target: str, html: str) -> List[str]:
    """Extract and fetch external script URLs."""
    soup = BeautifulSoup(html, "lxml")
    scripts = []

    for script in soup.find_all("script", src=True):
        src = script["src"]
        if src.startswith("http"):
            scripts.append(src)
        elif src.startswith("//"):
            scripts.append("https:" + src)
        else:
            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"
            scripts.append(base + (src if src.startswith("/") else "/" + src))

    return scripts

async def fetch_js_blobs(client: httpx.AsyncClient, script_urls: List[str]) -> List[str]:
    """Fetch external JavaScript files."""
    blobs = []
    for url in script_urls[:10]:  # Limit to 10 scripts
        try:
            resp = await client.get(url, timeout=10)
            blobs.append(resp.text)
        except Exception as e:
            logger.warning(f"Failed to fetch JS {url}: {e}")
    return blobs
