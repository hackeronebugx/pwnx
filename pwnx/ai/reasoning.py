"""LLM strategy selection (Groq / Ollama / heuristic fallback)."""

import json
import logging
import httpx
from typing import Dict, Optional
from pwnx.config import GROQ_API_KEY, OLLAMA_HOST

logger = logging.getLogger("pwnx.ai")

async def ai_reasoning_phase(html: str, js_blobs: list, params: list, target_analysis: dict) -> Dict[str, dict]:
    """Use LLM to decide strategy per parameter."""
    strategies = {}

    for param in params:
        prompt = f"""Analyze this web target for XSS vulnerability strategy.

Target Info:
- Parameter: {param}
- Framework: {target_analysis.get('framework', 'unknown')}
- WAF: {target_analysis.get('waf', 'none')}
- CSP: {'yes' if target_analysis.get('csp', {}).get('present') else 'no'}
- Tech Stack: {', '.join(target_analysis.get('tech_stack', []))}

HTML snippet (first 2000 chars):
{html[:2000]}

Based on this, what is the best XSS strategy for parameter '{param}'?
Respond ONLY with a JSON object in this exact format:
{{"strategy": "direct_injection|encoding_bypass|dom_clobbering|skip", "confidence": 0.0-1.0, "reasoning": "brief explanation"}}
"""

        if GROQ_API_KEY:
            result = await reason_with_groq(prompt)
        else:
            result = await reason_with_heuristic(param, target_analysis)

        strategies[param] = result

    return strategies

async def reason_with_groq(prompt: str, model: str = "llama-3.3-70b-versatile") -> dict:
    """Call Groq API for reasoning."""
    if not GROQ_API_KEY:
        return {"error": "GROQ_API_KEY not set", "strategy": "direct_injection", "confidence": 0.5}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                    "max_tokens": 500,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            # Try to extract JSON from response
            try:
                # Find JSON block
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0].strip()
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0].strip()

                return json.loads(content)
            except (json.JSONDecodeError, IndexError):
                # Fallback: parse manually
                strategy = "direct_injection"
                confidence = 0.5
                if "encoding" in content.lower() or "bypass" in content.lower():
                    strategy = "encoding_bypass"
                elif "skip" in content.lower():
                    strategy = "skip"

                return {
                    "strategy": strategy,
                    "confidence": confidence,
                    "reasoning": content[:200],
                    "raw_response": content[:500]
                }
    except Exception as e:
        logger.warning(f"Groq API error: {e}")
        return {"error": str(e), "strategy": "direct_injection", "confidence": 0.5}

async def reason_with_ollama(prompt: str, model: str = "llama3") -> dict:
    """Call local Ollama server."""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            data = resp.json()
            content = data.get("response", "")

            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"strategy": "direct_injection", "confidence": 0.5, "reasoning": content[:200]}
    except Exception as e:
        logger.warning(f"Ollama error: {e}")
        return {"error": str(e), "strategy": "direct_injection", "confidence": 0.5}

async def reason_with_heuristic(param: str, target_analysis: dict) -> dict:
    """Fallback heuristic reasoning."""
    waf = target_analysis.get("waf")
    framework = target_analysis.get("framework")
    csp = target_analysis.get("csp", {}).get("present", False)

    if framework in ["react", "angular", "vue"]:
        return {"strategy": "dom_clobbering", "confidence": 0.6, "reasoning": f"Framework {framework} auto-escapes HTML"}
    if waf:
        return {"strategy": "encoding_bypass", "confidence": 0.7, "reasoning": f"WAF detected: {waf}"}
    if csp:
        return {"strategy": "encoding_bypass", "confidence": 0.6, "reasoning": "CSP present, need bypass"}

    return {"strategy": "direct_injection", "confidence": 0.8, "reasoning": "No defenses detected"}
