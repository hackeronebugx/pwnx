"""Legacy payload ranking from SQLite database."""

import sqlite3
import logging
from typing import List, Tuple, Optional
from pwnx.config import XSS_PAYLOADS_DB

logger = logging.getLogger("pwnx.ai")

def get_payloads(context: str, encoding: str = "plain", limit: int = 10) -> List[Tuple]:
    """Fetch payloads from SQLite database."""
    try:
        conn = sqlite3.connect(XSS_PAYLOADS_DB)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT payload, tag, event, action FROM payloads WHERE context=? AND encoding=? LIMIT ?",
            (context, encoding, limit)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        logger.warning(f"Database error: {e}")
        return []

async def ai_select_payload(ctx: str, candidates: List[Tuple], target_info: str, mode: str = "heuristic") -> Optional[Tuple]:
    """Select best payload using AI or heuristic ranking."""
    if not candidates:
        return None

    if mode == "heuristic":
        # Simple heuristic: prefer img+onerror for html_body, input+onfocus for attributes
        if ctx == "html_body":
            for c in candidates:
                if c[1] == "img" and c[2] == "onerror":
                    return c
        elif ctx == "html_attribute":
            for c in candidates:
                if c[1] == "input" and c[2] == "onfocus":
                    return c
        return candidates[0]

    # For groq/ollama modes, just return first candidate (ranking done by reasoning layer)
    return candidates[0]
