"""Crash-safe incremental saving."""

import json
import os
from datetime import datetime
from pwnx.config import XSS_CHECKPOINT_DIR

def save_checkpoint(results: dict, target: str) -> str:
    """Save incremental checkpoint."""
    import re
    safe_target = re.sub(r"[^\w\.]", "_", target.replace("://", "___"))
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"pwnx_{safe_target}_{timestamp}.json"
    filepath = os.path.join(XSS_CHECKPOINT_DIR, filename)

    os.makedirs(XSS_CHECKPOINT_DIR, exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)

    return filepath
