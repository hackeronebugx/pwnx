"""XSSGAI Transformer payload generation wrapper."""

import json
import logging
import re
from pathlib import Path
from typing import List
from pwnx.config import XSSGAI_DIR

logger = logging.getLogger("pwnx.ai")

class XSSGAIBridge:
    """Bridge to XSSGAI model for novel payload generation."""

    def __init__(self):
        self.available = False
        self.model = None
        self.vocab = None
        self.device = None

        if XSSGAI_DIR and Path(XSSGAI_DIR).exists():
            try:
                import torch
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                vocab_path = Path(XSSGAI_DIR) / "vocab.json"
                model_path = Path(XSSGAI_DIR) / "xss_transformer_v2.pth"

                if vocab_path.exists() and model_path.exists():
                    with open(vocab_path) as f:
                        self.vocab = json.load(f)
                    self.model = self._load_model(model_path)
                    self.available = True
                    logger.info("XSSGAI model loaded successfully")
            except ImportError:
                logger.warning("PyTorch not installed. XSSGAI disabled.")
            except Exception as e:
                logger.warning(f"XSSGAI load failed: {e}")

    def _load_model(self, path):
        """Load PyTorch model."""
        import torch
        import torch.nn as nn

        class XSSTransformer(nn.Module):
            def __init__(self, vocab_size, d_model=256, nhead=8, num_layers=6):
                super().__init__()
                self.embedding = nn.Embedding(vocab_size, d_model)
                self.pos_encoder = nn.Parameter(torch.randn(1, 384, d_model))
                encoder_layer = nn.TransformerEncoderLayer(
                    d_model=d_model, nhead=nhead,
                    dim_feedforward=1024, batch_first=True
                )
                self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
                self.decoder = nn.Linear(d_model, vocab_size)

            def forward(self, x):
                x = self.embedding(x) + self.pos_encoder[:, :x.size(1)]
                out = self.transformer(x)
                return self.decoder(out)

        model = XSSTransformer(len(self.vocab))
        model.load_state_dict(torch.load(path, map_location=self.device))
        model.eval()
        return model.to(self.device)

    def generate(self, instruct: str, temperature: float = 0.8, top_p: float = 0.9, max_len: int = 384) -> str:
        """Generate payload from instruction."""
        import torch

        seed = [self.vocab.get(c, self.vocab.get("<unk>", 0)) for c in instruct]
        generated = seed.copy()

        for _ in range(max_len - len(seed)):
            input_ids = torch.tensor([generated]).to(self.device)
            with torch.no_grad():
                logits = self.model(input_ids)[:, -1, :]

            logits = logits / temperature
            probs = torch.softmax(logits, dim=-1)

            sorted_probs, sorted_indices = torch.sort(probs, descending=True)
            cumsum = torch.cumsum(sorted_probs, dim=-1)
            mask = cumsum <= top_p
            mask[0, 0] = True
            filtered_probs = sorted_probs * mask
            filtered_probs = filtered_probs / filtered_probs.sum()

            next_token = sorted_indices[0, torch.multinomial(filtered_probs, 1)].item()
            generated.append(next_token)

            if self.vocab.get(str(next_token)) == "[END]":
                break

        idx2char = {v: k for k, v in self.vocab.items()}
        return "".join([idx2char.get(i, "") for i in generated])

    def build_instruct(self, context: str, action: str = "ALERT", style: str = "PLAIN") -> str:
        """Map context to XSSGAI instruction format."""
        context_map = {
            "html_body": {"tag": "IMG", "event": "ONERROR"},
            "html_attribute": {"tag": "INPUT", "event": "ONFOCUS"},
            "script_context": {"tag": "SCRIPT", "event": "NONE"},
            "url_context": {"tag": "A", "event": "ONCLICK"},
        }
        ctx = context_map.get(context, {"tag": "IMG", "event": "ONERROR"})
        return f"[INSTRUCT] ACT:{action} TAG:{ctx['tag']} EV:{ctx['event']} STY:{style} [PAYLOAD]\n"

    def generate_for_context(self, context: str, count: int = 5, temperature: float = 0.8) -> List[str]:
        """Generate multiple payloads for a context."""
        if not self.available:
            return []

        instruct = self.build_instruct(context)
        payloads = []

        for _ in range(count):
            raw = self.generate(instruct, temperature=temperature)
            match = re.search(r'[PAYLOAD]\s*(.*?)(?:[END]|<end>|[MEMORIZED]|[NOVEL])', raw, re.DOTALL)
            if match:
                payload = match.group(1).strip()
                if payload and payload not in payloads:
                    payloads.append(payload)

        return payloads
