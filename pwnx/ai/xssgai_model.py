"""PyTorch model architecture stub for XSSGAI."""

import torch.nn as nn

class XSSTransformer(nn.Module):
    """6-layer Transformer for XSS payload generation."""

    def __init__(self, vocab_size: int, d_model: int = 256, nhead: int = 8, num_layers: int = 6):
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
