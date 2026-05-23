# PwnX Architecture

## Module Map

```
pwnx/
├── __init__.py          # Version info
├── cli.py               # Rich-powered CLI entry point
├── config.py            # Environment-driven settings
├── core/
│   ├── engine.py        # Main orchestrator (8-phase workflow)
│   ├── reflected.py     # GET parameter testing + context detection
│   ├── stored.py        # POST form testing + persistence verification
│   └── dom.py           # DOM source→sink analysis
├── recon/
│   ├── params.py        # Multi-source parameter discovery
│   ├── waf.py           # WAF detection
│   ├── fingerprint.py   # Framework detection
│   └── csp.py           # CSP parsing
├── ai/
│   ├── reasoning.py     # LLM strategy (Groq/Ollama/heuristic)
│   ├── selector.py      # Legacy payload ranking
│   ├── xssgai_bridge.py # Transformer generation wrapper
│   └── xssgai_model.py  # PyTorch architecture stub
└── utils/
    ├── confirm.py       # Headless browser + heuristic confirmation
    ├── mutate.py        # Automatic payload mutation
    ├── checkpoint.py    # Crash-safe saving
    └── report.py        # HTML/JSON report generation
```

## Data Flow

```
Target URL → Recon → Discover Params → AI Reasoning → Generate Payloads
                                              ↓
JSON Report ← Checkpoint ← Confirm ← Execute ← Mutate (loop 3x)
```

## Extension Points

- Add new WAF: `recon/waf.py` → `detect_waf()`
- Add new framework: `recon/fingerprint.py` → `detect_frameworks()`
- Add new payload source: `ai/` → new module
- Add new confirmation method: `utils/confirm.py` → `confirm_xss()`
