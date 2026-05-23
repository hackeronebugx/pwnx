# 🎯 PwnX v2.0.0

**AI-Augmented XSS Hunter** — Context-aware, dynamically generating, WAF-adaptive cross-site scripting scanner.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ⚡ Quick Start

```bash
# Install
git clone https://github.com/YOUR_USERNAME/pwnx.git
cd pwnx
pip install -e .

# Basic scan (offline, fast)
pwnx --target "http://testphp.vulnweb.com/search.php?test=query"

# Full scan with AI + headless browser
export GROQ_API_KEY="gsk_xxx"
pwnx --target "http://target.com" --selector groq --xssgai --headless
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ PHASE 1: RECONNAISSANCE                                     │
│ • WAF detection (Cloudflare, Akamai, Incapsula, etc.)      │
│ • Framework fingerprint (React, Angular, Vue, jQuery)      │
│ • CSP header + meta tag parsing                            │
│ • Server technology identification                         │
├─────────────────────────────────────────────────────────────┤
│ PHASE 2: PARAMETER DISCOVERY (Concurrent)                   │
│ • Arjun + katana + gau + hakrawler (parallel)              │
│ • HTML form/input parsing                                  │
│ • JavaScript dynamic parameter extraction                  │
├─────────────────────────────────────────────────────────────┤
│ PHASE 3: AI REASONING                                       │
│ • Groq / Ollama LLM strategy selection                     │
│ • Per-parameter strategy: direct / encoding / DOM          │
├─────────────────────────────────────────────────────────────┤
│ PHASE 4: PAYLOAD GENERATION                                 │
│ 1. XSSGAI Transformer → novel payloads                     │
│ 2. LLM custom payload → context-specific                   │
│ 3. SQLite database → offline fallback                      │
├─────────────────────────────────────────────────────────────┤
│ PHASE 5-6: EXECUTION & CONFIRMATION                         │
│ • Playwright headless browser (zero false positives)       │
│ • Heuristic fallback (fast, no dependencies)               │
├─────────────────────────────────────────────────────────────┤
│ PHASE 7: MUTATION & RETRY                                   │
│ • Automatic encoding cascade                               │
│ • Alternative tags/events on filter detection              │
│ • Up to 3 retries per parameter                            │
├─────────────────────────────────────────────────────────────┤
│ PHASE 8: REPORTING                                          │
│ • JSON / HTML / SARIF output                               │
│ • Incremental checkpointing (crash-safe)                   │
│ • PoC URLs with raw payloads (not URL-encoded)             │
└─────────────────────────────────────────────────────────────┘
```

## 📋 Requirements

### Minimum (Works Immediately)
- Python 3.10+
- `pip install -e .`

### Full Features
| Feature | Requirement | Install |
|---------|------------|---------|
| Parameter discovery | arjun, katana, gau, hakrawler | `pip install arjun` + `go install ...` |
| AI reasoning | Groq API key or Ollama | [Get Groq key](https://console.groq.com) |
| Novel payloads | XSSGAI + PyTorch | `git clone https://github.com/AnonKryptiQuz/XSSGAI.git` |
| Headless confirmation | Playwright | `pip install playwright && playwright install chromium` |

## 🔧 Environment Variables

| Variable | Required? | Purpose |
|----------|-----------|---------|
| `GROQ_API_KEY` | No | Groq LLM reasoning |
| `OLLAMA_HOST` | No | Local Ollama server URL |
| `XSSGAI_DIR` | No | Path to XSSGAI repo with model weights |
| `XSS_CANDIDATE_LIMIT` | No | Max payloads per parameter (default: 10) |
| `XSS_MAX_CONCURRENT` | No | Parallel requests (default: 5) |
| `XSS_TIMEOUT` | No | Request timeout seconds (default: 20) |
| `XSS_HEADLESS` | No | Enable headless by default (true/false) |

## 🛡️ Ethical Use

**PwnX is for authorized security testing only.** Always obtain permission before scanning targets you do not own.

## 📄 License

MIT License — see [LICENSE](LICENSE)
