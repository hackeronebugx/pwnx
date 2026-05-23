# Setup Guide

## Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install git python golang -y

# Clone and install
git clone https://github.com/YOUR_USERNAME/pwnx.git
cd pwnx
pip install -e .

# Optional tools
pip install arjun
go install github.com/projectdiscovery/katana/v2/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest

# Set environment variables
export XSS_MAX_CONCURRENT=3
export XSS_TIMEOUT=30
```

## VPS (Ubuntu/Debian)

```bash
# Update
apt update && apt upgrade -y

# Install Python and Go
apt install python3 python3-pip golang git -y

# Clone and install
git clone https://github.com/YOUR_USERNAME/pwnx.git
cd pwnx
pip3 install -e ".[all]"

# Install external tools
pip3 install arjun
go install github.com/projectdiscovery/katana/v2/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest

# Install Playwright
playwright install chromium

# Set API key
export GROQ_API_KEY="gsk_xxx"

# Run
pwnx --target "http://target.com" --selector groq --headless
```

## Troubleshooting

### "pwnx command not found"
```bash
# Reinstall
pip install -e .

# Or run directly
python -m pwnx.cli --target "http://target.com"
```

### "ModuleNotFoundError: No module named 'pwnx'"
```bash
# Ensure you're in the pwnx directory
cd /path/to/pwnx
pip install -e .
```

### Groq API 400 Error
```bash
# Check your API key
echo $GROQ_API_KEY

# Try a different model
# Edit pwnx/ai/reasoning.py and change model to "llama-3.1-8b-instant"
```
