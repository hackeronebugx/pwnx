# Contributing to PwnX

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/pwnx.git
cd pwnx
pip install -e ".[dev]"
```

## Code Style

- Black formatter: `black pwnx/`
- Type hints: `mypy pwnx/`
- Tests: `pytest tests/`

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Reporting Bugs

Use GitHub Issues with:
- Target URL type (if shareable)
- Command used
- Expected vs actual output
- Python version (`python --version`)
