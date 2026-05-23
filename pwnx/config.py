"""Environment-driven configuration."""

import os

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
XSSGAI_DIR = os.environ.get("XSSGAI_DIR", "")
XSS_PAYLOADS_DB = os.environ.get("XSS_PAYLOADS_DB", "xss_payloads.db")
XSS_CANDIDATE_LIMIT = int(os.environ.get("XSS_CANDIDATE_LIMIT", "10"))
XSS_MAX_CONCURRENT = int(os.environ.get("XSS_MAX_CONCURRENT", "5"))
XSS_TIMEOUT = int(os.environ.get("XSS_TIMEOUT", "20"))
XSS_HEADLESS = os.environ.get("XSS_HEADLESS", "false").lower() == "true"
XSS_CHECKPOINT_DIR = os.environ.get("XSS_CHECKPOINT_DIR", "checkpoints")
XSS_REPORT_DIR = os.environ.get("XSS_REPORT_DIR", "reports")
