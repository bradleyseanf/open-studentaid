# sessions.py
"""
Token storage and session-cache utilities for open_studentaid.

Handles secure, atomic read/write of access/refresh tokens on disk.
Tokens are stored under ~/.studentaid by default (or STUDENTAID_HOME if set).

Each provider has its own JSON file:
    ~/.studentaid/tokens_<provider>.json

Schema (typical)
----------------
{
  "access_token": "<JWT>",
  "refresh_token": "<JWT>",
  "expires_in": 900,
  "scope": "openid offline_access ...",
  "token_type": "Bearer",
  "obtained_at": 1739999999
}
"""

from __future__ import annotations
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional, Dict, Any

# Base directory for token cache
APP_DIR = Path(os.getenv("STUDENTAID_HOME", Path.home() / ".studentaid"))

# Refresh a minute early to avoid edge-case 401s
SKEW_SEC = 60


# ---------------------------- internal helpers ---------------------------- #

def token_path(provider: str) -> Path:
    """Return full path to the token cache file for a provider."""
    return APP_DIR / f"tokens_{provider}.json"


def _atomic_write_json(path: Path, data: dict) -> None:
    """
    Write JSON to disk atomically.
    Uses a temp file + os.replace for crash-safe writes.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        json.dump(data, tmp, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, path)


# ----------------------------- public helpers ----------------------------- #

def load_tokens(provider: str) -> Optional[Dict[str, Any]]:
    """
    Load cached token data for the given provider.
    Returns None if no cache exists or the file is invalid.
    """
    p = token_path(provider)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def save_tokens(provider: str, tokens: Dict[str, Any]) -> None:
    """
    Save tokens for the provider.
    Adds an 'obtained_at' timestamp if missing.
    """
    data = dict(tokens)
    data.setdefault("obtained_at", int(time.time()))
    _atomic_write_json(token_path(provider), data)


def access_token_valid(tokens: Dict[str, Any]) -> bool:
    """
    Return True if the access token is still valid,
    accounting for a small time skew margin.
    """
    try:
        obtained = int(tokens.get("obtained_at", 0))
        ttl = int(tokens.get("expires_in", 0))
        return (obtained + ttl - SKEW_SEC) > int(time.time())
    except Exception:
        return False


__all__ = [
    "load_tokens",
    "save_tokens",
    "access_token_valid",
    "token_path",
]
