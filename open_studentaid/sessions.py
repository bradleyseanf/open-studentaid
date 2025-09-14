from __future__ import annotations
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional, Dict

APP_DIR = Path(os.getenv("STUDENTAID_HOME", Path.home() / ".studentaid"))
SKEW_SEC = 60  # refresh a minute early

def token_path(provider: str) -> Path:
    return APP_DIR / f"tokens_{provider}.json"

def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        json.dump(data, tmp, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, path)

def load_tokens(provider: str) -> Optional[Dict]:
    p = token_path(provider)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None

def save_tokens(provider: str, tokens: Dict) -> None:
    data = dict(tokens)
    data.setdefault("obtained_at", int(time.time()))
    _atomic_write_json(token_path(provider), data)

def access_token_valid(tokens: Dict) -> bool:
    try:
        obtained = int(tokens.get("obtained_at", 0))
        ttl = int(tokens.get("expires_in", 0))
        return (obtained + ttl - SKEW_SEC) > int(time.time())
    except Exception:
        return False
