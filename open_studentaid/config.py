"""Session storage and virtual-display utilities for open_studentaid.

Tokens are stored under ``~/.studentaid`` by default. Browser storage is kept
under the project ``.osa`` directory unless an override is configured.

On Linux, ``managed_display`` can start Xvfb so headed Chrome can run on a
terminal-only server without opening a physical browser window.
"""

from __future__ import annotations
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Dict, Any

APP_DIR = Path(os.getenv("STUDENTAID_HOME", Path.home() / ".studentaid"))
SKEW_SEC = 60
LAST_SESSION_STATES: Dict[str, Dict[str, Any]] = {}


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
    try:
        os.chmod(tmp_name, 0o600)
    except OSError:
        pass
    os.replace(tmp_name, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


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


def session_state_path(provider: str) -> Path:
    root = os.getenv("OSA_STORAGE_DIR") or os.getenv("STUDENTAID_BROWSER_DIR")
    base = Path(root).expanduser() if root else Path.cwd() / ".osa"
    return base / provider / "storage_state.json"


def write_session_state(path: Path, state: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


class VirtualDisplayError(RuntimeError):
    pass


def _display_number() -> int:
    for number in range(90, 140):
        if not os.path.exists(f"/tmp/.X{number}-lock"):
            return number
    raise VirtualDisplayError("No free X display number was available for Xvfb.")


@contextlib.contextmanager
def managed_display(enabled: bool):
    """Start Xvfb automatically on Linux when background Chrome has no DISPLAY."""
    if not enabled or not sys.platform.startswith("linux") or os.getenv("DISPLAY"):
        yield
        return

    xvfb = shutil.which("Xvfb")
    if not xvfb:
        raise VirtualDisplayError(
            "No desktop DISPLAY is available and Xvfb is not installed. "
            "Install it with 'sudo apt install -y xvfb', or run under 'xvfb-run'."
        )

    number = _display_number()
    display = f":{number}"
    process = subprocess.Popen(
        [xvfb, display, "-screen", "0", "1440x1000x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    old_display = os.environ.get("DISPLAY")
    os.environ["DISPLAY"] = display
    try:
        time.sleep(0.25)
        if process.poll() is not None:
            raise VirtualDisplayError("Xvfb exited before Chrome could start.")
        yield
    finally:
        if old_display is None:
            os.environ.pop("DISPLAY", None)
        else:
            os.environ["DISPLAY"] = old_display
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()

__all__ = [
    "load_tokens",
    "save_tokens",
    "access_token_valid",
    "token_path",
    "LAST_SESSION_STATES",
    "session_state_path",
    "write_session_state",
    "VirtualDisplayError",
    "managed_display",
]
