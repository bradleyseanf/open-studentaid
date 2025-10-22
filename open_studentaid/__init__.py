# __init__.py
"""
Public, easy-to-use entry points for the StudentAid helpers.

Quick start
-----------
from open_studentaid import browser_login, ensure_login, loan_summary

# 1) First time: do an interactive login in a real browser (saves tokens to disk)
browser_login(provider="nelnet", debug=True)

# 2) Anywhere later: ensure/refresh access token + call APIs
_ = ensure_login(provider="nelnet")
total, count, raw = loan_summary(provider="nelnet")
"""

from __future__ import annotations
from typing import Tuple, Dict, Optional

from .config import DEFAULT_PROVIDER, DEFAULT_CLIENT_ID
from .auth import (
    login as _login,                      # ensures/refreshes from saved tokens
    login_full as _login_full,            # full headless flow (advanced)
    login_browser_assisted as _browser_login,  # interactive browser login (recommended)
)
from .api import loan_summary as _loan_summary


# -------- Top-level convenience functions (stable public surface) -------- #

def browser_login(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
    debug: bool = False,
) -> Dict:
    """
    Launch a real browser, complete sign-in + MFA, capture tokens,
    and persist them to ~/.studentaid/tokens_<provider>.json.
    Returns the token payload dict.
    """
    return _browser_login(provider=provider, client_id=client_id, debug=debug)


def ensure_login(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> str:
    """
    Ensure there is a valid access token for this provider.
    - Loads cached tokens if present
    - Refreshes if the 15-minute access token expired (using refresh_token)
    - Re-saves updated tokens to disk
    Returns a fresh access token string.
    """
    return _login(provider=provider, client_id=client_id)


def loan_summary(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Tuple[float, int, Dict]:
    """
    Returns (total_balance, loan_count, raw_json) for the borrower.
    Automatically relies on ensure_login() for a valid access token.
    """
    return _loan_summary(provider=provider, client_id=client_id)


# --------------------- Optional: simple OO wrapper ---------------------- #

class StudentAid:
    """
    Minimal convenience wrapper if you prefer an object API.

    sa = StudentAid(provider="nelnet")
    sa.login_browser(debug=True)   # one-time interactive login (saves tokens)
    total, count, raw = sa.loan_summary()
    """

    def __init__(self, provider: str = DEFAULT_PROVIDER, client_id: str = DEFAULT_CLIENT_ID):
        self.provider = provider
        self.client_id = client_id

    # Auth
    def login_browser(self, *, debug: bool = False) -> Dict:
        """Interactive browser login; persists tokens; returns token payload."""
        return browser_login(provider=self.provider, client_id=self.client_id, debug=debug)

    def ensure_login(self) -> str:
        """Ensure/refresh tokens; returns a fresh access token string."""
        return ensure_login(provider=self.provider, client_id=self.client_id)

    # APIs
    def loan_summary(self) -> Tuple[float, int, Dict]:
        """Borrower loan totals + raw payload."""
        return _loan_summary(provider=self.provider, client_id=self.client_id)


# What we expose as public API
__all__ = [
    "browser_login",
    "ensure_login",
    "loan_summary",
    "StudentAid",
    "DEFAULT_PROVIDER",
    "DEFAULT_CLIENT_ID",
]
