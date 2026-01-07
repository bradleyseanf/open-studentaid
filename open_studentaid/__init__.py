# __init__.py
"""
Public, easy-to-use entry points for the StudentAid helpers.
"""

from __future__ import annotations
from typing import Tuple, Dict, List

from .config import DEFAULT_PROVIDER, DEFAULT_CLIENT_ID
from .auth import (
    login as _login,
    login_full as _login_full,
)
from .api import loan_summary as _loan_summary
from .api import loan_details as _loan_details


# -------- Top-level convenience functions (stable public surface) -------- #

def login(
    *,
    provider: str = DEFAULT_PROVIDER,
    username: str,
    password: str,
    client_id: str = DEFAULT_CLIENT_ID,
    mfa_method: str = "sms",
    remember_device: bool = True,
    save_username: bool = True,
    headless: bool = True,
    debug: bool = False,
) -> Dict:
    """
    Login with Playwright (headless by default) and persist tokens.
    """
    return _login_full(
        provider=provider,
        username=username,
        password=password,
        client_id=client_id,
        mfa_method=mfa_method,
        remember_device=remember_device,
        save_username=save_username,
        headless=headless,
        debug=debug,
    )


def ensure_login(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> str:
    """
    Ensure there is a valid access token for this provider.
    """
    return _login(provider=provider, client_id=client_id)


def loan_summary(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Tuple[float, int, Dict]:
    """
    Returns (total_balance, loan_count, raw_json) for the borrower.
    """
    return _loan_summary(provider=provider, client_id=client_id)


def loan_details(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> List[Dict]:
    """
    Returns a list of loans with per-loan balances and metadata.
    """
    return _loan_details(provider=provider, client_id=client_id)


# --------------------- Optional: simple OO wrapper ---------------------- #

class StudentAid:
    """
    Minimal convenience wrapper if you prefer an object API.
    """

    def __init__(self, provider: str = DEFAULT_PROVIDER, client_id: str = DEFAULT_CLIENT_ID):
        self.provider = provider
        self.client_id = client_id

    # Auth
    def login(
        self,
        *,
        username: str,
        password: str,
        mfa_method: str = "sms",
        remember_device: bool = True,
        save_username: bool = True,
        headless: bool = True,
        debug: bool = False,
    ) -> Dict:
        """Playwright login with MFA; persists tokens; returns token payload."""
        return login(
            provider=self.provider,
            username=username,
            password=password,
            client_id=self.client_id,
            mfa_method=mfa_method,
            remember_device=remember_device,
            save_username=save_username,
            headless=headless,
            debug=debug,
        )

    def ensure_login(self) -> str:
        """Ensure/refresh tokens; returns a fresh access token string."""
        return ensure_login(provider=self.provider, client_id=self.client_id)

    # APIs
    def loan_summary(self) -> Tuple[float, int, Dict]:
        """Borrower loan totals + raw payload."""
        return _loan_summary(provider=self.provider, client_id=self.client_id)

    def loan_details(self) -> List[Dict]:
        """Per-loan details with balances."""
        return _loan_details(provider=self.provider, client_id=self.client_id)


# What we expose as public API
__all__ = [
    "login",
    "ensure_login",
    "loan_summary",
    "loan_details",
    "StudentAid",
    "DEFAULT_PROVIDER",
    "DEFAULT_CLIENT_ID",
]
