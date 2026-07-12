# __init__.py
"""
Public, easy-to-use entry points for the StudentAid helpers.
"""

from __future__ import annotations
from typing import Callable, Tuple, Dict, List, Optional, Any

from .openstudentaid import (
    DEFAULT_CLIENT_ID,
    DEFAULT_PROVIDER,
    login as _login,
    login_full as _login_full,
    save_session as _save_session,
)
from .api import loan_summary as _loan_summary
from .api import loan_details as _loan_details
from .api import loan_snapshot as _loan_snapshot


# -------- Top-level convenience functions (stable public surface) -------- #

def login(
    *,
    provider: str = DEFAULT_PROVIDER,
    username: Optional[str] = None,
    password: Optional[str] = None,
    client_id: str = DEFAULT_CLIENT_ID,
    mfa_method: Optional[str] = None,
    remember_device: Optional[bool] = None,
    trusted_device: Optional[bool] = None,
    save_session: Optional[bool] = None,
    save_username: bool = True,
    background: bool = False,
    get_code: Optional[Callable[[str], str]] = None,
    mfa_code: Optional[str] = None,
    debug: bool = False,
    timeout_seconds: int = 180,
) -> Dict[str, Any]:
    """
    Login with Playwright and persist tokens.

    If username/password are omitted they are read from STUDENT_AID_USERNAME and
    STUDENT_AID_PASSWORD, then requested securely in the terminal. MFA is similarly
    interactive unless get_code, mfa_code, or STUDENT_AID_MFA_CODE is provided.
    """
    return _login_full(
        provider=provider,
        username=username,
        password=password,
        client_id=client_id,
        mfa_method=mfa_method,
        remember_device=remember_device,
        trusted_device=trusted_device,
        save_session=save_session,
        save_username=save_username,
        background=background,
        get_code=get_code,
        mfa_code=mfa_code,
        debug=debug,
        timeout_seconds=timeout_seconds,
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


def get_amount(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> float:
    """Return the current total balance across the borrower's loans."""
    total, _, _ = _loan_summary(provider=provider, client_id=client_id)
    return total


def get_data(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Dict[str, Any]:
    """Return the raw borrower-details payload from Nelnet."""
    _, _, raw = _loan_summary(provider=provider, client_id=client_id)
    return raw


def loan_snapshot(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Dict[str, Any]:
    """Return total balance, loan count, per-account summaries, and raw data."""
    return _loan_snapshot(provider=provider, client_id=client_id)


def save_session(*, provider: str = DEFAULT_PROVIDER):
    """Persist the most recent successful in-process login under `.osa/`."""
    return _save_session(provider=provider)


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
        username: Optional[str] = None,
        password: Optional[str] = None,
        mfa_method: Optional[str] = None,
        remember_device: Optional[bool] = None,
        trusted_device: Optional[bool] = None,
        save_session: Optional[bool] = None,
        save_username: bool = True,
        background: bool = False,
        get_code: Optional[Callable[[str], str]] = None,
        mfa_code: Optional[str] = None,
        debug: bool = False,
        timeout_seconds: int = 180,
    ) -> Dict[str, Any]:
        """Playwright login with MFA; persists tokens; returns token payload."""
        return login(
            provider=self.provider,
            username=username,
            password=password,
            client_id=self.client_id,
            mfa_method=mfa_method,
            remember_device=remember_device,
            trusted_device=trusted_device,
            save_session=save_session,
            save_username=save_username,
            background=background,
            get_code=get_code,
            mfa_code=mfa_code,
            debug=debug,
            timeout_seconds=timeout_seconds,
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

    def get_amount(self) -> float:
        """Return the current total balance across the borrower's loans."""
        return get_amount(provider=self.provider, client_id=self.client_id)

    def get_data(self) -> Dict[str, Any]:
        """Return the raw borrower-details payload."""
        return get_data(provider=self.provider, client_id=self.client_id)

    def save_session(self):
        """Persist the most recent successful login under `.osa/`."""
        return save_session(provider=self.provider)

    def loan_snapshot(self) -> Dict[str, Any]:
        """Return total balance, loan count, per-account summaries, and raw data."""
        return loan_snapshot(provider=self.provider, client_id=self.client_id)


# What we expose as public API
__all__ = [
    "login",
    "ensure_login",
    "loan_summary",
    "loan_details",
    "get_amount",
    "get_data",
    "loan_snapshot",
    "save_session",
    "StudentAid",
    "DEFAULT_PROVIDER",
    "DEFAULT_CLIENT_ID",
]
