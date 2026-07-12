# api.py
from __future__ import annotations
from typing import Tuple, Dict, Any, List
import os
import re
import requests

from .openstudentaid import (
    DEFAULT_CLIENT_ID,
    DEFAULT_PROVIDER,
    ProviderConfig,
    ensure_access_token,
    refresh_tokens,
)
from .config import LAST_SESSION_STATES, load_tokens, managed_display, save_tokens, session_state_path

# In-process cache of discovered API bases per provider
_API_BASE_CACHE: Dict[str, str] = {}


def _money(x: Any) -> float:
    """Convert Nelnet's numeric/currency strings into a usable float."""
    if x is None:
        return 0.0
    if isinstance(x, (int, float)):
        return float(x)
    try:
        value = str(x).strip()
        if not value:
            return 0.0
        negative = value.startswith("(") and value.endswith(")")
        match = re.search(r"-?\d+(?:\.\d+)?", value.replace(",", ""))
        if not match:
            return 0.0
        result = float(match.group(0))
        return -abs(result) if negative else result
    except Exception:
        return 0.0


def _api_candidates(cfg: ProviderConfig) -> list[str]:
    """Return the current API host first, with old hosts as compatibility fallbacks."""
    key = cfg.provider
    if key in _API_BASE_CACHE:
        return [_API_BASE_CACHE[key]] + [
            base
            for base in (
                f"https://mmaapi.{cfg.provider}.studentaid.gov",
                f"https://api.{cfg.provider}.studentaid.gov",
                f"https://{cfg.provider}.studentaid.gov",
            )
            if base != _API_BASE_CACHE[key]
        ]
    return [
        f"https://mmaapi.{cfg.provider}.studentaid.gov",
        f"https://api.{cfg.provider}.studentaid.gov",
        f"https://{cfg.provider}.studentaid.gov",
    ]


def _browser_api_get(cfg: ProviderConfig, url: str, access_token: str):
    """Call the borrower API from Playwright's browser-backed request context.

    Nelnet's Akamai edge rejects the same OAuth request from the Python
    requests client, but accepts it from the authenticated browser context.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - depends on the user's environment
        raise RuntimeError(
            "Playwright is required to read borrower data. Install the project requirements."
        ) from exc

    storage_state = LAST_SESSION_STATES.get(cfg.provider)
    state_path = session_state_path(cfg.provider)
    if storage_state is None and state_path.exists():
        storage_state = str(state_path)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json, text/plain, */*",
        "Origin": f"https://{cfg.provider}.studentaid.gov",
        "Referer": f"https://{cfg.provider}.studentaid.gov/",
    }
    configured_user_agent = os.getenv("STUDENT_AID_API_USER_AGENT")
    context_options = {"viewport": {"width": 1440, "height": 1000}}
    if storage_state is not None:
        context_options["storage_state"] = storage_state
    if configured_user_agent:
        context_options["user_agent"] = configured_user_agent
        headers["User-Agent"] = configured_user_agent

    browser = None
    context = None
    with managed_display(enabled=True):
        with sync_playwright() as pw:
            channel = os.getenv("STUDENT_AID_CHROME_CHANNEL", "chrome").strip() or "chrome"
            launch_args = [
                "--window-position=-32000,-32000",
                "--window-size=1440,1000",
                "--start-minimized",
            ]
            try:
                browser = pw.chromium.launch(channel=channel, headless=False, args=launch_args)
            except Exception:
                browser = pw.chromium.launch(headless=False, args=launch_args)
            try:
                context = browser.new_context(**context_options)
                response = context.request.get(url, headers=headers, timeout=30_000)
                body = response.json() if response.ok else response.text()
                return response.status, body
            finally:
                if context is not None:
                    context.close()
                if browser is not None:
                    browser.close()


def _raise_api_error(status: int, url: str, body: Any) -> None:
    detail = body if isinstance(body, str) else ""
    raise requests.HTTPError(f"{status} Client Error for url: {url} {detail[:400]}")


def _loan_list(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    borrower = data.get("borrowerInfo") or {}
    containers = [container for container in (borrower, data) if isinstance(container, dict)]
    for container in containers:
        for key in ("edServicerLoans", "loans", "loanGroups", "loanDetails"):
            value = container.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _loan_total(loan: Dict[str, Any]) -> float:
    """Prefer an explicit current total and otherwise sum the known components."""
    for key in (
        "totalCurrentBalance",
        "currentTotalBalance",
        "totalBalance",
        "currentBalance",
        "amountOwed",
    ):
        if loan.get(key) not in (None, ""):
            return _money(loan[key])
    return sum(
        _money(loan.get(key))
        for key in (
            "currentPrincipalBalance",
            "currentInterest",
            "capitalizedInterest",
            "outstandingLateFees",
        )
    )


def _borrower_details(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Dict[str, Any]:
    """
    Fetch borrower details JSON from the servicer API.
    """
    cfg = ProviderConfig(provider=provider, client_id=client_id)
    access_token = ensure_access_token(provider=cfg.provider, client_id=cfg.client_id)

    last_status = None
    last_url = None
    last_body: Any = None
    for api_base in _api_candidates(cfg):
        url = api_base + cfg.borrower_details_path
        try:
            status, body = _browser_api_get(cfg, url, access_token)
        except Exception:
            continue
        last_status, last_url, last_body = status, url, body
        if status in (403, 404, 405):
            continue
        if status == 401:
            cached = load_tokens(cfg.provider) or {}
            refresh_token = cached.get("refresh_token")
            if refresh_token:
                refreshed = refresh_tokens(cfg, refresh_token)
                save_tokens(cfg.provider, refreshed)
                access_token = refreshed["access_token"]
            else:
                access_token = ensure_access_token(provider=cfg.provider, client_id=cfg.client_id)
            status, body = _browser_api_get(cfg, url, access_token)
            last_status, last_url, last_body = status, url, body
        if status >= 400:
            _raise_api_error(status, url, body)
        data = body
        if not isinstance(data, dict):
            raise RuntimeError(f"Nelnet API returned a non-object response from {url}")
        _API_BASE_CACHE[cfg.provider] = api_base
        return data

    if last_status is not None and last_url is not None:
        _raise_api_error(last_status, last_url, last_body)
    raise RuntimeError(f"Unable to reach the Nelnet borrower details API for provider '{cfg.provider}'.")


def loan_summary(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Tuple[float, int, Dict[str, Any]]:
    """
    Fetch borrower summary and return (total_balance, loan_count, raw_json).
    """
    data = _borrower_details(provider=provider, client_id=client_id)
    loans = _loan_list(data)
    loan_count = len(loans)

    total_balance = 0.0
    for ln in loans:
        total_balance += _loan_total(ln)

    return total_balance, loan_count, data


def loan_details(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> List[Dict[str, Any]]:
    """
    Return a list of per-loan balances and identifiers.
    """
    data = _borrower_details(provider=provider, client_id=client_id)
    loans = _loan_list(data)

    return _normalized_loan_details(loans)


def _normalized_loan_details(loans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    for ln in loans:
        principal = _money(ln.get("currentPrincipalBalance"))
        curr_int = _money(ln.get("currentInterest"))
        cap_int = _money(ln.get("capitalizedInterest"))
        late = _money(ln.get("outstandingLateFees"))
        total = _loan_total(ln)

        details.append(
            {
                "loanId": ln.get("loanId") or ln.get("loanAccountNumber") or ln.get("loanNumber"),
                "loanType": ln.get("loanTypeDescription") or ln.get("loanType"),
                "servicer": ln.get("servicerName") or ln.get("loanServicer"),
                "principal": principal,
                "interest": curr_int,
                "capitalizedInterest": cap_int,
                "lateFees": late,
                "totalBalance": total,
            }
        )

    return details


def loan_snapshot(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Dict[str, Any]:
    """Fetch borrower data once and return totals plus a per-account summary."""
    data = _borrower_details(provider=provider, client_id=client_id)
    loans = _loan_list(data)
    return {
        "totalBalance": sum(_loan_total(loan) for loan in loans),
        "loanCount": len(loans),
        "loans": _normalized_loan_details(loans),
        "raw": data,
    }
