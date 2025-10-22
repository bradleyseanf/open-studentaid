# api.py
from __future__ import annotations
from typing import Tuple, Dict, Any
import socket
import requests

from .config import ProviderConfig, DEFAULT_PROVIDER, DEFAULT_CLIENT_ID
from .auth import ensure_access_token

# In-process cache of discovered API bases per provider
_API_BASE_CACHE: Dict[str, str] = {}


def _money(x: Any) -> float:
    if x is None:
        return 0.0
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(str(x).replace(",", "").strip())
    except Exception:
        return 0.0


def _host_resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443)
        return True
    except Exception:
        return False


def _pick_api_base(cfg: ProviderConfig, sess: requests.Session, token: str, *, timeout: int = 5) -> str:
    """
    Detect a reachable API base for the provider. We try a few likely hosts and
    cache the first one that responds.
    """
    key = cfg.provider
    if key in _API_BASE_CACHE:
        return _API_BASE_CACHE[key]

    candidates = [
        f"https://mmaapi.{cfg.provider}.studentaid.gov",
        f"https://api.{cfg.provider}.studentaid.gov",
        f"https://{cfg.provider}.studentaid.gov",
    ]
    headers = {"Authorization": f"Bearer {token}"}

    for base in candidates:
        try:
            host = base.split("://", 1)[1].split("/", 1)[0]
            if not _host_resolves(host):
                continue
            # Prefer a cheap HEAD to a known path; consider most responses as "reachable".
            url = base + cfg.borrower_details_path
            r = sess.head(url, headers=headers, timeout=timeout)
            if r.status_code in (200, 401, 403, 404):
                _API_BASE_CACHE[key] = base
                return base
        except requests.RequestException:
            pass
        try:
            r = sess.get(base + "/health", timeout=timeout)
            if r.status_code in (200, 204, 401, 403, 404):
                _API_BASE_CACHE[key] = base
                return base
        except requests.RequestException:
            pass

    # Fallback to legacy default if none validated
    fallback = f"https://mmaapi.{cfg.provider}.studentaid.gov"
    _API_BASE_CACHE[key] = fallback
    return fallback


def loan_summary(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Tuple[float, int, Dict[str, Any]]:
    """
    Fetch borrower summary and return (total_balance, loan_count, raw_json).

    - Ensures a valid access token (auto-refresh via refresh_token if needed)
    - Dynamically discovers a reachable API base for the provider
    - Computes total as: principal + current interest + capitalized + late fees
    """
    cfg = ProviderConfig(provider=provider, client_id=client_id)

    # Always obtain a fresh-enough access token via our helper (auto-refreshes if expired)
    access_token = ensure_access_token(provider=cfg.provider, client_id=cfg.client_id)

    sess = requests.Session()
    api_base = _pick_api_base(cfg, sess, access_token)

    url = api_base + cfg.borrower_details_path
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    # Do the request; if we get a 401 (race with expiry), refresh once and retry.
    r = sess.get(url, headers=headers, timeout=30)
    if r.status_code == 401:
        access_token = ensure_access_token(provider=cfg.provider, client_id=cfg.client_id)
        headers["Authorization"] = f"Bearer {access_token}"
        r = sess.get(url, headers=headers, timeout=30)

    r.raise_for_status()
    data: Dict[str, Any] = r.json()

    loans = (data.get("borrowerInfo") or {}).get("edServicerLoans") or []
    loan_count = len(loans)

    total_balance = 0.0
    for ln in loans:
        principal = _money(ln.get("currentPrincipalBalance"))
        curr_int = _money(ln.get("currentInterest"))
        cap_int = _money(ln.get("capitalizedInterest"))
        late = _money(ln.get("outstandingLateFees"))
        total_balance += principal + curr_int + cap_int + late

    return total_balance, loan_count, data
