from __future__ import annotations
from typing import Tuple, Dict
import requests

from .config import ProviderConfig, DEFAULT_PROVIDER, DEFAULT_CLIENT_ID
from .auth import ensure_access_token

def _money(x) -> float:
    if x is None:
        return 0.0
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(str(x).replace(",", "").strip())
    except Exception:
        return 0.0

def loan_summary(provider: str = DEFAULT_PROVIDER,
                 client_id: str = DEFAULT_CLIENT_ID) -> Tuple[float, int, Dict]:
    """
    Returns (total_balance, loan_count, raw_json)
    total_balance = principal + current interest + capitalized + late fees
    """
    cfg = ProviderConfig(provider=provider, client_id=client_id)
    at = ensure_access_token(provider=cfg.provider, client_id=cfg.client_id)

    url = f"{cfg.api_base}{cfg.borrower_details_path}"
    headers = {"Authorization": f"Bearer {at}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()

    loans = (data.get("borrowerInfo") or {}).get("edServicerLoans") or []
    loan_count = len(loans)

    total_balance = 0.0
    for ln in loans:
        principal = _money(ln.get("currentPrincipalBalance"))
        curr_int  = _money(ln.get("currentInterest"))
        cap_int   = _money(ln.get("capitalizedInterest"))
        late      = _money(ln.get("outstandingLateFees"))
        total_balance += principal + curr_int + cap_int + late

    return total_balance, loan_count, data
