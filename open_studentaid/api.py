"""Provider-neutral borrower data API."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .edfinancial.api import borrower_details as _edfinancial_borrower_details
from .nelnet.api import borrower_details as _nelnet_borrower_details
from .openstudentaid import DEFAULT_CLIENT_ID, DEFAULT_PROVIDER


def _money(value: Any) -> float:
    """Convert numeric and currency strings into a float."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = str(value).strip()
        if not text:
            return 0.0
        negative = text.startswith("(") and text.endswith(")")
        match = re.search(r"-?\d+(?:\.\d+)?", text.replace(",", ""))
        if not match:
            return 0.0
        result = float(match.group(0))
        return -abs(result) if negative else result
    except Exception:
        return 0.0


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
    """Prefer an explicit current total and otherwise sum known components."""
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
    normalized_provider = provider.strip().lower()
    if normalized_provider == "edfinancial":
        return _edfinancial_borrower_details(normalized_provider, client_id)
    if normalized_provider == "nelnet":
        return _nelnet_borrower_details(normalized_provider, client_id)
    raise ValueError(
        f"Unsupported provider '{provider}'. Supported providers: nelnet, edfinancial."
    )


def _summary_values(data: Dict[str, Any]) -> Tuple[float, int]:
    loans = _loan_list(data)
    explicit_total = data.get("totalCurrentBalance")
    explicit_count = data.get("totalNumberOfLoans")
    total = (
        _money(explicit_total)
        if explicit_total not in (None, "")
        else sum(_loan_total(loan) for loan in loans)
    )
    count = int(explicit_count) if explicit_count not in (None, "") else len(loans)
    return total, count


def loan_summary(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Tuple[float, int, Dict[str, Any]]:
    """Return ``(total_balance, loan_count, raw_data)`` for either provider."""
    data = _borrower_details(provider=provider, client_id=client_id)
    total, count = _summary_values(data)
    return total, count, data


def _normalized_loan_details(loans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    for loan in loans:
        details.append(
            {
                "loanId": (
                    loan.get("loanId")
                    or loan.get("loanAccountNumber")
                    or loan.get("loanNumber")
                ),
                "loanType": loan.get("loanTypeDescription") or loan.get("loanType"),
                "servicer": loan.get("servicerName") or loan.get("loanServicer"),
                "status": loan.get("status"),
                "interestRate": (
                    _money(loan.get("interestRate"))
                    if loan.get("interestRate") not in (None, "")
                    else None
                ),
                "principal": _money(loan.get("currentPrincipalBalance")),
                "interest": _money(loan.get("currentInterest")),
                "capitalizedInterest": _money(loan.get("capitalizedInterest")),
                "lateFees": _money(loan.get("outstandingLateFees")),
                "totalBalance": _loan_total(loan),
            }
        )
    return details


def loan_details(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> List[Dict[str, Any]]:
    """Return normalized per-loan balances and identifiers."""
    data = _borrower_details(provider=provider, client_id=client_id)
    return _normalized_loan_details(_loan_list(data))


def loan_snapshot(
    *,
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> Dict[str, Any]:
    """Fetch once and return totals, normalized loans, and raw provider data."""
    data = _borrower_details(provider=provider, client_id=client_id)
    total, count = _summary_values(data)
    return {
        "totalBalance": total,
        "loanCount": count,
        "loans": _normalized_loan_details(_loan_list(data)),
        "raw": data,
    }
