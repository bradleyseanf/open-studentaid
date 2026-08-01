"""Edfinancial authenticated account-summary implementation."""

from __future__ import annotations

import os
import re
from typing import Any, Dict

from bs4 import BeautifulSoup

from ..config import managed_display, session_state_path, write_session_state
from ..exceptions import RefreshFailedError


def _money(value: Any) -> float:
    match = re.search(r"-?\d+(?:\.\d+)?", str(value).replace(",", ""))
    return float(match.group(0)) if match else 0.0


def parse_account_summary(html: str, text: str) -> Dict[str, Any]:
    balance_match = re.search(
        r"Total\s+Current\s+Balance:\s*\$([\d,]+(?:\.\d{2})?)", text, re.I
    )
    count_match = re.search(r"Total\s+Number\s+of\s+Loans:\s*(\d+)", text, re.I)
    if not balance_match or not count_match:
        raise RuntimeError(
            "Edfinancial's account-summary balance fields could not be parsed."
        )

    soup = BeautifulSoup(html, "html.parser")
    loans = []
    for row in soup.select("#transactions-info-container > tr"):
        loan_cell = row.select_one("td.loan[title]")
        if loan_cell is None:
            continue
        title = loan_cell.get("title", "").strip()
        detail = loan_cell.select_one(".loanDetails")
        detail_text = detail.get_text(" ", strip=True) if detail else ""
        balance = re.search(
            r"Current\s+Balance\s+\$([\d,]+(?:\.\d{2})?)", detail_text, re.I
        )
        rate = re.search(r"Interest\s+Rate\s+([\d.]+)%", detail_text, re.I)
        type_cell = row.select_one("td[title='Type']")
        status_cell = row.select_one("td.status[title]")
        link = loan_cell.select_one("a[href*='loanId=']")
        loan_id_match = re.search(r"[?&]loanId=(\d+)", link.get("href", "") if link else "")
        loans.append(
            {
                "loanId": loan_id_match.group(1) if loan_id_match else title.split(" ", 1)[0],
                "loanTypeDescription": title,
                "loanType": type_cell.get_text(" ", strip=True) if type_cell else None,
                "servicerName": "Edfinancial",
                "status": status_cell.get("title") if status_cell else None,
                "interestRate": float(rate.group(1)) if rate else None,
                "currentBalance": _money(balance.group(1)) if balance else 0.0,
            }
        )

    expected_count = int(count_match.group(1))
    if len(loans) != expected_count:
        raise RuntimeError(
            f"Edfinancial reported {expected_count} loans but {len(loans)} rows were parsed."
        )
    return {
        "provider": "edfinancial",
        "totalCurrentBalance": _money(balance_match.group(1)),
        "totalNumberOfLoans": expected_count,
        "loans": loans,
    }


def _persist_browser_session(context, state_path) -> None:
    """Keep cookies rotated during a successful account read for the next run."""
    write_session_state(state_path, context.storage_state())


def borrower_details(provider: str, client_id: str) -> Dict[str, Any]:
    del provider, client_id
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "Playwright is required to read Edfinancial borrower data."
        ) from exc

    state_path = session_state_path("edfinancial")
    if not state_path.exists():
        raise RefreshFailedError(
            "No saved Edfinancial browser session was found. Re-login is required."
        )

    browser = None
    context = None
    with managed_display(enabled=True):
        with sync_playwright() as pw:
            channel = os.getenv("STUDENT_AID_CHROME_CHANNEL", "chrome").strip() or "chrome"
            launch_options = {
                "headless": False,
                "args": [
                    "--window-position=-32000,-32000",
                    "--window-size=1440,1000",
                    "--start-minimized",
                ],
            }
            try:
                browser = pw.chromium.launch(channel=channel, **launch_options)
            except Exception:
                browser = pw.chromium.launch(**launch_options)
            try:
                context = browser.new_context(
                    storage_state=str(state_path),
                    viewport={"width": 1440, "height": 1000},
                )
                page = context.new_page()
                page.goto(
                    "https://myaccount.edfinancial.studentaid.gov/AccountSummary",
                    wait_until="domcontentloaded",
                    timeout=60_000,
                )
                page.wait_for_timeout(2_000)
                text = page.locator("body").inner_text(timeout=10_000)
                if (
                    "myaccount.edfinancial.studentaid.gov" not in page.url
                    or "Total Current Balance" not in text
                ):
                    raise RefreshFailedError(
                        "The saved Edfinancial browser session expired. "
                        f"Re-login is required; current URL: {page.url}"
                    )
                details = parse_account_summary(page.content(), text)
                _persist_browser_session(context, state_path)
                return details
            finally:
                if context is not None:
                    context.close()
                if browser is not None:
                    browser.close()
