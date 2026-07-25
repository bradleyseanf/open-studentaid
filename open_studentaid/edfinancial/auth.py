"""Edfinancial CALM/MyAccount login behavior."""

from __future__ import annotations

import re
from datetime import date
from urllib.parse import urlsplit

from ..exceptions import LoginFlowError


def login_url() -> str:
    return "https://myaccount.edfinancial.studentaid.gov/"


def _page_text(page) -> str:
    try:
        return page.locator("body").inner_text(timeout=2_000)
    except Exception:
        return ""


def _first_visible(page, selectors: list[str]):
    for selector in selectors:
        try:
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if candidate.is_visible():
                    return candidate
        except Exception:
            continue
    return None


def normalize_date_of_birth(value: str) -> tuple[str, str, str]:
    digits = re.sub(r"\D+", "", str(value))
    if len(digits) != 8:
        raise LoginFlowError("STUDENT_AID_DOB must contain 8 digits in MMDDYYYY format.")
    month, day, year = digits[:2], digits[2:4], digits[4:]
    try:
        parsed = date(int(year), int(month), int(day))
    except ValueError as exc:
        raise LoginFlowError("STUDENT_AID_DOB is not a valid calendar date.") from exc
    if parsed > date.today():
        raise LoginFlowError("STUDENT_AID_DOB cannot be in the future.")
    return month, day, year


def normalize_social_security_number(value: str) -> tuple[str, str, str]:
    digits = re.sub(r"\D+", "", str(value))
    if len(digits) != 9:
        raise LoginFlowError("STUDENT_AID_SSN must contain exactly 9 digits.")
    return digits[:3], digits[3:5], digits[5:]


def identity_verification_present(page) -> bool:
    text = _page_text(page).lower()
    return "date of birth" in text and (
        "social security number" in text
        or "account number" in text
        or "more information to keep you secure" in text
    )


def account_summary_present(page) -> bool:
    parsed = urlsplit(page.url)
    if parsed.hostname != "myaccount.edfinancial.studentaid.gov":
        return False
    return (
        "/accountsummary" in parsed.path.lower()
        and "total current balance" in _page_text(page).lower()
    )


def _visible_unique_inputs(page, selectors: list[str]):
    found = []
    seen = set()
    for selector in selectors:
        try:
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if not candidate.is_visible():
                    continue
                element_id = candidate.get_attribute("id")
                name = candidate.get_attribute("name")
                key = element_id or (f"{name}:{index}" if name else f"{selector}:{index}")
                if key not in seen:
                    seen.add(key)
                    found.append(candidate)
        except Exception:
            continue
    return found


def _date_of_birth_fields(page):
    month = _first_visible(
        page,
        [
            "input[name*='birthMonth' i]",
            "input[id*='birthMonth' i]",
            "input[name*='dobMonth' i]",
            "input[id*='dobMonth' i]",
            "input[placeholder='MM' i]",
            "input[aria-label*='birth month' i]",
        ],
    )
    day = _first_visible(
        page,
        [
            "input[name*='birthDay' i]",
            "input[id*='birthDay' i]",
            "input[name*='dobDay' i]",
            "input[id*='dobDay' i]",
            "input[placeholder='DD' i]",
            "input[aria-label*='birth day' i]",
        ],
    )
    year = _first_visible(
        page,
        [
            "input[name*='birthYear' i]",
            "input[id*='birthYear' i]",
            "input[name*='dobYear' i]",
            "input[id*='dobYear' i]",
            "input[placeholder='YYYY' i]",
            "input[aria-label*='birth year' i]",
        ],
    )
    return month, day, year


def _social_security_fields(page):
    fields = _visible_unique_inputs(
        page,
        [
            "input[name*='ssn' i]",
            "input[id*='ssn' i]",
            "input[name*='socialSecurity' i]",
            "input[id*='socialSecurity' i]",
            "input[aria-label*='social security' i]",
        ],
    )
    if fields:
        return fields

    candidates = _visible_unique_inputs(
        page, ["input[type='password']", "input[inputmode='numeric']"]
    )
    masked = []
    for candidate in candidates:
        placeholder = candidate.get_attribute("placeholder") or ""
        maximum = candidate.get_attribute("maxlength") or ""
        compact_placeholder = placeholder.replace(" ", "").replace("-", "")
        if set(compact_placeholder) <= {"*"} and (
            compact_placeholder or maximum in {"2", "3", "4"}
        ):
            masked.append(candidate)
    return masked


def fill_identity_verification(
    page, date_of_birth: str, social_security_number: str
) -> None:
    month, day, year = normalize_date_of_birth(date_of_birth)
    ssn_first, ssn_middle, ssn_last = normalize_social_security_number(
        social_security_number
    )
    month_field, day_field, year_field = _date_of_birth_fields(page)
    if month_field is None or day_field is None or year_field is None:
        raise LoginFlowError(
            f"Edfinancial's date-of-birth fields changed; current URL: {page.url}"
        )

    ssn_fields = _social_security_fields(page)
    if len(ssn_fields) not in {1, 3}:
        raise LoginFlowError(
            "Edfinancial requires SSN identity verification, but its SSN fields "
            f"could not be identified; current URL: {page.url}"
        )

    try:
        month_field.fill(month, timeout=5_000)
        day_field.fill(day, timeout=5_000)
        year_field.fill(year, timeout=5_000)
        if len(ssn_fields) == 1:
            ssn_fields[0].fill(ssn_first + ssn_middle + ssn_last, timeout=5_000)
        else:
            for field, part in zip(ssn_fields, (ssn_first, ssn_middle, ssn_last)):
                field.fill(part, timeout=5_000)
    except Exception as exc:
        raise LoginFlowError(
            "Edfinancial's identity-verification fields could not be filled."
        ) from exc
