"""Nelnet OAuth borrower API implementation."""

from __future__ import annotations

import os
from typing import Any, Dict

import requests

from ..config import (
    LAST_SESSION_STATES,
    load_tokens,
    managed_display,
    save_tokens,
    session_state_path,
)

_API_BASE_CACHE: Dict[str, str] = {}


def _api_candidates(provider: str) -> list[str]:
    cached = _API_BASE_CACHE.get(provider)
    candidates = [
        f"https://mmaapi.{provider}.studentaid.gov",
        f"https://api.{provider}.studentaid.gov",
        f"https://{provider}.studentaid.gov",
    ]
    return ([cached] if cached else []) + [base for base in candidates if base != cached]


def _browser_api_get(provider: str, url: str, access_token: str):
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "Playwright is required to read Nelnet borrower data."
        ) from exc

    storage_state = LAST_SESSION_STATES.get(provider)
    state_path = session_state_path(provider)
    if storage_state is None and state_path.exists():
        storage_state = str(state_path)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json, text/plain, */*",
        "Origin": f"https://{provider}.studentaid.gov",
        "Referer": f"https://{provider}.studentaid.gov/",
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
                browser = pw.chromium.launch(
                    channel=channel, headless=False, args=launch_args
                )
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


def borrower_details(provider: str, client_id: str) -> Dict[str, Any]:
    # Imported lazily to avoid a module cycle during public API initialization.
    from ..openstudentaid import ProviderConfig, ensure_access_token, refresh_tokens

    cfg = ProviderConfig(provider=provider, client_id=client_id)
    access_token = ensure_access_token(provider=provider, client_id=client_id)
    last_status = None
    last_url = None
    last_body: Any = None

    for api_base in _api_candidates(provider):
        url = api_base + cfg.borrower_details_path
        try:
            status, body = _browser_api_get(provider, url, access_token)
        except Exception:
            continue
        last_status, last_url, last_body = status, url, body
        if status in (403, 404, 405):
            continue
        if status == 401:
            cached = load_tokens(provider) or {}
            refresh_token = cached.get("refresh_token")
            if refresh_token:
                refreshed = refresh_tokens(cfg, refresh_token)
                save_tokens(provider, refreshed)
                access_token = refreshed["access_token"]
            else:
                access_token = ensure_access_token(
                    provider=provider, client_id=client_id
                )
            status, body = _browser_api_get(provider, url, access_token)
            last_status, last_url, last_body = status, url, body
        if status >= 400:
            _raise_api_error(status, url, body)
        if not isinstance(body, dict):
            raise RuntimeError(f"Nelnet API returned a non-object response from {url}")
        _API_BASE_CACHE[provider] = api_base
        return body

    if last_status is not None and last_url is not None:
        _raise_api_error(last_status, last_url, last_body)
    raise RuntimeError("Unable to reach the Nelnet borrower details API.")
