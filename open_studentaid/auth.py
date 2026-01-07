from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Callable, Dict, Optional

import requests

from .config import ProviderConfig, DEFAULT_PROVIDER, DEFAULT_CLIENT_ID
from .sessions import load_tokens, save_tokens, access_token_valid

# =========================
# Exceptions
# =========================
class TokenMissingError(RuntimeError):
    pass


class RefreshFailedError(RuntimeError):
    pass


class LoginFlowError(RuntimeError):
    pass


_STD_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)


# --- Playwright helpers ---

def _require_playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return sync_playwright
    except Exception as e:
        raise LoginFlowError(
            "Playwright is required for browser login. "
            "Install with: pip install playwright && python -m playwright install chromium"
        ) from e


def _click_if_present(page, selector: str, *, timeout_ms: int = 2500) -> bool:
    try:
        el = page.locator(selector).first
        el.click(timeout=timeout_ms)
        return True
    except Exception:
        return False


def _click_force(page, selector: str) -> bool:
    try:
        return bool(
            page.evaluate(
                """(sel) => {
                    const el = document.querySelector(sel);
                    if (!el) return false;
                    el.click();
                    return true;
                }""",
                selector,
            )
        )
    except Exception:
        return False


def _fill_first(page, selectors: list[str], value: str) -> bool:
    for sel in selectors:
        try:
            el = page.locator(sel).first
            if el.count() > 0:
                el.fill(value, timeout=3000)
                return True
        except Exception:
            continue
    return False


def _dump_debug_artifacts(page, *, label: str) -> Optional[Path]:
    """
    Best-effort debug dump: screenshot + HTML to a local folder.
    Returns the folder path if created.
    """
    try:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_dir = Path.cwd() / "studentaid_debug"
        out_dir.mkdir(parents=True, exist_ok=True)
        png = out_dir / f"{label}_{ts}.png"
        html = out_dir / f"{label}_{ts}.html"
        page.screenshot(path=str(png), full_page=True)
        html.write_text(page.content(), encoding="utf-8")
        return out_dir
    except Exception:
        return None


def _wait_for_any_selector(page, selectors: list[str], *, timeout_ms: int) -> bool:
    deadline = time.time() + (timeout_ms / 1000.0)
    while time.time() < deadline:
        for sel in selectors:
            try:
                if page.locator(sel).count() > 0:
                    return True
            except Exception:
                continue
        page.wait_for_timeout(250)
    return False


def _wait_visible(page, selector: str, *, timeout_ms: int) -> bool:
    try:
        page.wait_for_selector(selector, timeout=timeout_ms, state="visible")
        return True
    except Exception:
        return False


def _find_auth_login_url(page, provider: str) -> Optional[str]:
    """Best-effort scrape for the auth-domain login URL on the landing page."""
    try:
        links = page.eval_on_selector_all(
            "a[href]",
            "els => els.map(e => e.getAttribute('href')).filter(Boolean)",
        )
    except Exception:
        return None
    for href in links:
        if f"auth.{provider}.studentaid.gov/Account/Login" in href:
            return href
    return None


# =========================
# Headless Playwright login
# =========================

def login_playwright(
    provider: str,
    username: str,
    password: str,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    mfa_method: str = "sms",
    remember_device: bool = True,
    save_username: bool = True,
    headless: bool = True,
    get_code: Optional[Callable[[str], str]] = None,
    debug: bool = False,
) -> Dict:
    """
    Headless Playwright login that mirrors the real browser flow.
    Uses a persistent browser profile under .osa/ so the device can be remembered.
    """
    cfg = ProviderConfig(provider=provider.strip().lower(), client_id=client_id)
    choice_map = {"sms": "3", "email": "2"}
    choice_val = choice_map.get(mfa_method.lower())
    if choice_val is None:
        raise LoginFlowError("mfa_method must be 'sms' or 'email'")

    token_payload: Dict | None = None
    sync_playwright = _require_playwright()

    def _on_response(resp):
        nonlocal token_payload
        if token_payload is not None:
            return
        try:
            url = resp.url
            if "/connect/token" not in url:
                return
            if resp.status != 200:
                return
            j = resp.json()
            if isinstance(j, dict) and "access_token" in j:
                token_payload = j
                if debug:
                    safe = {k: j.get(k) for k in ("token_type", "expires_in", "scope")}
                    print(f"[DEBUG] Captured token payload from {url} -> {safe}")
        except Exception:
            pass

    with sync_playwright() as pw:
        storage_dir = None
        if remember_device:
            storage_dir = Path.cwd() / ".osa" / cfg.provider
            storage_dir.mkdir(parents=True, exist_ok=True)

        if storage_dir:
            try:
                context = pw.chromium.launch_persistent_context(
                    user_data_dir=str(storage_dir),
                    channel="chrome",
                    headless=headless,
                    user_agent=_STD_UA,
                    viewport={"width": 1280, "height": 900},
                )
            except Exception:
                context = pw.chromium.launch_persistent_context(
                    user_data_dir=str(storage_dir),
                    headless=headless,
                    user_agent=_STD_UA,
                    viewport={"width": 1280, "height": 900},
                )
            browser = None
        else:
            try:
                browser = pw.chromium.launch(channel="chrome", headless=headless)
            except Exception:
                browser = pw.chromium.launch(headless=headless)
            context = browser.new_context(
                user_agent=_STD_UA,
                viewport={"width": 1280, "height": 900},
            )

        context.on("response", _on_response)
        page = context.new_page()

        login_url = f"https://{cfg.provider}.studentaid.gov/account/login"
        if debug:
            print(f"[DEBUG] Opening login: {login_url}")
        page.goto(login_url, wait_until="domcontentloaded")

        _wait_for_any_selector(page, ["app-root", "body"], timeout_ms=10000)

        if "welcome" in page.url.lower():
            _click_if_present(page, "button:has-text('Log In')", timeout_ms=8000)
            try:
                page.wait_for_url(re.compile(r"/account/login", re.I), timeout=15000)
            except Exception:
                pass

        # Select "Access Your Student Loan Account" and continue.
        if "account/login" in page.url.lower():
            if _wait_visible(page, "label[for='borrower']", timeout_ms=15000):
                try:
                    page.locator("label[for='borrower']").click(timeout=3000)
                except Exception:
                    pass
            try:
                page.locator("input#borrower").check(timeout=3000)
            except Exception:
                pass

            if _wait_visible(page, "#continue-button", timeout_ms=10000):
                _click_if_present(page, "#continue-button", timeout_ms=5000)
            _click_if_present(page, "button:has-text('Continue')", timeout_ms=5000)
            _click_if_present(page, "button[data-cy='submit-form']", timeout_ms=5000)
            _click_force(page, "#continue-button")

            if _wait_visible(page, "#accept-disclaimer", timeout_ms=10000) or _wait_visible(
                page,
                "button[aria-label*='accept federal usage disclaimer' i]",
                timeout_ms=10000,
            ):
                try:
                    page.locator("#accept-disclaimer").scroll_into_view_if_needed(timeout=2000)
                except Exception:
                    pass
                _click_if_present(page, "#accept-disclaimer", timeout_ms=8000)
            _click_if_present(page, "button:has-text('Accept')", timeout_ms=8000)
            _click_if_present(page, "button[aria-label*='accept federal usage disclaimer' i]", timeout_ms=8000)
            _click_force(page, "#accept-disclaimer")

            try:
                page.wait_for_url(re.compile(r"/Account/Login", re.I), timeout=20000)
            except Exception:
                pass
            if "account/login" in page.url.lower():
                auth_url = _find_auth_login_url(page, cfg.provider)
                if auth_url:
                    if debug:
                        print(f"[DEBUG] Navigating to auth login: {auth_url}")
                    page.goto(auth_url, wait_until="domcontentloaded")

        if debug:
            print(f"[DEBUG] URL before credential form: {page.url}")

        if not _wait_for_any_selector(page, ["input[type='password']"], timeout_ms=20000):
            if debug:
                out_dir = _dump_debug_artifacts(page, label="login_landing")
                if out_dir:
                    print(f"[DEBUG] Saved debug artifacts to: {out_dir}")
            raise LoginFlowError(f"Login form did not load; current URL: {page.url}")

        _fill_first(
            page,
            [
                "input[name*='user' i]",
                "input[id*='user' i]",
                "input[name*='email' i]",
                "input[id*='email' i]",
            ],
            username,
        )
        _fill_first(page, ["input[type='password']"], password)

        if save_username:
            try:
                page.get_by_label(re.compile(r"save username", re.I)).check(timeout=2000)
            except Exception:
                pass

        try:
            page.get_by_role("button", name=re.compile(r"continue", re.I)).click(timeout=5000)
        except Exception:
            _click_if_present(page, "button:has-text('Continue')", timeout_ms=5000)

        if debug:
            print(f"[DEBUG] After login submit URL: {page.url}")

        # MFA choice page (may be skipped if device is already trusted).
        try:
            has_choice = _wait_for_any_selector(page, ["input[name='AuthChoice']"], timeout_ms=20000)
            if has_choice:
                page.locator(f"input[name='AuthChoice'][value='{choice_val}']").check(timeout=5000)
                try:
                    page.get_by_role("button", name=re.compile(r"send code", re.I)).click(timeout=5000)
                except Exception:
                    _click_if_present(page, "button:has-text('Send')", timeout_ms=5000)
        except Exception:
            pass

        # MFA code page (if required).
        try:
            page.wait_for_selector("input[name='UserCode']", timeout=60000)
            code_input = (
                get_code("Enter the MFA code you received: ")
                if get_code
                else input("Enter the MFA code you received: ")
            ).strip()
            if not code_input:
                raise LoginFlowError("No MFA code provided")
            page.locator("input[name='UserCode']").fill(code_input, timeout=5000)

            if remember_device:
                try:
                    page.locator("input#trustedDevice").check(timeout=2000)
                except Exception:
                    try:
                        page.get_by_label(re.compile(r"remember this device", re.I)).check(timeout=2000)
                    except Exception:
                        pass

            try:
                page.get_by_role("button", name=re.compile(r"verify", re.I)).click(timeout=5000)
            except Exception:
                _click_if_present(page, "button:has-text('Verify')", timeout_ms=5000)
        except Exception:
            pass

        deadline = time.time() + 120
        while time.time() < deadline and token_payload is None:
            page.wait_for_timeout(300)

        last_url = page.url
        if storage_dir:
            try:
                context.storage_state(path=str(storage_dir / "storage_state.json"))
            except Exception:
                pass
        context.close()
        if browser:
            browser.close()

    if not token_payload:
        raise LoginFlowError(
            "Login did not complete or no token was returned. "
            f"Last URL: {last_url}"
        )

    save_tokens(cfg.provider, token_payload)
    return token_payload


# =========================
# Token refresh / access
# =========================

def _std_headers(provider: str) -> Dict[str, str]:
    return {
        "User-Agent": _STD_UA,
        "Origin": f"https://{provider}.studentaid.gov",
        "Referer": f"https://{provider}.studentaid.gov/",
    }


def refresh_tokens(cfg: ProviderConfig, refresh_token: str) -> Dict:
    """
    Refresh using read-only scope. Defensive if refresh_token is not rotated.
    """
    url = cfg.token_url
    headers = {
        **_std_headers(cfg.provider),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": cfg.client_id,
        "scope": "openid offline_access mma.api.read",
    }
    r = requests.post(url, headers=headers, data=data, timeout=30)
    if r.status_code >= 400:
        raise RefreshFailedError(f"Refresh failed ({r.status_code}): {r.text[:400]}")
    payload = r.json()
    if not payload.get("refresh_token"):
        payload["refresh_token"] = refresh_token
    payload.setdefault("expires_in", 3600)
    payload.setdefault("token_type", "Bearer")
    payload["obtained_at"] = int(time.time())
    return payload


def ensure_access_token(
    provider: str = DEFAULT_PROVIDER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> str:
    """
    Ensure we have a valid access token, refreshing if needed.
    """
    cfg = ProviderConfig(provider=provider.strip().lower(), client_id=client_id)
    tokens = load_tokens(cfg.provider)
    if not tokens:
        raise TokenMissingError(
            f"No tokens found for provider '{cfg.provider}'. "
            "Run login() once to establish a token cache."
        )

    if tokens.get("access_token") and access_token_valid(tokens):
        return tokens["access_token"]

    rt = tokens.get("refresh_token")
    if not rt:
        raise TokenMissingError("Token file exists but has no refresh_token. Re-login.")
    new_tokens = refresh_tokens(cfg, rt)
    save_tokens(cfg.provider, new_tokens)
    return new_tokens["access_token"]


def login(provider: str = DEFAULT_PROVIDER, client_id: str = DEFAULT_CLIENT_ID) -> str:
    """
    Simple entry that just ensures we have a fresh access token using saved tokens.
    """
    return ensure_access_token(provider=provider, client_id=client_id)


def login_full(
    provider: str,
    username: str,
    password: str,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    mfa_method: str = "sms",
    remember_device: bool = True,
    save_username: bool = True,
    headless: bool = True,
    get_code: Optional[Callable[[str], str]] = None,
    debug: bool = False,
) -> Dict:
    """
    Primary login entry using Playwright headless flow.
    """
    return login_playwright(
        provider=provider,
        username=username,
        password=password,
        client_id=client_id,
        mfa_method=mfa_method,
        remember_device=remember_device,
        save_username=save_username,
        headless=headless,
        get_code=get_code,
        debug=debug,
    )
