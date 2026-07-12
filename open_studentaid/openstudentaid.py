from __future__ import annotations

import getpass
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv

from .config import (
    LAST_SESSION_STATES,
    access_token_valid,
    load_tokens,
    managed_display,
    save_tokens,
    session_state_path,
    write_session_state,
)


load_dotenv()

DEFAULT_PROVIDER = os.getenv("STUDENT_AID_PROVIDER", "nelnet").strip().lower()
DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "mma")


class ProviderConfig:
    def __init__(self, provider: str, client_id: str = DEFAULT_CLIENT_ID):
        self.provider = provider
        self.client_id = client_id

    @property
    def auth_base(self) -> str:
        return f"https://auth.{self.provider}.studentaid.gov"

    @property
    def token_url(self) -> str:
        return f"{self.auth_base}/connect/token"

    @property
    def api_base(self) -> str:
        return f"https://mmaapi.{self.provider}.studentaid.gov"

    @property
    def borrower_details_path(self) -> str:
        return "/api/1/borrower/details"


class TokenMissingError(RuntimeError):
    """Raised when an API call needs a token but no saved token is available."""


class RefreshFailedError(RuntimeError):
    """Raised when the cached refresh token cannot be exchanged."""


class LoginFlowError(RuntimeError):
    """Raised when the interactive Playwright login cannot reach an authenticated state."""


_DEFAULT_TIMEOUT_SECONDS = 180


def save_session(provider: str = DEFAULT_PROVIDER) -> Path:
    """Persist the most recent in-process browser state under ``.osa/``.

    Call this after ``login(save_session=False)`` when the caller decides that the
    successful login should be remembered. Existing saved state is returned unchanged.
    """
    provider = provider.strip().lower()
    path = session_state_path(provider)
    if path.exists():
        return path
    state = LAST_SESSION_STATES.get(provider)
    if state is None:
        raise LoginFlowError(
            f"No in-memory session is available for '{provider}'. Run login() successfully first."
        )
    return write_session_state(path, state)


def _require_playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401

        return sync_playwright
    except Exception as exc:  # pragma: no cover - depends on the user's environment
        raise LoginFlowError(
            "Playwright is required for browser login. Install it with "
            "'pip install -e .' and then run 'python -m playwright install chromium'."
        ) from exc


def _env_first(*names: str) -> Optional[str]:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


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


def _visible_count(page, selector: str) -> int:
    try:
        locator = page.locator(selector)
        return sum(1 for index in range(locator.count()) if locator.nth(index).is_visible())
    except Exception:
        return 0


def _button(page, patterns: list[str]):
    """Return the first visible button whose accessible name matches one of patterns."""
    for pattern in patterns:
        try:
            locator = page.get_by_role("button", name=re.compile(pattern, re.I))
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if candidate.is_visible() and candidate.is_enabled():
                    return candidate
        except Exception:
            continue
    return None


def _click_button(page, patterns: list[str], *, timeout_ms: int = 8_000) -> bool:
    button = _button(page, patterns)
    if button is None:
        return False
    try:
        button.click(timeout=timeout_ms)
        return True
    except Exception:
        return False


def _page_text(page) -> str:
    try:
        return page.locator("body").inner_text(timeout=2_000)
    except Exception:
        return ""


def _redact(value: str, secrets: list[str]) -> str:
    result = value
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    return result


class _FlowTracer:
    """Save redacted DOM/URL snapshots when debug mode is enabled."""

    def __init__(self, *, enabled: bool, secrets: list[str]):
        self.enabled = enabled
        self.secrets = secrets
        self.counter = 0
        self.directory: Optional[Path] = None
        if enabled:
            root = os.getenv("STUDENT_AID_DEBUG_DIR") or os.getenv("STUDENTAID_DEBUG_DIR")
            self.directory = Path(root).expanduser() if root else Path.cwd() / "studentaid_debug"
            self.directory.mkdir(parents=True, exist_ok=True)

    def network(self, kind: str, *, url: str, method: str = "", status: Optional[int] = None) -> None:
        if not self.enabled or self.directory is None:
            return
        event = {
            "kind": kind,
            "method": method,
            "status": status,
            "url": _redact(url, self.secrets),
        }
        try:
            with (self.directory / "network.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event) + "\n")
        except Exception:
            return

    def capture(self, page, label: str, *, note: str = "", screenshot: bool = True) -> None:
        if not self.enabled or page is None or page.is_closed():
            return
        self.counter += 1
        safe_label = re.sub(r"[^a-zA-Z0-9_.-]+", "_", label).strip("_") or "step"
        stem = f"{self.counter:02d}_{safe_label}"
        try:
            html = _redact(page.content(), self.secrets)
            body = _redact(_page_text(page), self.secrets)
            metadata = {
                "step": label,
                "note": note,
                "url": _redact(page.url, self.secrets),
                "title": _redact(page.title(), self.secrets),
                "body_text": body,
            }
            (self.directory / f"{stem}.html").write_text(html, encoding="utf-8")
            (self.directory / f"{stem}.json").write_text(
                json.dumps(metadata, indent=2), encoding="utf-8"
            )
            if screenshot:
                page.screenshot(path=str(self.directory / f"{stem}.png"), full_page=True)
        except Exception:
            # Diagnostics must never turn a usable login into a failed login.
            return


def _is_blocked(page) -> bool:
    text = _page_text(page).lower()
    return "http 403" in text or "access denied" in text or "request rejected" in text


def _accept_cookie_banner(page, tracer: _FlowTracer) -> bool:
    """Accept only controls inside the consent manager, never a page-wide Continue button."""
    roots = []
    try:
        roots.append(page.locator("#transcend-consent-manager"))
    except Exception:
        pass

    for root in roots:
        try:
            if root.count() == 0:
                continue
            for pattern in [r"^Accept All$", r"^Accept$", r"^Continue$"]:
                buttons = root.get_by_role("button", name=re.compile(pattern, re.I))
                for index in range(buttons.count()):
                    button = buttons.nth(index)
                    if button.is_visible():
                        button.click(timeout=3_000)
                        page.wait_for_timeout(300)
                        tracer.capture(page, "cookies_accepted")
                        return True
        except Exception:
            continue
    return False


def _accept_federal_notice(page, tracer: _FlowTracer) -> bool:
    """Accept the current federal usage notice when the agreement page is displayed."""
    button = _first_visible(
        page,
        [
            "#accept-disclaimer",
            "button[aria-label*='accept federal usage disclaimer' i]",
        ],
    )
    if button is None:
        return False
    try:
        button.scroll_into_view_if_needed(timeout=2_000)
        button.click(timeout=10_000)
        tracer.capture(page, "federal_notice_accepted")
        return True
    except Exception as exc:
        raise LoginFlowError("The federal usage notice was present but could not be accepted.") from exc


def _credential_form(page) -> bool:
    return bool(
        _first_visible(
            page,
            [
                "#password-textfield",
                "input[name='Password']",
                "input[data-cy='password']",
                "input[type='password']",
            ],
        )
    )


def _login_error(page) -> str:
    selectors = ["[role='alert']", "[data-cy='trouble-logging-in-error']", ".validation-summary-errors"]
    for selector in selectors:
        try:
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if candidate.is_visible():
                    message = candidate.inner_text().strip()
                    if message:
                        return re.sub(r"\s+", " ", message)
        except Exception:
            continue
    text = _page_text(page)
    for marker in ["Incorrect Username or Password", "account access", "too many attempts"]:
        if marker.lower() in text.lower():
            return marker
    return ""


def _open_login_and_terms(page, tracer: _FlowTracer, *, timeout_ms: int = 45_000) -> None:
    """Navigate the public site, agreement page, and OAuth login page."""
    deadline = time.monotonic() + timeout_ms / 1_000
    last_url = ""
    while time.monotonic() < deadline:
        if _is_blocked(page):
            raise LoginFlowError(
                "Nelnet returned HTTP 403 Access Denied. Nelnet's edge protection rejects "
                "automated browser modes; use the normal headed Chrome session and do not "
                "override the browser User-Agent."
            )
        if _credential_form(page):
            tracer.capture(page, "credential_form_ready")
            return

        url = page.url
        if url != last_url:
            last_url = url
            tracer.capture(page, "navigation", note=url)

        _accept_cookie_banner(page, tracer)
        if _accept_federal_notice(page, tracer):
            page.wait_for_timeout(500)
            continue

        if "/welcome" in url.lower() or "log in" in _page_text(page).lower():
            # The header has a combined "Log In | Create Online Account" button and a
            # separate exact "Log In" button. Prefer the exact action.
            if _click_button(page, [r"^Log In$"]):
                tracer.capture(page, "login_link_clicked")
                page.wait_for_timeout(500)
                continue

        if _login_error(page):
            return

        page.wait_for_timeout(250)

    raise LoginFlowError(f"The login form did not load; current URL: {page.url}")


def _fill_credentials(page, username: str, password: str, *, save_username: bool) -> None:
    username_field = _first_visible(
        page,
        ["#username-textfield", "input[name='Username']", "input[data-cy='username']", "input[type='text']"],
    )
    password_field = _first_visible(
        page,
        ["#password-textfield", "input[name='Password']", "input[data-cy='password']", "input[type='password']"],
    )
    if username_field is None or password_field is None:
        raise LoginFlowError(f"Nelnet's credential form changed; current URL: {page.url}")
    try:
        username_field.fill(username, timeout=5_000)
        password_field.fill(password, timeout=5_000)
    except Exception as exc:
        raise LoginFlowError("Nelnet's credential fields could not be filled.") from exc

    remember = _first_visible(page, ["#rememberLogin", "input[name='RememberLogin']"])
    if remember is not None and save_username:
        try:
            if not remember.is_checked():
                remember.check(timeout=2_000)
        except Exception:
            # Saving the username is optional; authentication is not.
            pass


def _code_inputs(page):
    selectors = [
        "input[name='UserCode']",
        "input[id*='UserCode' i]",
        "input[autocomplete='one-time-code']",
        "input[name*='verification' i]",
        "input[name*='otp' i]",
        "input[name*='code' i]",
        "input[id*='verification' i]",
        "input[id*='otp' i]",
        "input[inputmode='numeric']",
    ]
    found = []
    seen = set()
    for selector in selectors:
        try:
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if not candidate.is_visible() or candidate.get_attribute("type") in {"hidden", "radio", "checkbox"}:
                    continue
                key = candidate.get_attribute("id") or f"{selector}:{index}"
                if key not in seen:
                    seen.add(key)
                    found.append(candidate)
        except Exception:
            continue
    return found


def _mfa_choice_present(page) -> bool:
    if _visible_count(page, "input[name='AuthChoice']"):
        return True
    text = _page_text(page).lower()
    return bool(
        re.search(
            r"(choose|select|how would you like|verification method|text message|email address).*(code|verify|authentication)",
            text,
            re.S,
        )
    )


def _method_pattern(method: str) -> re.Pattern[str]:
    normalized = method.strip().lower().replace("-", "_")
    if normalized in {"sms", "text", "text_message", "textmessage"}:
        return re.compile(r"text\s*(message|to)|sms|mobile|phone|send.*text", re.I | re.S)
    if normalized in {"email", "e_mail"}:
        return re.compile(r"email|e-mail", re.I | re.S)
    if normalized in {"authenticator", "authenticator_app", "app", "totp"}:
        return re.compile(r"authenticator|verification app|security app|one.?time password|totp", re.I | re.S)
    raise LoginFlowError("mfa_method must be 'sms', 'email', or 'authenticator'")


def _select_mfa_method(page, mfa_method: str) -> None:
    pattern = _method_pattern(mfa_method)

    # Prefer accessible labels; this works whether the site uses radios, cards, or
    # labels wrapping the input. It also avoids relying on unstable numeric values.
    for selector in ["label", "[role='radio']", "[data-testid*='mfa' i]", "[data-cy*='mfa' i]"]:
        try:
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if not candidate.is_visible():
                    continue
                label_text = candidate.inner_text().strip()
                if not pattern.search(label_text):
                    continue
                try:
                    control = candidate.locator("input[type='radio'], input[type='checkbox']").first
                    if control.count() and control.is_visible():
                        control.check(timeout=5_000)
                    else:
                        candidate.click(timeout=5_000)
                    return
                except Exception:
                    try:
                        candidate.click(timeout=5_000)
                        return
                    except Exception:
                        continue
        except Exception:
            continue

    # Final fallback: inspect radio input ancestry and its associated label text.
    try:
        radios = page.locator("input[type='radio']")
        for index in range(radios.count()):
            radio = radios.nth(index)
            if not radio.is_visible():
                continue
            text = radio.evaluate(
                """el => {
                    const label = el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`) : null;
                    return [el.getAttribute('aria-label') || '', el.parentElement?.innerText || '', label?.innerText || ''].join(' ');
                }"""
            )
            if pattern.search(text):
                radio.check(timeout=5_000)
                return
    except Exception:
        pass

    raise LoginFlowError(f"Nelnet did not show an MFA option for '{mfa_method}'.")


def _click_send_code(page) -> bool:
    return _click_button(page, [r"send\s*(the\s*)?code", r"send", r"continue", r"next"], timeout_ms=8_000)


def _resolve_mfa_code(
    *,
    get_code: Optional[Callable[[str], str]],
    mfa_code: Optional[str],
) -> str:
    value = mfa_code or _env_first("STUDENT_AID_MFA_CODE", "MFA_CODE", "mfa_code")
    if value is None and get_code is not None:
        value = get_code("Enter the MFA code you received: ")
    if value is None:
        try:
            value = input("Enter the MFA code you received: ")
        except EOFError as exc:
            raise LoginFlowError(
                "MFA is required but no code was supplied. Pass get_code=..., "
                "mfa_code=..., or set STUDENT_AID_MFA_CODE."
            ) from exc
    value = re.sub(r"[\s-]+", "", str(value))
    if not value or len(value) < 4:
        raise LoginFlowError("The MFA code was empty or too short.")
    return value


def _fill_mfa_code(page, code: str) -> None:
    fields = _code_inputs(page)
    if not fields:
        raise LoginFlowError(f"Nelnet's MFA code field changed; current URL: {page.url}")
    try:
        if len(fields) == 1:
            fields[0].fill(code, timeout=5_000)
            return
        if len(code) != len(fields):
            # Some implementations expose one logical code field plus hidden helpers;
            # use the first visible field rather than silently losing characters.
            fields[0].fill(code, timeout=5_000)
            return
        for field, character in zip(fields, code):
            field.fill(character, timeout=5_000)
    except Exception as exc:
        raise LoginFlowError("Nelnet's MFA code field could not be filled.") from exc


def _remember_device(page) -> None:
    checkbox = _first_visible(
        page,
        [
            "#trustedDevice",
            "input[name*='trusted' i]",
            "input[name*='remember' i]",
            "input[id*='remember' i]",
        ],
    )
    if checkbox is not None:
        try:
            if not checkbox.is_checked():
                checkbox.check(timeout=2_000)
            return
        except Exception:
            pass

    try:
        labels = page.get_by_label(re.compile(r"remember|trust|recognize this device|don't ask", re.I))
        for index in range(labels.count()):
            label = labels.nth(index)
            if label.is_visible():
                label.check(timeout=2_000)
                return
    except Exception:
        pass


def _click_verify(page) -> bool:
    return _click_button(page, [r"verify", r"submit", r"continue", r"sign\s*in"], timeout_ms=8_000)


def _active_page(context, fallback):
    for candidate in reversed(context.pages):
        if not candidate.is_closed():
            if _code_inputs(candidate) or _credential_form(candidate) or "auth." in candidate.url:
                return candidate
    return fallback


def _browser_context(
    pw,
    storage_dir: Optional[Path],
    storage_state_path: Optional[Path],
    *,
    background: bool,
    viewport: dict[str, int],
):
    """Launch real Chrome where possible; stale User-Agent spoofing is deliberately avoided."""
    channel = os.getenv("STUDENT_AID_CHROME_CHANNEL", "chrome").strip() or "chrome"
    launch_kwargs = {"headless": False, "viewport": viewport}
    browser_args = []
    if background:
        browser_args = [
            "--window-position=-32000,-32000",
            f"--window-size={viewport['width']},{viewport['height']}",
            "--start-minimized",
        ]
    if storage_state_path is not None and storage_state_path.exists():
        try:
            browser = pw.chromium.launch(channel=channel, headless=False, args=browser_args)
        except Exception:
            try:
                browser = pw.chromium.launch(headless=False, args=browser_args)
            except Exception as exc:
                raise LoginFlowError(
                    "Could not launch a Playwright browser. Install Chrome or run "
                    "'python -m playwright install chromium'."
                ) from exc
        return browser.new_context(storage_state=str(storage_state_path), viewport=viewport), browser
    if storage_dir is not None:
        if browser_args:
            launch_kwargs["args"] = browser_args
        try:
            return pw.chromium.launch_persistent_context(
                user_data_dir=str(storage_dir), channel=channel, **launch_kwargs
            ), None
        except Exception as first_error:
            try:
                return pw.chromium.launch_persistent_context(
                    user_data_dir=str(storage_dir), **launch_kwargs
                ), None
            except Exception as second_error:
                raise LoginFlowError(
                    "Could not launch a Playwright browser. Install Chrome or run "
                    "'python -m playwright install chromium'."
                ) from second_error

    try:
        browser = pw.chromium.launch(channel=channel, headless=False, args=browser_args)
    except Exception:
        try:
            browser = pw.chromium.launch(headless=False, args=browser_args)
        except Exception as exc:
            raise LoginFlowError(
                "Could not launch a Playwright browser. A headed login needs a desktop "
                "session; install Chrome or run 'python -m playwright install chromium'."
            ) from exc
    return browser.new_context(viewport=viewport), browser


def login_playwright(
    provider: str,
    username: str,
    password: str,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    mfa_method: str = "sms",
    remember_device: Optional[bool] = None,
    trusted_device: Optional[bool] = None,
    save_session: Optional[bool] = None,
    save_username: bool = True,
    background: bool = False,
    get_code: Optional[Callable[[str], str]] = None,
    mfa_code: Optional[str] = None,
    debug: bool = False,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Log in through the real Nelnet browser flow and save the OAuth token payload.

    Always use a headed real Chrome session because the current Nelnet edge layer rejects
    automated browser modes. MFA can be supplied interactively, with ``get_code``, or
    with ``mfa_code``/``STUDENT_AID_MFA_CODE``.
    """
    provider = provider.strip().lower()
    if not username.strip() or not password:
        raise LoginFlowError("A Nelnet username and password are required.")
    if provider == "nelnet" and "@" in username:
        raise LoginFlowError(
            "Nelnet requires the account username, not an email address. "
            "No login request was sent."
        )
    if save_session is None:
        save_session = remember_device if remember_device is not None else True
    if trusted_device is None:
        trusted_device = remember_device if remember_device is not None else True
    if mfa_method.strip().lower() not in {
        "sms",
        "text",
        "text_message",
        "textmessage",
        "email",
        "e_mail",
        "authenticator",
        "authenticator_app",
        "app",
        "totp",
    }:
        raise LoginFlowError("mfa_method must be 'sms', 'email', or 'authenticator'")

    cfg = ProviderConfig(provider=provider, client_id=client_id)
    sync_playwright = _require_playwright()
    tracer = _FlowTracer(
        enabled=debug,
        secrets=[username, password, mfa_code or _env_first("STUDENT_AID_MFA_CODE", "MFA_CODE", "mfa_code") or ""],
    )
    token_payload: Optional[Dict[str, Any]] = None
    context = None
    browser = None
    page = None
    last_url = ""
    storage_dir: Optional[Path] = None
    storage_state_path: Optional[Path] = None

    if save_session:
        storage_state_path = session_state_path(cfg.provider)
        storage_dir = storage_state_path.parent
        storage_dir.mkdir(parents=True, exist_ok=True)

    def on_response(response) -> None:
        nonlocal token_payload
        if token_payload is not None:
            return
        try:
            parsed = urlsplit(response.url)
            if parsed.hostname != urlsplit(cfg.auth_base).hostname or parsed.path.rstrip("/").lower() != "/connect/token":
                return
            if response.status not in {200, 201}:
                return
            payload = response.json()
            if isinstance(payload, dict) and payload.get("access_token"):
                token_payload = payload
                if debug:
                    print(
                        "[DEBUG] Captured OAuth token response "
                        f"(expires_in={payload.get('expires_in')}, scope={payload.get('scope')!r})"
                    )
        except Exception:
            return

    try:
        with managed_display(enabled=background):
            with sync_playwright() as pw:
                context, browser = _browser_context(
                    pw,
                    storage_dir,
                    storage_state_path,
                    background=background,
                    viewport={"width": 1440, "height": 1000},
                )
                context.on("response", on_response)
                context.on(
                    "request",
                    lambda request: tracer.network(
                        "request", url=request.url, method=request.method
                    ),
                )
                context.on(
                    "response",
                    lambda response: tracer.network(
                        "response", url=response.url, status=response.status
                    ),
                )
                page = context.pages[0] if context.pages else context.new_page()
                if page.is_closed():
                    page = context.new_page()
                if debug:
                    print(f"[DEBUG] Opening {cfg.provider} login in headed Chrome")
                page.goto(
                    f"https://{cfg.provider}.studentaid.gov/account/login",
                    wait_until="domcontentloaded",
                    timeout=60_000,
                )
                _open_login_and_terms(page, tracer)
                if _login_error(page):
                    raise LoginFlowError(_login_error(page))

                tracer.capture(page, "before_credentials")
                _fill_credentials(page, username, password, save_username=save_username)
                submit = _first_visible(page, ["#btnSubmit", "button[data-cy='login']", "button[type='submit']"])
                if submit is None:
                    raise LoginFlowError(f"Nelnet's login submit button changed; current URL: {page.url}")
                submit.click(timeout=10_000)
                tracer.capture(page, "credentials_submitted", screenshot=False)

                deadline = time.monotonic() + max(30, timeout_seconds)
                choice_submitted = False
                code_submitted = False
                while time.monotonic() < deadline and token_payload is None:
                    page = _active_page(context, page)
                    previous_url = last_url
                    last_url = page.url
                    error = _login_error(page)
                    if error:
                        tracer.capture(page, "login_error", note=error)
                        raise LoginFlowError(error)

                    code_fields = _code_inputs(page)
                    if code_fields and not code_submitted:
                        tracer.capture(page, "mfa_code_form_ready")
                        code = _resolve_mfa_code(get_code=get_code, mfa_code=mfa_code)
                        _fill_mfa_code(page, code)
                        if trusted_device:
                            _remember_device(page)
                        if not _click_verify(page):
                            raise LoginFlowError(f"Nelnet's MFA verification button changed; current URL: {page.url}")
                        code_submitted = True
                        tracer.capture(page, "mfa_code_submitted", screenshot=False)
                        page.wait_for_timeout(500)
                        continue

                    if _mfa_choice_present(page) and not choice_submitted:
                        tracer.capture(page, "mfa_choice_form_ready")
                        _select_mfa_method(page, mfa_method)
                        if not _click_send_code(page):
                            raise LoginFlowError(f"Nelnet's MFA send-code button changed; current URL: {page.url}")
                        choice_submitted = True
                        tracer.capture(page, "mfa_method_submitted")
                        page.wait_for_timeout(500)
                        continue

                    if page.url != previous_url:
                        tracer.capture(page, "navigation", note=page.url)
                    page.wait_for_timeout(300)

                if token_payload is None:
                    tracer.capture(page, "login_timeout", note=last_url or page.url)
                    raise LoginFlowError(
                        "Login did not complete before the timeout; no OAuth token was observed. "
                        f"Last URL: {last_url or page.url}"
                    )

                try:
                    state = context.storage_state()
                    LAST_SESSION_STATES[cfg.provider] = state
                    if save_session and storage_state_path is not None:
                        write_session_state(storage_state_path, state)
                except Exception:
                    pass
    except LoginFlowError as exc:
        if tracer.directory and "Debug artifacts:" not in str(exc):
            raise LoginFlowError(f"{exc} Debug artifacts: {tracer.directory}") from exc
        raise
    except Exception as exc:
        debug_hint = f" Debug artifacts: {tracer.directory}" if tracer.directory else ""
        raise LoginFlowError(f"Playwright login failed: {exc}.{debug_hint}") from exc
    finally:
        # Persistent contexts own their browser; non-persistent contexts need their browser
        # closed separately. Playwright's context manager is still allowed to finish first.
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass

    if not token_payload:
        raise LoginFlowError("Login completed without an OAuth access token.")
    save_tokens(cfg.provider, token_payload)
    return token_payload


def _std_headers(provider: str) -> Dict[str, str]:
    return {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": os.getenv(
            "STUDENT_AID_API_USER_AGENT",
            "open-studentaid/0.1 (+Playwright browser login)",
        ),
        "Origin": f"https://{provider}.studentaid.gov",
        "Referer": f"https://{provider}.studentaid.gov/",
    }


def refresh_tokens(cfg: ProviderConfig, refresh_token: str) -> Dict[str, Any]:
    """Refresh a saved OAuth token and preserve a rotated refresh token when returned."""
    response = requests.post(
        cfg.token_url,
        headers={**_std_headers(cfg.provider), "Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": cfg.client_id,
            "scope": "openid offline_access mma.api.read mma.api.write",
        },
        timeout=30,
    )
    if response.status_code >= 400:
        raise RefreshFailedError(
            f"Refresh failed ({response.status_code}): {response.text[:400]} Re-login is required."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise RefreshFailedError("Refresh returned a non-JSON response. Re-login is required.") from exc
    if not payload.get("access_token"):
        raise RefreshFailedError("Refresh returned no access_token. Re-login is required.")
    payload.setdefault("refresh_token", refresh_token)
    payload.setdefault("expires_in", 3600)
    payload.setdefault("token_type", "Bearer")
    payload["obtained_at"] = int(time.time())
    return payload


def ensure_access_token(provider: str = DEFAULT_PROVIDER, client_id: str = DEFAULT_CLIENT_ID) -> str:
    """Return a valid cached token, refreshing it when possible."""
    cfg = ProviderConfig(provider=provider.strip().lower(), client_id=client_id)
    tokens = load_tokens(cfg.provider)
    if not tokens:
        raise TokenMissingError(
            f"No tokens found for provider '{cfg.provider}'. Run login() once to establish a token cache."
        )
    if tokens.get("access_token") and access_token_valid(tokens):
        return tokens["access_token"]
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise TokenMissingError("Token file exists but has no refresh_token. Re-login.")
    refreshed = refresh_tokens(cfg, refresh_token)
    save_tokens(cfg.provider, refreshed)
    return refreshed["access_token"]


def login(provider: str = DEFAULT_PROVIDER, client_id: str = DEFAULT_CLIENT_ID) -> str:
    """Compatibility alias for ensuring a cached access token."""
    return ensure_access_token(provider=provider, client_id=client_id)


def _resolve_credential(
    value: Optional[str],
    env_name: str,
    prompt: str,
    *,
    secret: bool,
    aliases: tuple[str, ...] = (),
) -> str:
    if value:
        return value
    from_env = _env_first(env_name, *aliases)
    if from_env:
        return from_env
    try:
        return getpass.getpass(prompt) if secret else input(prompt)
    except EOFError as exc:
        raise LoginFlowError(
            f"Missing credential. Pass it to login() or set {env_name} in the environment."
        ) from exc


def login_full(
    provider: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    *,
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
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Resolve explicit/env/terminal credentials and run the Playwright login."""
    resolved_username = _resolve_credential(
        username,
        "STUDENT_AID_USERNAME",
        "Nelnet username: ",
        secret=False,
        aliases=("NELNET_USERNAME", "USERNAME", "username"),
    )
    resolved_password = _resolve_credential(
        password,
        "STUDENT_AID_PASSWORD",
        "Nelnet password: ",
        secret=True,
        aliases=("NELNET_PASSWORD", "PASSWORD", "password"),
    )
    resolved_method = mfa_method or _env_first(
        "STUDENT_AID_MFA_METHOD", "MFA_METHOD", "mfa_method"
    ) or "sms"
    if save_session is None:
        save_session = remember_device if remember_device is not None else True
    if trusted_device is None:
        trusted_device = remember_device if remember_device is not None else True
    return login_playwright(
        provider=provider,
        username=resolved_username,
        password=resolved_password,
        client_id=client_id,
        mfa_method=resolved_method,
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


__all__ = [
    "LoginFlowError",
    "RefreshFailedError",
    "TokenMissingError",
    "ensure_access_token",
    "login",
    "login_full",
    "login_playwright",
    "refresh_tokens",
    "save_session",
]


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    from .api import loan_details, loan_snapshot

    parser = argparse.ArgumentParser(prog="studentaid", description="Read your Nelnet student-loan data")
    parser.add_argument("--provider", default=DEFAULT_PROVIDER)
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser("login", help="Complete Nelnet login and MFA")
    login_parser.add_argument("--username")
    login_parser.add_argument("--mfa-method", choices=["sms", "email", "authenticator"], default=None)
    login_parser.add_argument("--background", action="store_true")
    login_parser.add_argument("--no-save-session", action="store_true")
    login_parser.add_argument("--no-trusted-device", action="store_true")
    login_parser.add_argument("--debug", action="store_true")
    subparsers.add_parser("amount", help="Print the current total balance")
    subparsers.add_parser("details", help="Print normalized per-loan details as JSON")
    subparsers.add_parser("summary", help="Print total and per-account loan summary as JSON")

    args = parser.parse_args(argv)
    try:
        if args.command == "login":
            login_full(
                provider=args.provider,
                username=args.username,
                mfa_method=args.mfa_method,
                trusted_device=not args.no_trusted_device,
                save_session=not args.no_save_session,
                background=args.background,
                debug=args.debug,
            )
            print("Login completed and token cache updated.")
        elif args.command == "amount":
            from .api import loan_summary

            print(loan_summary(provider=args.provider)[0])
        elif args.command == "details":
            print(json.dumps(loan_details(provider=args.provider), indent=2))
        elif args.command == "summary":
            result = loan_snapshot(provider=args.provider)
            result.pop("raw", None)
            print(json.dumps(result, indent=2, default=str))
        return 0
    except Exception as exc:
        print(f"studentaid: {exc}")
        return 1
