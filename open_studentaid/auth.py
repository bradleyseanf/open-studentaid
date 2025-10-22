from __future__ import annotations

import base64
import hashlib
import secrets
import time
import urllib.parse as urlparse
from typing import Callable, Dict, Optional, Tuple

import requests
from bs4 import BeautifulSoup

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


# =========================
# PKCE & HTTP Helpers
# =========================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _new_code_verifier() -> str:
    # RFC 7636 requires 43-128 chars; 64 gives ample entropy
    return _b64url(secrets.token_bytes(48))


def _code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return _b64url(digest)


def _akamai_warmup(sess: requests.Session, debug: bool = False):
    # 1) root splash – sets sitewide cookies (ak_bmsc / bm_sv)
    root = "https://nelnet.studentaid.gov/"
    r1 = sess.get(root, timeout=30)
    if debug:
        print(f"[DEBUG] warmup GET {root} -> {r1.status_code}; set-cookie? {bool(r1.headers.get('set-cookie'))}")

    # 2) login landing – sets antiforgery cookie on .studentaid.gov when it wants to
    warm = "https://nelnet.studentaid.gov/account/login"
    r2 = sess.get(warm, timeout=30)
    if debug:
        print(f"[DEBUG] warmup GET {warm} -> {r2.status_code}; set-cookie? {bool(r2.headers.get('set-cookie'))}")

    if debug:
        print("[DEBUG] warmup cookies:", sorted({c.name for c in sess.cookies}))

def _form_action_url(current_url: str, form_el) -> str:
    action = (form_el.get("action") or "").strip()
    return current_url if action == "" else urlparse.urljoin(current_url, action)

def _hidden(soup: BeautifulSoup, name: str) -> str:
    el = soup.find("input", {"name": name})
    return el.get("value", "") if el else ""


# --- Browser-assisted login helpers (Playwright headed browser) ---

def _ensure_playwright_available():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False

import time as _time
from playwright.sync_api import sync_playwright

def browser_assisted_login(
    *,
    provider: str,
    client_id: str = DEFAULT_CLIENT_ID,  # kept for signature parity; not used here
    debug: bool = False,
) -> Dict:
    """
    Open the site's normal login, let the human complete auth/MFA, then capture the
    first successful OAuth token payload by watching the browser's network traffic
    to {auth_base}/connect/token. Works even if the actual authorize host/params
    change, because we do not craft that request ourselves.
    """
    cfg = ProviderConfig(provider=provider.strip().lower(), client_id=client_id)

    token_payload: Dict | None = None

    with sync_playwright() as pw:
        # Prefer installed Chrome (less bot friction), else bundled Chromium.
        try:
            browser = pw.chromium.launch(channel="chrome", headless=False)
        except Exception:
            browser = pw.chromium.launch(headless=False)

        # Use a fresh, non-persistent context (no prior cookies).
        context = browser.new_context()
        page = context.new_page()

        # Listener: capture the first successful /connect/token JSON.
        def _on_response(resp):
            nonlocal token_payload
            if token_payload is not None:
                return
            try:
                url = resp.url
                if not url.startswith(cfg.auth_base) or "/connect/token" not in url:
                    return
                if resp.status != 200:
                    return
                # Must be a token exchange; try to parse JSON
                j = resp.json()
                if isinstance(j, dict) and "access_token" in j:
                    token_payload = j
                    if debug:
                        safe = {k: j.get(k) for k in ("token_type", "expires_in", "scope")}
                        print(f"[DEBUG] Captured token payload from {url} -> {safe}")
            except Exception:
                pass

        context.on("response", _on_response)

        # Warm-up (Akamai + sets cookies). Best-effort only.
        try:
            page.goto(f"https://{cfg.provider}.studentaid.gov/", wait_until="domcontentloaded")
        except Exception:
            pass

        # Send user to the normal login screen and let the site handle redirects.
        login_url = f"https://{cfg.provider}.studentaid.gov/account/login"
        if debug:
            print(f"[DEBUG] Opening login: {login_url}")
            print("[DEBUG] Complete sign-in + MFA in the browser window…")
        page.goto(login_url, wait_until="domcontentloaded")

        # Wait up to 3 minutes for any tab to receive /connect/token.
        deadline = _time.time() + 180
        while _time.time() < deadline and token_payload is None:
            page.wait_for_timeout(300)

        browser.close()

    if not token_payload:
        raise LoginFlowError("Login did not complete or no token was returned.")

    # Persist & return.
    save_tokens(cfg.provider, token_payload)
    return token_payload


def login_browser_assisted(
    provider: str = DEFAULT_PROVIDER,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    debug: bool = False,
) -> Dict:
    """
    Open a real browser, let the user sign in + MFA, capture tokens from /connect/token.
    """
    return browser_assisted_login(provider=provider, client_id=client_id, debug=debug)

def _std_headers(provider: str) -> Dict[str, str]:
    # Browser-like headers to satisfy WAF/Bot and ASP.NET antiforgery
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
        ),
        # Critical: client hints + fetch metadata (Chrome sends these)
        "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        "sec-ch-ua-mobile": "?0",
        'sec-ch-ua-platform': '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-User": "?1",

        # Navigation context toward auth
        "Referer": f"https://{provider}.studentaid.gov/",
        "Origin":  f"https://{provider}.studentaid.gov",
    }


def _abs_url(auth_base: str, url: str) -> str:
    if not url:
        return ""
    return (auth_base + url) if url.startswith("/") else url


def _parse_hidden_fields_from_html(html: str) -> Dict[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    data: Dict[str, str] = {}
    for inp in soup.select("input[type=hidden]"):
        name = inp.get("name")
        val = inp.get("value") or ""
        if name:
            data[name] = val
    return data


def _collect_form_inputs(form_el) -> Dict[str, str]:
    """
    Collect ALL inputs from a given <form> so we echo back anything the server expects,
    including hidden fields, return URL, and submit values.
    """
    data: Dict[str, str] = {}
    for inp in form_el.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        val = inp.get("value") or ""
        data[name] = val
    # Capture submit/button values if present but unnamed inputs are ignored by browsers typically
    for btn in form_el.find_all(["button", "input"]):
        itype = (btn.get("type") or "").lower()
        if itype == "submit":
            n = btn.get("name")
            v = btn.get("value") or "Submit"
            if n and n not in data:
                data[n] = v
    return data

def _extract_iframe_srcs(auth_base: str, page_url: str, html: str) -> list[str]:
    """Return a list of absolute iframe URLs found in the HTML. Handles src, srcdoc, and data-* fallbacks."""
    soup = BeautifulSoup(html, "html.parser")
    srcs: list[str] = []

    def absolutize(u: str) -> str:
        if not u:
            return ""
        if u.startswith("//"):
            return "https:" + u
        if u.startswith("/"):
            return auth_base + u
        return u  # assume absolute

    for ifr in soup.find_all("iframe"):
        # 1) src attribute (normal case)
        src = (ifr.get("src") or "").strip()

        # 2) sometimes login iframes lazy-load via data-* attributes
        if not src:
            for k, v in ifr.attrs.items():
                if k.startswith("data-") and isinstance(v, str):
                    if any(seg in v.lower() for seg in ("/account/", "/login", "signin", "auth", "identity")):
                        src = v.strip()
                        break

        # 3) srcdoc (inline HTML) — parse it and look for nested iframes with real src
        if not src:
            srcdoc = ifr.get("srcdoc")
            if isinstance(srcdoc, str) and srcdoc.strip():
                sub = BeautifulSoup(srcdoc, "html.parser")
                for sub_ifr in sub.find_all("iframe"):
                    sub_src = (sub_ifr.get("src") or "").strip()
                    if sub_src:
                        src = sub_src
                        break

        if src:
            srcs.append(absolutize(src))

    return srcs

import re

LOGIN_URL_PATTERNS = re.compile(
    r"""(?xi)
    # common identities / endpoints we might see inside JS
    (?:/Account/(?:Login|SignIn|SignInStart|Authenticate|ExternalLogin|Password|TwoFactor|SendCode|VerifyCode)
     |/Identity/Account/(?:Login|LoginWith2fa|LoginWithRecoveryCode)
     |/MFA/(?:AuthChoice|Verify|VerifyCode)
     |/connect/authorize[^\s'"]*
     |/connect/authorize/callback[^\s'"]*
     |/connect/token
     )
    """
)

def _mine_script_for_login_urls(sess: requests.Session, base_url: str, html: str, debug: bool=False) -> list[str]:
    """
    Fetch all <script src=...> files and mine them for likely login-related URLs.
    Return absolute URLs (deduped).
    """
    from bs4 import BeautifulSoup  # already imported above, but safe here

    def dbg(msg: str):
        if debug:
            print(f"[DEBUG] _mine_script_for_login_urls: {msg}")

    soup = BeautifulSoup(html, "html.parser")
    urls: list[str] = []

    # Collect script sources (ignore inline for now; we can scan inline text too)
    script_srcs = []
    for s in soup.find_all("script"):
        src = (s.get("src") or "").strip()
        if src:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base_url.rstrip("/") + src
            script_srcs.append(src)

    dbg(f"script srcs found: {len(script_srcs)}")

    # Fetch each script and mine for URL patterns
    seen = set()
    for s_url in script_srcs:
        try:
            r = sess.get(s_url, timeout=30)
            if r.status_code != 200 or not r.text:
                dbg(f"skip script {s_url} status={r.status_code}")
                continue
            for m in LOGIN_URL_PATTERNS.finditer(r.text):
                path = m.group(0)
                # absolutize to the auth domain
                if path.startswith("//"):
                    absu = "https:" + path
                elif path.startswith("/"):
                    absu = base_url.rstrip("/") + path
                elif path.startswith("http"):
                    absu = path
                else:
                    absu = base_url.rstrip("/") + "/" + path.lstrip("/")
                if absu not in seen:
                    seen.add(absu)
                    urls.append(absu)
        except Exception as e:
            dbg(f"script fetch error {s_url}: {e}")

    # Also scan inline scripts quickly
    for s in soup.find_all("script"):
        txt = s.string or ""
        if not txt:
            continue
        for m in LOGIN_URL_PATTERNS.finditer(txt):
            path = m.group(0)
            if path.startswith("//"):
                absu = "https:" + path
            elif path.startswith("/"):
                absu = base_url.rstrip("/") + path
            elif path.startswith("http"):
                absu = path
            else:
                absu = base_url.rstrip("/") + "/" + path.lstrip("/")
            if absu not in seen:
                seen.add(absu)
                urls.append(absu)

    dbg(f"mined login-ish urls: {urls[:5]}{' …' if len(urls)>5 else ''}")
    return urls

_STD_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

def _fetch_login_form_via_browser(login_url: str, *, debug: bool = False):
    """
    Headless Chromium pass to execute Akamai/BM + antiforgery JS and return:
      - final HTML (which contains <form id="frmSubmit">)
      - cookies to import into our requests.Session
    Requires: playwright  (pip install playwright && python -m playwright install chromium)
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise LoginFlowError(
            "Browser fallback requested but Playwright is not available. "
            "Install with: pip install playwright && python -m playwright install chromium"
        ) from e

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(
            user_agent=_STD_UA,
            java_script_enabled=True,
            viewport={"width": 1280, "height": 900},
        )
        page = ctx.new_page()

        # hit nelnet root + /account/login (same as our warmup)
        page.goto("https://nelnet.studentaid.gov/", wait_until="networkidle")
        page.goto("https://nelnet.studentaid.gov/account/login", wait_until="networkidle")

        # now the actual auth login URL
        page.goto(login_url, wait_until="networkidle")

        html = page.content()
        cookies = ctx.cookies()  # list of dicts
        if debug:
            print("[DEBUG] browser cookies:", sorted({c["name"] for c in cookies}))
            print("[DEBUG] page url:", page.url)
            print("[DEBUG] page html size:", len(html))

        ctx.close()
        browser.close()

    return html, cookies

def _import_browser_cookies(sess: requests.Session, cookies: list[dict]):
    """Copy Playwright cookies into our requests session."""
    for c in cookies:
        # Only bring over studentaid.gov cookies
        dom = c.get("domain") or ""
        if not dom or not dom.endswith("studentaid.gov"):
            continue
        sess.cookies.set(
            name=c["name"],
            value=c.get("value", ""),
            domain=dom,
            path=c.get("path", "/"),
        )


def _find_login_form(
    sess: requests.Session,
    auth_base: str,
    login_url: str,
    *,
    debug: bool = False,
) -> Tuple[str, BeautifulSoup]:
    """
    Returns (form_action_url, form_element).
    Handles iframe-hosted, nested iframes,
    script-built SPA pages, handler probes,
    and as last resort, a headless browser fetch.
    """
    def dbg(msg: str):
        if debug:
            print(f"[DEBUG] _find_login_form: {msg}")

    abs_login = _abs_url(auth_base, login_url)

    # 0) Warmup (root + /account/login)
    _akamai_warmup(sess, debug=debug)

    # 1) Try the main page
    r = sess.get(abs_login, headers={"User-Agent": _STD_UA}, timeout=30)
    dbg(f"GET {abs_login} -> {r.status_code}; len={len(r.text)}")
    if r.status_code != 200:
        raise LoginFlowError(f"GET login page failed: {r.status_code}")

    soup = BeautifulSoup(r.text, "html.parser")
    form_el = soup.find("form")
    if form_el:
        action = form_el.get("action") or r.url
        dbg(f"Found form on main page; action={action}")
        return _abs_url(auth_base, action), form_el

    # 2) Try iframes on the main page
    iframe_urls = _extract_iframe_srcs(auth_base, r.url, r.text)
    dbg(f"Iframes on main page: {iframe_urls}")
    for iframe_url in iframe_urls:
        ri = sess.get(iframe_url, headers={"User-Agent": _STD_UA}, timeout=30)
        dbg(f"GET iframe {iframe_url} -> {ri.status_code}")
        if ri.status_code != 200:
            continue
        soup_if = BeautifulSoup(ri.text, "html.parser")
        form_if = soup_if.find("form")
        if form_if:
            action_if = form_if.get("action") or ri.url
            dbg(f"Found form in iframe; action={action_if}")
            return _abs_url(auth_base, action_if), form_if

        nested_urls = _extract_iframe_srcs(auth_base, ri.url, ri.text)
        dbg(f"Nested iframes in {iframe_url}: {nested_urls}")
        for nested in nested_urls:
            rn = sess.get(nested, headers={"User-Agent": _STD_UA}, timeout=30)
            dbg(f"GET nested iframe {nested} -> {rn.status_code}")
            if rn.status_code != 200:
                continue
            soup_n = BeautifulSoup(rn.text, "html.parser")
            form_n = soup_n.find("form")
            if form_n:
                action_n = form_n.get("action") or rn.url
                dbg(f"Found form in nested iframe; action={action_n}")
                return _abs_url(auth_base, action_n), form_n

    # 3) Fallbacks: direct /Account/Login
    direct_login = f"{auth_base}/Account/Login"
    rd = sess.get(direct_login, headers={"User-Agent": _STD_UA}, timeout=30)
    dbg(f"GET {direct_login} -> {rd.status_code}")
    if rd.status_code == 200:
        soup_d = BeautifulSoup(rd.text, "html.parser")
        form_d = soup_d.find("form")
        if form_d:
            action_d = form_d.get("action") or rd.url
            dbg(f"Found form on /Account/Login; action={action_d}")
            return _abs_url(auth_base, action_d), form_d

    parsed = urlparse.urlparse(abs_login)
    q = urlparse.parse_qs(parsed.query)
    ret = (q.get("ReturnUrl") or [None])[0]
    if ret:
        rd2_url = f"{auth_base}/Account/Login?ReturnUrl={urlparse.quote(ret, safe='')}"
        rd2 = sess.get(rd2_url, headers={"User-Agent": _STD_UA}, timeout=30)
        dbg(f"GET {rd2_url} -> {rd2.status_code}")
        if rd2.status_code == 200:
            soup_d2 = BeautifulSoup(rd2.text, "html.parser")
            form_d2 = soup_d2.find("form")
            if form_d2:
                action_d2 = form_d2.get("action") or rd2.url
                dbg(f"Found form on /Account/Login?ReturnUrl; action={action_d2}")
                return _abs_url(auth_base, action_d2), form_d2

    # 4) Mine script files for login endpoints
    mined = _mine_script_for_login_urls(sess, auth_base, r.text, debug=debug)
    for candidate in mined:
        try:
            rx = sess.get(candidate, headers={"User-Agent": _STD_UA}, timeout=30)
            dbg(f"GET mined {candidate} -> {rx.status_code}")
            if rx.status_code != 200:
                continue
            soup_x = BeautifulSoup(rx.text, "html.parser")
            form_x = soup_x.find("form")
            if form_x:
                action_x = form_x.get("action") or rx.url
                dbg(f"Found form from mined URL; action={action_x}")
                return _abs_url(auth_base, action_x), form_x
        except Exception as e:
            dbg(f"fetch mined error {candidate}: {e}")

    # 5) Handler probes
    for probe in [
        f"{auth_base}/Account/Login?handler=SignIn",
        f"{auth_base}/Account/Login?handler=Login",
        f"{auth_base}/Account/SignInStart",
        f"{auth_base}/Account/SignIn",
        f"{auth_base}/Identity/Account/Login?handler=SignIn",
        f"{auth_base}/Identity/Account/Login",
        f"{auth_base}/Account/Login?handler=SignIn&ReturnUrl={urlparse.quote(ret, safe='') if ret else ''}",
        f"{auth_base}/Identity/Account/Login?handler=SignIn&ReturnUrl={urlparse.quote(ret, safe='') if ret else ''}",
    ]:
        try:
            rp = sess.get(probe, headers={"User-Agent": _STD_UA}, timeout=30)
            dbg(f"GET probe {probe} -> {rp.status_code}; len={len(rp.text)}")
            if rp.status_code == 200:
                soup_p = BeautifulSoup(rp.text, "html.parser")
                form_p = soup_p.find("form")
                if form_p:
                    action_p = form_p.get("action") or rp.url
                    dbg(f"Found form from probe; action={action_p}")
                    return _abs_url(auth_base, action_p), form_p
        except Exception as e:
            dbg(f"probe error {probe}: {e}")

    # 6) FINAL fallback: headless browser
    if debug:
        print("[DEBUG] Falling back to headless browser to fetch login form…")

    try:
        html, pw_cookies = _fetch_login_form_via_browser(abs_login, debug=debug)
        _import_browser_cookies(sess, pw_cookies)

        soup_b = BeautifulSoup(html, "html.parser")
        form_b = soup_b.find("form", id="frmSubmit") or soup_b.find("form")
        if form_b:
            action_b = form_b.get("action") or abs_login
            if debug:
                print(f"[DEBUG] Browser fallback found form; action={action_b}")
            return _abs_url(auth_base, action_b), form_b
    except Exception as e:
        if debug:
            print("[DEBUG] Browser fallback error:", repr(e))

    raise LoginFlowError(
        "Login page has no <form> element (after warmup, iframe, fallbacks, "
        "script-mining, handler probes, and browser fallback)"
    )

def _detect_username_password_fields(form_el) -> Tuple[Optional[str], Optional[str]]:
    """
    Try to detect username & password input names. If ambiguous, return None to fail fast.
    """
    username_field = None
    password_field = None

    for inp in form_el.find_all("input"):
        name = (inp.get("name") or "")
        itype = (inp.get("type") or "").lower()
        if not password_field and itype == "password":
            password_field = name
        if not username_field:
            if "email" in name.lower() or "user" in name.lower():
                username_field = name
            elif itype in ("email", "text"):
                username_field = name

    return username_field, password_field


def _csrf_headers(provider: str, sess: requests.Session, form_token: str | None = None) -> Dict[str, str]:
    """
    Build headers for form POSTs. If a hidden anti-forgery field value is known,
    send it in the RequestVerificationToken header (ASP.NET Core expects this).
    """
    headers = dict(_std_headers(provider))
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Prefer the hidden field's token if we have it; otherwise fall back to cookie.
    if form_token:
        headers["RequestVerificationToken"] = form_token
    else:
        cookie_val = (
            sess.cookies.get("__RequestVerificationToken")
            or sess.cookies.get(".AspNetCore.Antiforgery")  # some deployments shorten the name
        )
        if cookie_val:
            headers["RequestVerificationToken"] = cookie_val
    return headers


# =========================
# OAuth (PKCE) building blocks
# =========================
def build_authorize_url(cfg: ProviderConfig, code_challenge: str, state: str, nonce: str) -> Tuple[str, str]:
    """
    Returns (authorize_url, redirect_uri) with READ-ONLY scope.
    """
    redirect_uri = f"https://{cfg.provider}.studentaid.gov/auth/callback"
    params = {
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid offline_access mma.api.read",  # READ-ONLY
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "nonce": nonce,
    }
    return f"{cfg.auth_base}/connect/authorize?{urlparse.urlencode(params)}", redirect_uri


def start_authorization(sess: requests.Session, authorize_url: str) -> str:
    # make sure the next hop thinks we came from nelnet site
    # (sess.headers already has Referer/Origin from _std_headers)
    r = sess.get(authorize_url, allow_redirects=False, timeout=30)
    if r.status_code not in (302, 303):
        raise LoginFlowError(f"Unexpected status from /connect/authorize: {r.status_code}")
    loc = r.headers.get("Location")
    if not loc:
        raise LoginFlowError("No login redirect location from /connect/authorize")
    return loc


# =========================
# Login & MFA Steps
# =========================
def submit_login_form(
    sess: requests.Session,
    cfg,
    login_url: str,
    username: str,
    password: str,
    *,
    debug: bool = False,
):
    # Find the actual login form (handles iframes, probes, etc.)
    action, form_el = _find_login_form(sess, cfg.auth_base, login_url, debug=debug)

    # Collect *all* inputs exactly as presented
    form = _collect_form_inputs(form_el)

    # Detect the correct username/password field names
    uname_name, pwd_name = _detect_username_password_fields(form_el)
    if not uname_name or not pwd_name:
        raise LoginFlowError("Could not detect username/password field names on login form.")

    # Overwrite with our credentials while preserving any other fields (ReturnUrl, tokens, etc.)
    form[uname_name] = username
    form[pwd_name]  = password

    # Pull the anti-forgery hidden field value, if present, for the header
    soup = BeautifulSoup(str(form_el), "html.parser")
    hidden_anti = (
        _hidden(soup, "__RequestVerificationToken")
        or _hidden(soup, "RequestVerificationToken")
        or form.get("__RequestVerificationToken")
        or form.get("RequestVerificationToken")
        or ""
    )

    # Some sites require an explicit submit value; make sure one exists
    form.setdefault("submitValue", "login")

    headers = _csrf_headers(cfg.provider, sess, form_token=hidden_anti)
    headers.update({
        "Origin": f"https://{cfg.provider}.studentaid.gov",
        "Referer": action,
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })

    rp = sess.post(action, data=form, headers=headers, allow_redirects=False, timeout=30)
    if debug:
        print(f"[DEBUG] submit_login_form: POST {action} -> {rp.status_code} Location={rp.headers.get('Location')}")

    # A successful login will usually 302 to the MFA choice page
    if rp.status_code in (302, 303) and rp.headers.get("Location"):
        return urlparse.urljoin(action, rp.headers["Location"])

    # If we were kept on the same page (200), treat that as a failure with body for debugging
    raise LoginFlowError(f"Login POST failed: {rp.status_code} {rp.text[:400]}")


def choose_mfa_method(
    sess: requests.Session,
    cfg: ProviderConfig,
    mfa_choice_url: str,
    mfa_method: str,
    *,
    debug: bool = False,
) -> str:
    """
    GET MFA choice page, POST the chosen method (sms/email).
    Returns next redirect URL (absolute).
    """
    r = sess.get(mfa_choice_url, timeout=30)
    if r.status_code != 200:
        raise LoginFlowError(f"GET MFA choice failed: {r.status_code}")

    soup = BeautifulSoup(r.text, "html.parser")
    form_el = soup.find("form")
    if not form_el:
        raise LoginFlowError("MFA choice page missing form")

    # hidden fields present on the page (including anti-forgery)
    hidden = _parse_hidden_fields_from_html(str(form_el))
    form = dict(hidden)

    choice_map = {"sms": "0", "email": "1"}
    choice_val = choice_map.get(mfa_method.lower())
    if choice_val is None:
        raise LoginFlowError("mfa_method must be 'sms' or 'email'")
    form["AuthChoice"] = choice_val

    # include submit fields if any present
    for btn in form_el.find_all(["button", "input"]):
        itype = (btn.get("type") or "").lower()
        if itype == "submit":
            n = btn.get("name")
            v = btn.get("value") or "Submit"
            if n and n not in form:
                form[n] = v

    action = form_el.get("action") or r.url
    action = _abs_url(cfg.auth_base, action)

    headers = _csrf_headers(cfg.provider, sess)
    r = sess.post(action, data=form, headers=headers, allow_redirects=False, timeout=30)
    if r.status_code not in (302, 303):
        if debug:
            print("[DEBUG] MFA choice POST body (first 800 chars):\n", r.text[:800])
            print("[DEBUG] Sent fields:", sorted(form.keys()))
        raise LoginFlowError(f"POST MFA choice failed: {r.status_code}")

    nxt = r.headers.get("Location", "")
    return _abs_url(cfg.auth_base, nxt)


def verify_mfa_code(
    sess: requests.Session,
    cfg: ProviderConfig,
    verify_url: str,
    code: str,
    *,
    debug: bool = False,
) -> str:
    """
    GET MFA verify page, POST verification code.
    Returns next redirect URL (absolute).
    """
    r = sess.get(verify_url, timeout=30)
    if r.status_code != 200:
        raise LoginFlowError(f"GET MFA verify failed: {r.status_code}")

    soup = BeautifulSoup(r.text, "html.parser")
    form_el = soup.find("form")
    if not form_el:
        raise LoginFlowError("MFA verify page missing form")

    hidden = _parse_hidden_fields_from_html(str(form_el))
    form = dict(hidden)

    # field name from HAR; default to 'UserCode'
    form["UserCode"] = code
    form.setdefault("SaveTrustedDevice", "false")

    # include submit fields if present
    for btn in form_el.find_all(["button", "input"]):
        itype = (btn.get("type") or "").lower()
        if itype == "submit":
            n = btn.get("name")
            v = btn.get("value") or "Submit"
            if n and n not in form:
                form[n] = v

    action = form_el.get("action") or r.url
    action = _abs_url(cfg.auth_base, action)

    headers = _csrf_headers(cfg.provider, sess)
    r = sess.post(action, data=form, headers=headers, allow_redirects=False, timeout=30)
    if r.status_code not in (302, 303):
        if debug:
            print("[DEBUG] MFA verify POST body (first 800 chars):\n", r.text[:800])
            print("[DEBUG] Sent fields:", sorted(form.keys()))
        raise LoginFlowError(f"POST MFA verify failed: {r.status_code}")

    nxt = r.headers.get("Location", "")
    return _abs_url(cfg.auth_base, nxt)


def follow_redirects_for_code(
    sess: requests.Session,
    cfg: ProviderConfig,
    start_url: str,
    redirect_uri: str,
    max_hops: int = 12,
) -> str:
    """
    Follow 302/303s until we arrive at redirect_uri?code=...
    Returns the authorization code string.
    """
    cur = start_url
    for _ in range(max_hops):
        r = sess.get(cur, allow_redirects=False, timeout=30)
        loc = r.headers.get("Location", "")
        final = cur if not loc else _abs_url(cfg.auth_base, loc)

        if final.startswith(redirect_uri):
            parsed = urlparse.urlparse(final)
            q = urlparse.parse_qs(parsed.query)
            code_param = (q.get("code") or [None])[0]
            if not code_param:
                break
            return code_param

        cur = final
    raise LoginFlowError("Did not receive authorization code after MFA")


# =========================
# Token exchange & refresh
# =========================
def exchange_code_for_tokens(
    sess: requests.Session,
    cfg: ProviderConfig,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> Dict:
    """
    POST /connect/token with authorization_code + PKCE verifier.
    Some deployments are strict about Origin/Referer and explicit scope.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": f"https://{cfg.provider}.studentaid.gov",
        "Referer": f"https://{cfg.provider}.studentaid.gov/",
        "User-Agent": _std_headers(cfg.provider)["User-Agent"],
    }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,       # MUST exactly match the one used in /authorize
        "client_id": cfg.client_id,
        "code_verifier": code_verifier,     # PKCE
        "scope": "openid offline_access mma.api.read",  # harmless if ignored; fixes picky setups
    }
    tr = sess.post(cfg.token_url, headers=headers, data=data, timeout=30)
    if tr.status_code >= 400:
        raise LoginFlowError(f"Token exchange failed ({tr.status_code}): {tr.text[:400]}")
    tokens = tr.json()
    tokens.setdefault("token_type", "Bearer")
    tokens.setdefault("expires_in", 3600)
    tokens["obtained_at"] = int(time.time())
    return tokens


def refresh_tokens(cfg: ProviderConfig, refresh_token: str) -> Dict:
    """
    Refresh using read-only scope. Defensive if refresh_token is not rotated.
    """
    url = cfg.token_url
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": f"https://{cfg.provider}.studentaid.gov",
        "Referer": f"https://{cfg.provider}.studentaid.gov/",
        "User-Agent": _std_headers(cfg.provider)["User-Agent"],
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": cfg.client_id,
        "scope": "openid offline_access mma.api.read",  # READ-ONLY
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
            f"Run login_full() once to establish a token cache."
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


# =========================
# Full Login (creds + MFA)
# =========================
def login_full(
    provider: str,
    username: str,
    password: str,
    *,
    client_id: str = DEFAULT_CLIENT_ID,
    mfa_method: str = "sms",  # or "email"
    get_code: Optional[Callable[[str], str]] = None,
    debug: bool = False,
) -> Dict:
    """
    Full browser-equivalent login:
      - PKCE authorize (READ-ONLY scope)
      - Login form (iframe-aware) with anti-forgery
      - MFA choice + verify
      - Follow redirects to capture authorization code
      - Exchange for tokens
      - Persist token cache (~/.studentaid/tokens_<provider>.json)

    Returns tokens dict.
    """
    provider = provider.strip().lower()
    cfg = ProviderConfig(provider=provider, client_id=client_id)
    sess = requests.Session()
    sess.headers.update(_std_headers(cfg.provider))

    def dbg(msg: str):
        if debug:
            print(f"[DEBUG] {msg}")

    # PKCE
    code_verifier = _new_code_verifier()
    code_challenge = _code_challenge_s256(code_verifier)
    state = _b64url(secrets.token_bytes(16))
    nonce = _b64url(secrets.token_bytes(16))

    authorize_url, redirect_uri = build_authorize_url(cfg, code_challenge, state, nonce)
    login_url = start_authorization(sess, authorize_url)
    login_url = _abs_url(cfg.auth_base, login_url)
    dbg(f"Login URL: {login_url}")

    # Login
    nxt = submit_login_form(sess, cfg, login_url, username, password, debug=debug)
    dbg(f"After login redirect to: {nxt}")

    # MFA choice
    nxt = choose_mfa_method(sess, cfg, nxt, mfa_method=mfa_method, debug=debug)
    dbg(f"After MFA choice redirect to: {nxt}")

    # MFA code
    code_input = (get_code("Enter the MFA code you received: ") if get_code else input("Enter the MFA code you received: ")).strip()
    if not code_input:
        raise LoginFlowError("No MFA code provided")

    nxt = verify_mfa_code(sess, cfg, nxt, code_input, debug=debug)
    dbg(f"After MFA verify redirect to: {nxt}")

    # Follow redirects for authorization code
    auth_code = follow_redirects_for_code(sess, cfg, nxt, redirect_uri)
    dbg(f"Authorization code: {auth_code[:8]}…")

    # Token exchange
    tokens = exchange_code_for_tokens(sess, cfg, auth_code, code_verifier, redirect_uri)
    save_tokens(cfg.provider, tokens)
    return tokens