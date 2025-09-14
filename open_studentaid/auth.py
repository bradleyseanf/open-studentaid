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


def _std_headers(provider: str) -> Dict[str, str]:
    # Keep these browser-like to avoid WAF heuristics
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Referer": f"https://{provider}.studentaid.gov/",
        "Origin": f"https://{provider}.studentaid.gov",
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


def _find_login_form(
    sess: requests.Session,
    auth_base: str,
    login_url: str,
    *,
    debug: bool = False,
) -> Tuple[str, BeautifulSoup]:
    """
    Returns (form_action_url, form_element). Handles iframe-hosted, nested iframes,
    AND script-built SPA pages by mining script files for login endpoints.
    """
    def dbg(msg: str):
        if debug:
            print(f"[DEBUG] _find_login_form: {msg}")

    abs_login = _abs_url(auth_base, login_url)

    # 1) Try the main page
    r = sess.get(abs_login, timeout=30)
    dbg(f"GET {abs_login} -> {r.status_code}")
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
        ri = sess.get(iframe_url, timeout=30)
        dbg(f"GET iframe {iframe_url} -> {ri.status_code}")
        if ri.status_code != 200:
            continue
        soup_if = BeautifulSoup(ri.text, "html.parser")
        form_if = soup_if.find("form")
        if form_if:
            action_if = form_if.get("action") or ri.url
            dbg(f"Found form in iframe; action={action_if}")
            return _abs_url(auth_base, action_if), form_if

        # nested iframes inside this iframe
        nested_urls = _extract_iframe_srcs(auth_base, ri.url, ri.text)
        dbg(f"Nested iframes in {iframe_url}: {nested_urls}")
        for nested in nested_urls:
            rn = sess.get(nested, timeout=30)
            dbg(f"GET nested iframe {nested} -> {rn.status_code}")
            if rn.status_code != 200:
                continue
            soup_n = BeautifulSoup(rn.text, "html.parser")
            form_n = soup_n.find("form")
            if form_n:
                action_n = form_n.get("action") or rn.url
                dbg(f"Found form in nested iframe; action={action_n}")
                return _abs_url(auth_base, action_n), form_n

    # 3) Fallbacks: direct Account/Login (without/with ReturnUrl)
    direct_login = f"{auth_base}/Account/Login"
    rd = sess.get(direct_login, timeout=30)
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
        rd2 = sess.get(rd2_url, timeout=30)
        dbg(f"GET {rd2_url} -> {rd2.status_code}")
        if rd2.status_code == 200:
            soup_d2 = BeautifulSoup(rd2.text, "html.parser")
            form_d2 = soup_d2.find("form")
            if form_d2:
                action_d2 = form_d2.get("action") or rd2.url
                dbg(f"Found form on /Account/Login?ReturnUrl; action={action_d2}")
                return _abs_url(auth_base, action_d2), form_d2

    # 4) NEW: mine script files for login endpoints (SPA/JS-built)
    mined = _mine_script_for_login_urls(sess, auth_base, r.text, debug=debug)
    for candidate in mined:
        try:
            rx = sess.get(candidate, timeout=30)
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

    if debug:
        print("[DEBUG] No <form> found. First 1000 chars of main page:\n", r.text[:1000])

    raise LoginFlowError("Login page has no <form> element (after iframe, fallbacks, and script-mining)")


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


def _csrf_headers(provider: str, sess: requests.Session) -> Dict[str, str]:
    """
    IdentityServer/ASP.NET often uses both a hidden field and a cookie for anti-forgery.
    If a __RequestVerificationToken cookie exists, also send it as a header.
    """
    headers = dict(_std_headers(provider))
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    csrf_cookie = sess.cookies.get("__RequestVerificationToken")
    if csrf_cookie:
        headers.setdefault("RequestVerificationToken", csrf_cookie)
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
    """
    Start OAuth: expect 302 to /Account/Login?ReturnUrl=...
    Returns absolute login URL.
    """
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
    cfg: ProviderConfig,
    login_url: str,
    username: str,
    password: str,
    *,
    debug: bool = False,
) -> str:
    """
    Fetch the login page (or its iframe), scrape inputs, fill creds, POST form.
    Returns next redirect URL (absolute).
    """
    abs_login = _abs_url(cfg.auth_base, login_url)
    action, form_el = _find_login_form(sess, cfg.auth_base, abs_login, debug=debug)

    form_data = _collect_form_inputs(form_el)

    user_field, pass_field = _detect_username_password_fields(form_el)
    if not user_field or not pass_field:
        if debug:
            print("[DEBUG] Login inputs found:", sorted(form_data.keys()))
        raise LoginFlowError("Could not detect username/password fields on login form")

    form_data[user_field] = username
    form_data[pass_field] = password
    if "RememberLogin" in form_data and not form_data["RememberLogin"]:
        form_data["RememberLogin"] = "false"

    headers = _csrf_headers(cfg.provider, sess)
    r = sess.post(action, data=form_data, headers=headers, allow_redirects=False, timeout=30)
    if r.status_code not in (302, 303):
        if debug:
            print("[DEBUG] Login POST failed. Response (first 800 chars):\n", r.text[:800])
            print("[DEBUG] Posted fields:", sorted(form_data.keys()))
            print("[DEBUG] Posted to:", action)
        raise LoginFlowError(f"POST login failed: {r.status_code}")

    nxt = r.headers.get("Location", "")
    if not nxt:
        raise LoginFlowError("No redirect after login")
    return _abs_url(cfg.auth_base, nxt)


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
        "redirect_uri": redirect_uri,
        "client_id": cfg.client_id,
        "code_verifier": code_verifier,
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
# Orchestrator: Full Login (creds + MFA)
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
