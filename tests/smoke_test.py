"""Interactive smoke test for a real provider login and loan snapshot."""

from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from open_studentaid import loan_snapshot, login, save_session
from open_studentaid.openstudentaid import LoginFlowError


def _yes_no(prompt: str, *, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def main() -> int:
    provider = input("Provider [nelnet]: ").strip().lower() or "nelnet"
    username = input("Username (not email): ").strip()
    if provider == "nelnet" and "@" in username:
        print("No login attempted: Nelnet usernames cannot be email addresses.")
        return 2
    password = getpass.getpass("Password: ")
    mfa_method = input("MFA method [sms/email/authenticator] (default sms): ").strip().lower() or "sms"
    if mfa_method not in {"sms", "email", "authenticator"}:
        print("MFA method must be sms, email, or authenticator.")
        return 2
    trusted_device = _yes_no("Remember this device", default=True)
    should_save_session = _yes_no("Save the browser session locally", default=True)

    try:
        login(
            provider=provider,
            username=username,
            password=password,
            mfa_method=mfa_method,
            trusted_device=trusted_device,
            save_session=False,
            background=True,
            get_code=lambda prompt: input(prompt),
        )
        session_path = save_session(provider=provider) if should_save_session else None
        snapshot = loan_snapshot(provider=provider)
        snapshot.pop("raw", None)
        print(json.dumps({"session": str(session_path) if session_path else None, **snapshot}, indent=2, default=str))
        return 0
    except LoginFlowError as exc:
        print(f"Smoke test failed: {exc}")
        return 1
    except Exception as exc:
        print(f"Smoke test failed while reading loan data: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
