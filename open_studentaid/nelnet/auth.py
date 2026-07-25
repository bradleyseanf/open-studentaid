"""Nelnet-specific login behavior."""

from ..exceptions import LoginFlowError


def login_url(provider: str = "nelnet") -> str:
    return f"https://{provider}.studentaid.gov/account/login"


def validate_username(username: str) -> None:
    if "@" in username:
        raise LoginFlowError(
            "Nelnet requires the account username, not an email address. "
            "No login request was sent."
        )
