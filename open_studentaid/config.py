# config.py
"""
Configuration and environment defaults for open_studentaid.

This file defines ProviderConfig — a lightweight container for provider-specific
OAuth and API endpoints.  It automatically reads defaults from environment
variables, supports dynamic API-base overrides discovered at runtime, and
exposes the standard StudentAid endpoints for convenience.

Environment variables
---------------------
STUDENT_AID_PROVIDER : str   # default provider, e.g. "nelnet" or "cri"
CLIENT_ID            : str   # default OAuth client ID, usually "mma"
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables from a .env file if present
load_dotenv()

# Default fallbacks
DEFAULT_PROVIDER = os.getenv("STUDENT_AID_PROVIDER", "nelnet").strip().lower()
DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "mma")


@dataclass(frozen=True)
class ProviderConfig:
    """
    Holds per-provider endpoints used by the authentication and API layers.
    """

    provider: str
    client_id: str = DEFAULT_CLIENT_ID
    # allow runtime override for API base if discovered dynamically
    _api_base_override: str | None = field(default=None, compare=False)

    # -------------------- OAuth endpoints -------------------- #

    @property
    def auth_base(self) -> str:
        """Base URL for authorization endpoints."""
        return f"https://auth.{self.provider}.studentaid.gov"

    @property
    def token_url(self) -> str:
        """Full URL to the OAuth token endpoint."""
        return f"{self.auth_base}/connect/token"

    # -------------------- API endpoints ---------------------- #

    @property
    def api_base(self) -> str:
        """
        API base URL used for borrower endpoints.
        If runtime discovery provides an override, that is used instead.
        """
        return self._api_base_override or f"https://mmaapi.{self.provider}.studentaid.gov"

    def with_api_base(self, api_base: str) -> "ProviderConfig":
        """Return a copy of this ProviderConfig with a new API base URL."""
        return type(self)(
            provider=self.provider,
            client_id=self.client_id,
            _api_base_override=api_base,
        )

    # -------------------- Standard paths ---------------------- #

    @property
    def borrower_details_path(self) -> str:
        """Relative path for borrower-details API endpoint."""
        return "/api/1/borrower/details"


__all__ = [
    "ProviderConfig",
    "DEFAULT_PROVIDER",
    "DEFAULT_CLIENT_ID",
]
