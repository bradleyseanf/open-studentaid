from __future__ import annotations
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

DEFAULT_PROVIDER = os.getenv("STUDENT_AID_PROVIDER", "nelnet").strip().lower()
DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "mma")

@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    client_id: str = DEFAULT_CLIENT_ID

    @property
    def auth_base(self) -> str:
        return f"https://auth.{self.provider}.studentaid.gov"

    @property
    def token_url(self) -> str:
        return f"{self.auth_base}/connect/token"

    @property
    def api_base(self) -> str:
        return f"https://mmaapi.{self.provider}.studentaid.gov"

    # well-known paths we’ll use first
    @property
    def borrower_details_path(self) -> str:
        return "/api/1/borrower/details"
