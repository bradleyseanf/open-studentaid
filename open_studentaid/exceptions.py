"""Public exceptions shared by all student-loan providers."""


class TokenMissingError(RuntimeError):
    """Raised when a provider needs a saved authentication session."""


class RefreshFailedError(RuntimeError):
    """Raised when a saved provider session can no longer be reused."""


class LoginFlowError(RuntimeError):
    """Raised when an interactive provider login cannot complete."""
