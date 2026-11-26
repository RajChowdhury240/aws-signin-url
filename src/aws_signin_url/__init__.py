"""Turn AWS credentials into an AWS Management Console sign-in URL."""

__version__ = "0.1.0"

from .core import SigninError, SigninResult, generate_login_url  # noqa: E402

__all__ = ["generate_login_url", "SigninError", "SigninResult", "__version__"]
