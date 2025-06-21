"""
Zero Trust Auth SDK for Python

A comprehensive Python SDK for integrating with the MVP Zero Trust Authentication system.
"""

from .client import (
    ZeroTrustClient,
    ZeroTrustAPIError,
    ZeroTrustUtils,
    AuthenticationRequest,
    TokenValidationRequest,
    RefreshTokenRequest,
    LogoutRequest,
    AuthenticationResponse,
    TokenValidationResponse,
    User,
    Claims,
)

__version__ = "1.0.0"
__author__ = "MVP Team"
__email__ = "team@mvp.com"

__all__ = [
    "ZeroTrustClient",
    "ZeroTrustAPIError",
    "ZeroTrustUtils",
    "AuthenticationRequest",
    "TokenValidationRequest",
    "RefreshTokenRequest",
    "LogoutRequest",
    "AuthenticationResponse",
    "TokenValidationResponse",
    "User",
    "Claims",
]
