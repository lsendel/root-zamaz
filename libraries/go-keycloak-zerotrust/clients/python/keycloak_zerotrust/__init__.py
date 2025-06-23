"""
Keycloak Zero Trust Python Client Library

A comprehensive Python client for implementing Zero Trust authentication
with Keycloak, featuring device attestation, risk assessment, and
enterprise-grade security controls.

Example usage:
    >>> from keycloak_zerotrust import KeycloakZeroTrustClient, ZeroTrustConfig
    >>> 
    >>> config = ZeroTrustConfig(
    ...     base_url="https://keycloak.company.com",
    ...     realm="company",
    ...     client_id="api-service",
    ...     client_secret="secret"
    ... )
    >>> 
    >>> async with KeycloakZeroTrustClient(config) as client:
    ...     claims = await client.validate_token("Bearer jwt-token")
    ...     print(f"User: {claims.username}, Trust Level: {claims.trust_level}")
"""

__version__ = "1.0.0"
__author__ = "Zero Trust Team"
__email__ = "team@yourorg.com"

# Core exports
from .client import KeycloakZeroTrustClient
from .config import ZeroTrustConfig, CacheConfig, ZeroTrustSettings
from .models import (
    ZeroTrustClaims,
    AuthenticatedUser,
    UserInfo,
    TokenPair,
    UserRegistrationRequest,
    TrustLevelUpdateRequest,
    LocationInfo,
    ClientMetrics,
)
from .exceptions import (
    KeycloakZeroTrustError,
    AuthenticationError,
    ConfigurationError,
    ConnectionError,
    TrustLevelError,
    DeviceVerificationError,
)

# Framework integrations
try:
    from .integrations.fastapi import ZeroTrustMiddleware as FastAPIMiddleware
    __all_integrations__ = ["FastAPIMiddleware"]
except ImportError:
    __all_integrations__ = []

try:
    from .integrations.flask import ZeroTrustMiddleware as FlaskMiddleware
    __all_integrations__.append("FlaskMiddleware")
except ImportError:
    pass

try:
    from .integrations.django import ZeroTrustMiddleware as DjangoMiddleware
    __all_integrations__.append("DjangoMiddleware")
except ImportError:
    pass

try:
    from .integrations.starlette import ZeroTrustMiddleware as StarletteMiddleware
    __all_integrations__.append("StarletteMiddleware")
except ImportError:
    pass

__all__ = [
    # Core classes
    "KeycloakZeroTrustClient",
    "ZeroTrustConfig",
    "CacheConfig", 
    "ZeroTrustSettings",
    
    # Models
    "ZeroTrustClaims",
    "AuthenticatedUser",
    "UserInfo",
    "TokenPair",
    "UserRegistrationRequest",
    "TrustLevelUpdateRequest",
    "LocationInfo",
    "ClientMetrics",
    
    # Exceptions
    "KeycloakZeroTrustError",
    "AuthenticationError",
    "ConfigurationError",
    "ConnectionError",
    "TrustLevelError",
    "DeviceVerificationError",
    
    # Version info
    "__version__",
    "__author__",
    "__email__",
] + __all_integrations__