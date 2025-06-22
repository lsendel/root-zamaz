"""
Zero Trust Authentication Core Library - Python Implementation

Description: Multi-language authentication library implementing Zero Trust security principles
Version: 1.0.0
License: MIT
"""

from .blacklist.blacklist import (
    Blacklist,
    BlacklistEntry,
    BlacklistStats,
    HybridBlacklist,
    MemoryBlacklist,
    RedisBlacklist,
    RedisClient,
)
from .jwt.manager import (
    ExpiredTokenError,
    InvalidTokenError,
    JWTClaims,
    JWTConfig,
    JWTError,
    JWTKey,
    JWTManager,
    KeyManager,
    Token,
    TokenBlacklistedError,
    TokenNotActiveError,
    TokenRequest,
)
from .trust.calculator import (
    BehaviorAnalysis,
    BehaviorService,
    CalculationRequest,
    CalculatorConfig,
    DeviceHistory,
    DeviceService,
    Location,
    LocationService,
    TrustCalculator,
    TrustFactors,
    TrustLevel,
    default_calculator_config,
)

__version__ = "1.0.0"
__all__ = [
    # Version
    "__version__",
    # JWT Management
    "JWTManager",
    "KeyManager",
    "JWTConfig",
    "JWTClaims",
    "Token",
    "TokenRequest",
    "JWTKey",
    "JWTError",
    "TokenBlacklistedError",
    "InvalidTokenError",
    "ExpiredTokenError",
    "TokenNotActiveError",
    # Trust Level Calculation
    "TrustLevel",
    "TrustFactors",
    "Location",
    "CalculationRequest",
    "DeviceHistory",
    "BehaviorAnalysis",
    "CalculatorConfig",
    "DeviceService",
    "BehaviorService",
    "LocationService",
    "TrustCalculator",
    "default_calculator_config",
    # Token Blacklisting
    "Blacklist",
    "BlacklistEntry",
    "BlacklistStats",
    "MemoryBlacklist",
    "RedisClient",
    "RedisBlacklist",
    "HybridBlacklist",
    # Convenience functions
    "create_default_jwt_config",
    "create_jwt_manager",
    "create_trust_calculator",
    "requires_trust_level",
    "check_trust_level",
]


def create_default_jwt_config(**kwargs) -> JWTConfig:
    """Create default JWT configuration with optional overrides."""
    import os
    from datetime import timedelta
    
    defaults = {
        "secret": os.getenv("JWT_SECRET", "your-secret-key-32-characters-long"),
        "expiry_duration": timedelta(minutes=30),
        "refresh_duration": timedelta(days=7),
        "issuer": "zerotrust-auth-core",
        "rotation_duration": timedelta(days=1),
    }
    defaults.update(kwargs)
    return JWTConfig(**defaults)


def create_jwt_manager(config: JWTConfig = None) -> JWTManager:
    """Create JWT Manager with sensible defaults."""
    if config is None:
        config = create_default_jwt_config()
    return JWTManager(config)


def create_trust_calculator(
    device_service: DeviceService = None,
    behavior_service: BehaviorService = None,
    location_service: LocationService = None,
    config: CalculatorConfig = None,
) -> TrustCalculator:
    """Create Trust Calculator with default services."""
    return TrustCalculator(device_service, behavior_service, location_service, config)


def requires_trust_level(operation: str) -> TrustLevel:
    """Get required trust level for an operation."""
    return TrustCalculator.get_trust_level_for_operation(operation)


def check_trust_level(actual: TrustLevel, required: TrustLevel) -> bool:
    """Check if trust level meets requirement."""
    return actual.meets_requirement(required)