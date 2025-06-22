"""Trust level calculation for Zero Trust authentication."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Dict, List, Optional, Protocol

from pydantic import BaseModel, Field, validator


class TrustLevel(IntEnum):
    """Trust levels in Zero Trust architecture."""

    NONE = 0  # Untrusted - failed authentication, suspicious activity
    LOW = 25  # Basic authentication - new devices, minimal verification
    MEDIUM = 50  # Known device - standard authentication with known device
    HIGH = 75  # Verified device + location - trusted environment
    FULL = 100  # Hardware attestation - TPM, secure enclave, biometrics

    def __str__(self) -> str:
        """Return string representation of trust level."""
        return self.name.title()

    @classmethod
    def from_value(cls, value: int) -> "TrustLevel":
        """Create trust level from integer value."""
        if value >= 100:
            return cls.FULL
        elif value >= 75:
            return cls.HIGH
        elif value >= 50:
            return cls.MEDIUM
        elif value >= 25:
            return cls.LOW
        else:
            return cls.NONE

    def meets_requirement(self, required: "TrustLevel") -> bool:
        """Check if this trust level meets the required minimum."""
        return self.value >= required.value


class Location(BaseModel):
    """Geographic location for trust calculation."""

    country: str
    region: str
    city: str
    latitude: float
    longitude: float
    ip_address: str


class TrustFactors(BaseModel):
    """Factors used in trust calculation."""

    device_verified: bool = False
    location_verified: bool = False
    behavior_normal: bool = True
    recent_activity: bool = False
    hardware_attestation: bool = False
    biometric_verified: bool = False
    network_trusted: bool = False
    session_age: Optional[datetime] = None
    previous_trust_level: TrustLevel = TrustLevel.NONE


class CalculationRequest(BaseModel):
    """Trust calculation request."""

    user_id: str
    device_id: Optional[str] = None
    location: Optional[Location] = None
    action: Optional[str] = None
    last_activity: datetime
    session_start: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    factors: Optional[TrustFactors] = None


class DeviceHistory(BaseModel):
    """Device history information."""

    first_seen: datetime
    last_seen: datetime
    login_count: int
    failure_count: int
    is_trusted: bool
    risk_score: int = Field(ge=0, le=100)
    platform: str
    user_agent: str
    last_trust_level: TrustLevel


class BehaviorAnalysis(BaseModel):
    """Behavior analysis results."""

    is_suspicious: bool
    anomaly_score: float = Field(ge=0.0, le=1.0)
    typical_login_times: List[int] = Field(default_factory=list)  # Hours of day
    typical_locations: List[str] = Field(default_factory=list)
    unusual_activity: List[str] = Field(default_factory=list)
    last_analyzed: datetime
    confidence_score: float = Field(ge=0.0, le=1.0)


class CalculatorConfig(BaseModel):
    """Configuration for trust calculation."""

    base_score: int = 10
    device_weight: int = 25
    location_weight: int = 20
    behavior_weight: int = 15
    activity_weight: int = 10
    hardware_weight: int = 15
    biometric_weight: int = 10
    network_weight: int = 5
    max_inactivity_duration: timedelta = Field(default_factory=lambda: timedelta(minutes=30))
    suspicious_activity_penalty: int = 50
    new_device_penalty: int = 15

    @validator("max_inactivity_duration", pre=True)
    def parse_duration(cls, v):
        """Parse duration from various formats."""
        if isinstance(v, int):
            return timedelta(milliseconds=v)
        return v


class DeviceService(Protocol):
    """Device service interface for device verification."""

    async def verify_device(self, device_id: str) -> bool:
        """Verify device authenticity."""
        ...

    async def get_device_history(self, device_id: str) -> Optional[DeviceHistory]:
        """Get device history information."""
        ...

    async def check_hardware_attestation(self, device_id: str) -> bool:
        """Check hardware attestation status."""
        ...

    async def is_device_trusted(self, device_id: str) -> bool:
        """Check if device is trusted."""
        ...

    async def mark_device_as_trusted(self, device_id: str) -> None:
        """Mark device as trusted."""
        ...


class BehaviorService(Protocol):
    """Behavior service interface for behavior analysis."""

    async def analyze_behavior(self, user_id: str, action: str) -> BehaviorAnalysis:
        """Analyze user behavior."""
        ...

    async def is_action_suspicious(self, user_id: str, action: str) -> bool:
        """Check if action is suspicious."""
        ...

    async def update_behavior_profile(
        self, user_id: str, action: str, timestamp: datetime
    ) -> None:
        """Update behavior profile."""
        ...

    async def get_typical_patterns(self, user_id: str) -> BehaviorAnalysis:
        """Get typical behavior patterns."""
        ...


class LocationService(Protocol):
    """Location service interface for location verification."""

    async def verify_location(self, user_id: str, location: Location) -> bool:
        """Verify location authenticity."""
        ...

    async def is_location_trusted(self, location: Location) -> bool:
        """Check if location is trusted."""
        ...

    async def get_location_from_ip(self, ip_address: str) -> Optional[Location]:
        """Get location from IP address."""
        ...

    async def add_trusted_location(self, user_id: str, location: Location) -> None:
        """Add trusted location."""
        ...


class TrustCalculator:
    """Trust level calculator."""

    def __init__(
        self,
        device_service: Optional[DeviceService] = None,
        behavior_service: Optional[BehaviorService] = None,
        location_service: Optional[LocationService] = None,
        config: Optional[CalculatorConfig] = None,
    ):
        """Initialize trust calculator."""
        self.device_service = device_service
        self.behavior_service = behavior_service
        self.location_service = location_service
        self.config = config or CalculatorConfig()

    def calculate(self, factors: TrustFactors) -> TrustLevel:
        """Calculate trust level based on provided factors."""
        score = self.config.base_score

        # Device verification
        if factors.device_verified:
            score += self.config.device_weight
        else:
            score -= self.config.new_device_penalty

        # Location verification
        if factors.location_verified:
            score += self.config.location_weight

        # Behavior analysis
        if factors.behavior_normal:
            score += self.config.behavior_weight
        else:
            score -= self.config.suspicious_activity_penalty

        # Recent activity
        if factors.recent_activity:
            score += self.config.activity_weight

        # Hardware attestation (high security feature)
        if factors.hardware_attestation:
            score += self.config.hardware_weight

        # Biometric verification
        if factors.biometric_verified:
            score += self.config.biometric_weight

        # Trusted network
        if factors.network_trusted:
            score += self.config.network_weight

        # Session age consideration
        if factors.session_age:
            session_duration = datetime.now() - factors.session_age
            if session_duration > timedelta(hours=4):
                score -= 10  # Reduce trust for very old sessions
            elif session_duration > timedelta(hours=8):
                score -= 20  # Significant reduction for very stale sessions

        # Consider previous trust level for gradual changes
        if factors.previous_trust_level > TrustLevel.NONE:
            # Smooth trust level changes to avoid dramatic swings
            previous_score = factors.previous_trust_level.value
            if abs(score - previous_score) > 25:
                # Limit trust level changes to 25 points per calculation
                if score > previous_score:
                    score = previous_score + 25
                else:
                    score = previous_score - 25

        # Ensure score is within bounds
        score = max(0, min(100, score))

        return TrustLevel.from_value(score)

    async def calculate_for_user(self, request: CalculationRequest) -> TrustLevel:
        """Perform comprehensive trust calculation for a user."""
        factors = TrustFactors()

        # Use provided factors if available
        if request.factors:
            factors = request.factors.copy()

        # Device verification
        if request.device_id and self.device_service:
            try:
                factors.device_verified = await self.device_service.verify_device(
                    request.device_id
                )

                if factors.device_verified:
                    # Check hardware attestation
                    try:
                        factors.hardware_attestation = (
                            await self.device_service.check_hardware_attestation(
                                request.device_id
                            )
                        )
                    except Exception:
                        # Non-critical, continue if it fails
                        pass

                # Get device history for additional context
                try:
                    history = await self.device_service.get_device_history(
                        request.device_id
                    )
                    if history:
                        if history.is_trusted and history.failure_count < 3:
                            factors.device_verified = True
                        factors.previous_trust_level = history.last_trust_level
                except Exception:
                    # Non-critical
                    pass

            except Exception as e:
                raise ValueError(f"Device verification failed: {e}")

        # Location verification
        if request.location and self.location_service:
            try:
                factors.location_verified = (
                    await self.location_service.verify_location(
                        request.user_id, request.location
                    )
                )

                # Check if location is on trusted network
                try:
                    factors.network_trusted = (
                        await self.location_service.is_location_trusted(request.location)
                    )
                except Exception:
                    # Non-critical
                    pass

            except Exception as e:
                raise ValueError(f"Location verification failed: {e}")

        elif request.ip_address and self.location_service:
            # Derive location from IP address
            try:
                location = await self.location_service.get_location_from_ip(
                    request.ip_address
                )
                if location:
                    factors.location_verified = (
                        await self.location_service.verify_location(
                            request.user_id, location
                        )
                    )
                    factors.network_trusted = (
                        await self.location_service.is_location_trusted(location)
                    )
            except Exception:
                # Non-critical
                pass

        # Behavior analysis
        if request.action and self.behavior_service:
            try:
                suspicious = await self.behavior_service.is_action_suspicious(
                    request.user_id, request.action
                )
                factors.behavior_normal = not suspicious

                # Update behavior profile for future analysis
                await self.behavior_service.update_behavior_profile(
                    request.user_id, request.action, request.last_activity
                )

            except Exception as e:
                raise ValueError(f"Behavior analysis failed: {e}")

        # Recent activity check
        time_since_activity = datetime.now() - request.last_activity
        factors.recent_activity = time_since_activity < self.config.max_inactivity_duration

        # Session age
        factors.session_age = request.session_start

        return self.calculate(factors)

    async def calculate_for_authentication(
        self,
        user_id: str,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> TrustLevel:
        """Calculate trust level during authentication."""
        now = datetime.now()
        request = CalculationRequest(
            user_id=user_id,
            device_id=device_id,
            ip_address=ip_address,
            last_activity=now,
            session_start=now,
            action="login",
        )

        return await self.calculate_for_user(request)

    @staticmethod
    def get_trust_level_for_operation(operation: str) -> TrustLevel:
        """Get required trust level for different operations."""
        operation_mapping = {
            # Low trust operations
            "login": TrustLevel.LOW,
            "read_profile": TrustLevel.LOW,
            "view_dashboard": TrustLevel.LOW,
            # Medium trust operations
            "update_profile": TrustLevel.MEDIUM,
            "create_resource": TrustLevel.MEDIUM,
            "view_reports": TrustLevel.MEDIUM,
            # High trust operations
            "delete_resource": TrustLevel.HIGH,
            "admin_action": TrustLevel.HIGH,
            "financial_transaction": TrustLevel.HIGH,
            # Full trust operations
            "system_admin": TrustLevel.FULL,
            "security_settings": TrustLevel.FULL,
            "user_management": TrustLevel.FULL,
        }
        
        return operation_mapping.get(operation, TrustLevel.MEDIUM)

    @staticmethod
    def validate_factors(factors: TrustFactors) -> None:
        """Validate trust calculation factors."""
        # Check for logical inconsistencies
        if factors.hardware_attestation and not factors.device_verified:
            raise ValueError("Hardware attestation requires device verification")

        if factors.biometric_verified and not factors.device_verified:
            raise ValueError("Biometric verification requires device verification")

    @staticmethod
    def require_trust_level(required: TrustLevel):
        """Create a requirement checker for a minimum trust level."""
        def checker(actual: TrustLevel) -> bool:
            return actual.meets_requirement(required)
        return checker


def default_calculator_config() -> CalculatorConfig:
    """Get default calculator configuration."""
    return CalculatorConfig()