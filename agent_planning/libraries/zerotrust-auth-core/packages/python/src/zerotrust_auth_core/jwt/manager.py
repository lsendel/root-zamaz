"""JWT authentication services with Zero Trust principles."""

import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from uuid import uuid4

import jwt
from pydantic import BaseModel, Field, validator

from ..blacklist.blacklist import Blacklist, MemoryBlacklist


class JWTConfig(BaseModel):
    """JWT Manager configuration."""

    secret: str = Field(min_length=32)
    expiry_duration: timedelta = Field(default_factory=lambda: timedelta(minutes=30))
    refresh_duration: timedelta = Field(default_factory=lambda: timedelta(days=7))
    issuer: str
    rotation_duration: timedelta = Field(default_factory=lambda: timedelta(days=1))

    @validator("expiry_duration", "refresh_duration", "rotation_duration", pre=True)
    def parse_duration(cls, v):
        """Parse duration from various formats."""
        if isinstance(v, (int, float)):
            return timedelta(milliseconds=v)
        return v


class JWTClaims(BaseModel):
    """JWT claims with Zero Trust attributes."""

    user_id: str
    email: str
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    device_id: Optional[str] = None
    trust_level: int = Field(ge=0, le=100)
    iat: int
    exp: int
    iss: str
    sub: str
    jti: str
    nbf: Optional[int] = None


class Token(BaseModel):
    """Token response."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_at: datetime
    trust_level: int


class TokenRequest(BaseModel):
    """Token generation request."""

    user_id: str
    email: str
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    device_id: Optional[str] = None
    trust_level: int = Field(ge=0, le=100)


class JWTKey(BaseModel):
    """JWT signing key with metadata."""

    id: str
    key: str
    created_at: datetime
    expires_at: datetime
    is_active: bool


class JWTError(Exception):
    """Base JWT error."""

    def __init__(self, message: str, code: str):
        """Initialize JWT error."""
        super().__init__(message)
        self.code = code


class TokenBlacklistedError(JWTError):
    """Token has been blacklisted."""

    def __init__(self):
        """Initialize blacklisted error."""
        super().__init__("Token has been blacklisted", "TOKEN_BLACKLISTED")


class InvalidTokenError(JWTError):
    """Invalid token error."""

    def __init__(self, message: str = "Invalid token"):
        """Initialize invalid token error."""
        super().__init__(message, "INVALID_TOKEN")


class ExpiredTokenError(JWTError):
    """Token has expired."""

    def __init__(self):
        """Initialize expired token error."""
        super().__init__("Token has expired", "EXPIRED_TOKEN")


class TokenNotActiveError(JWTError):
    """Token not yet active."""

    def __init__(self):
        """Initialize not active error."""
        super().__init__("Token not yet active", "TOKEN_NOT_ACTIVE")


class KeyManager:
    """Key manager for JWT signing keys with rotation support."""

    def __init__(self, initial_secret: str, rotation_duration: timedelta):
        """Initialize key manager."""
        self.keys: Dict[str, JWTKey] = {}
        self.current_key_id: str
        self.rotation_duration = rotation_duration

        # Create initial key
        key_id = self._generate_key_id()
        now = datetime.now()

        key = JWTKey(
            id=key_id,
            key=initial_secret,
            created_at=now,
            expires_at=now + rotation_duration * 2,  # Allow overlap
            is_active=True,
        )

        self.keys[key_id] = key
        self.current_key_id = key_id

    def get_current_key(self) -> Optional[JWTKey]:
        """Get the current active signing key."""
        key = self.keys.get(self.current_key_id)
        return key if key and key.is_active else None

    def get_key(self, key_id: str) -> Optional[JWTKey]:
        """Get a specific key by ID for token validation."""
        return self.keys.get(key_id)

    def rotate_key(self) -> None:
        """Rotate the signing key."""
        # Generate new key
        new_key_bytes = self._generate_secure_key()
        new_key_id = self._generate_key_id()
        now = datetime.now()

        new_key = JWTKey(
            id=new_key_id,
            key=new_key_bytes,
            created_at=now,
            expires_at=now + self.rotation_duration * 2,
            is_active=True,
        )

        # Mark current key as inactive
        current_key = self.keys.get(self.current_key_id)
        if current_key:
            current_key.is_active = False

        # Add new key and update current
        self.keys[new_key_id] = new_key
        self.current_key_id = new_key_id

        # Clean up expired keys
        self._cleanup_expired_keys()

    def get_stats(self) -> Dict[str, Union[str, int]]:
        """Get key manager statistics."""
        now = datetime.now()
        active_keys = 0
        expired_keys = 0

        for key in self.keys.values():
            if key.is_active and now < key.expires_at:
                active_keys += 1
            elif now > key.expires_at:
                expired_keys += 1

        return {
            "total_keys": len(self.keys),
            "active_keys": active_keys,
            "expired_keys": expired_keys,
            "current_key_id": self.current_key_id,
            "rotation_period": f"{self.rotation_duration.total_seconds()}s",
        }

    def _generate_key_id(self) -> str:
        """Generate a unique key identifier."""
        return str(uuid4()).replace("-", "")[:16]

    def _generate_secure_key(self) -> str:
        """Generate a secure key."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(chars) for _ in range(64))

    def _cleanup_expired_keys(self) -> None:
        """Clean up expired keys."""
        now = datetime.now()
        expired_keys = [
            key_id
            for key_id, key in self.keys.items()
            if now > key.expires_at and key_id != self.current_key_id
        ]

        for key_id in expired_keys:
            del self.keys[key_id]


class JWTManager:
    """JWT Manager with Zero Trust capabilities."""

    def __init__(self, config: JWTConfig):
        """Initialize JWT manager."""
        self._validate_config(config)
        self.config = config
        self.key_manager = KeyManager(config.secret, config.rotation_duration)
        self.blacklist: Blacklist = MemoryBlacklist()  # Default implementation

    async def generate_token(self, request: TokenRequest) -> Token:
        """Generate a new JWT token with trust level."""
        self._validate_token_request(request)

        now = datetime.now()
        expires_at = now + self.config.expiry_duration
        jti = str(uuid4())

        claims = JWTClaims(
            user_id=request.user_id,
            email=request.email,
            roles=request.roles,
            permissions=request.permissions,
            device_id=request.device_id,
            trust_level=request.trust_level,
            iat=int(now.timestamp()),
            exp=int(expires_at.timestamp()),
            iss=self.config.issuer,
            sub=request.user_id,
            jti=jti,
            nbf=int(now.timestamp()),
        )

        # Get current signing key
        current_key = self.key_manager.get_current_key()
        if not current_key:
            raise ValueError("No active signing key available")

        # Create token with key ID in header
        token = jwt.encode(
            claims.dict(),
            current_key.key,
            algorithm="HS256",
            headers={"kid": current_key.id},
        )

        # Generate refresh token
        refresh_token = await self._generate_refresh_token(request.user_id)

        return Token(
            access_token=token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            trust_level=request.trust_level,
        )

    async def validate_token(self, token_string: str) -> JWTClaims:
        """Validate a JWT token and return claims."""
        if not token_string:
            raise InvalidTokenError()

        # Check blacklist first
        blacklisted = await self.blacklist.is_blacklisted(token_string)
        if blacklisted:
            raise TokenBlacklistedError()

        try:
            # Decode header to get key ID
            unverified_header = jwt.get_unverified_header(token_string)
            kid = unverified_header.get("kid")

            # Get signing key
            signing_key = None
            if kid:
                key = self.key_manager.get_key(kid)
                if key:
                    signing_key = key.key

            # Fallback to current key for tokens without key ID
            if not signing_key:
                current_key = self.key_manager.get_current_key()
                if current_key:
                    signing_key = current_key.key

            if not signing_key:
                raise ValueError("No valid signing key found")

            # Decode and validate token
            payload = jwt.decode(
                token_string,
                signing_key,
                algorithms=["HS256"],
                issuer=self.config.issuer,
            )

            return JWTClaims(**payload)

        except jwt.ExpiredSignatureError:
            raise ExpiredTokenError()
        except jwt.ImmatureSignatureError:
            raise TokenNotActiveError()
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Token validation failed: {e}")
        except Exception as e:
            raise InvalidTokenError(f"Token validation failed: {e}")

    async def blacklist_token(self, token_string: str, reason: str) -> None:
        """Blacklist a token."""
        if not token_string:
            raise ValueError("Token string cannot be empty")
        if not reason:
            raise ValueError("Reason cannot be empty")

        try:
            # Extract JTI and expiration from token for efficient blacklisting
            payload = jwt.decode(token_string, options={"verify_signature": False})

            jti = payload.get("jti")
            exp = payload.get("exp")

            if not jti:
                raise ValueError("Token missing JTI claim")

            expires_at = datetime.fromtimestamp(exp)
            await self.blacklist.add(jti, reason, expires_at)

        except Exception as e:
            raise ValueError(f"Failed to blacklist token: {e}")

    async def refresh_token(self, refresh_token: str, request: TokenRequest) -> Token:
        """Refresh a token using a valid refresh token."""
        try:
            current_key = self.key_manager.get_current_key()
            if not current_key:
                raise ValueError("No active signing key available")

            payload = jwt.decode(
                refresh_token, current_key.key, algorithms=["HS256"]
            )

            if payload.get("type") != "refresh":
                raise ValueError("Not a refresh token")

            if payload.get("user_id") != request.user_id:
                raise ValueError("User ID mismatch")

            # Generate new access token
            return await self.generate_token(request)

        except Exception as e:
            raise ValueError(f"Invalid refresh token: {e}")

    def set_blacklist(self, blacklist: Blacklist) -> None:
        """Set the blacklist implementation."""
        self.blacklist = blacklist

    def get_config(self) -> Dict[str, Union[str, int]]:
        """Get configuration (without secrets)."""
        return {
            "expiry_duration": int(self.config.expiry_duration.total_seconds() * 1000),
            "refresh_duration": int(self.config.refresh_duration.total_seconds() * 1000),
            "issuer": self.config.issuer,
            "rotation_duration": int(
                self.config.rotation_duration.total_seconds() * 1000
            ),
        }

    def _validate_config(self, config: JWTConfig) -> None:
        """Validate JWT configuration."""
        if not config:
            raise ValueError("Config cannot be None")
        if len(config.secret) < 32:
            raise ValueError("JWT secret must be at least 32 characters")
        if config.expiry_duration.total_seconds() <= 0:
            raise ValueError("Expiry duration must be positive")
        if config.refresh_duration.total_seconds() <= 0:
            raise ValueError("Refresh duration must be positive")
        if not config.issuer:
            raise ValueError("Issuer cannot be empty")

    def _validate_token_request(self, request: TokenRequest) -> None:
        """Validate token generation request."""
        if not request:
            raise ValueError("Token request cannot be None")
        if not request.user_id:
            raise ValueError("User ID cannot be empty")
        if not request.email:
            raise ValueError("Email cannot be empty")
        if not (0 <= request.trust_level <= 100):
            raise ValueError("Trust level must be between 0 and 100")

    async def _generate_refresh_token(self, user_id: str) -> str:
        """Generate a refresh token."""
        now = datetime.now()
        expires_at = now + self.config.refresh_duration

        claims = {
            "user_id": user_id,
            "type": "refresh",
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "jti": str(uuid4()),
        }

        current_key = self.key_manager.get_current_key()
        if not current_key:
            raise ValueError("No active signing key available")

        return jwt.encode(claims, current_key.key, algorithm="HS256")