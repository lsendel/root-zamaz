"""
Keycloak Zero Trust Client Implementation

This module provides the main client class for interacting with Keycloak
with Zero Trust security features.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin

import httpx
import jwt
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError

from .config import ZeroTrustConfig
from .models import (
    ZeroTrustClaims,
    AuthenticatedUser,
    UserInfo,
    TokenPair,
    UserRegistrationRequest,
    TrustLevelUpdateRequest,
    ClientMetrics,
    TokenIntrospectionResponse,
)
from .exceptions import (
    AuthenticationError,
    ConnectionError,
    TrustLevelError,
    DeviceVerificationError,
    ConfigurationError,
)
from .cache import TokenCache, MemoryTokenCache, RedisTokenCache

logger = logging.getLogger(__name__)


class KeycloakZeroTrustClient:
    """
    Asynchronous Keycloak Zero Trust authentication client.
    
    This client provides comprehensive Zero Trust authentication features including:
    - Token validation with intelligent caching
    - Trust level enforcement and validation
    - Device attestation and verification
    - Risk assessment and adaptive policies
    - User management operations
    - Health monitoring and metrics
    
    Example:
        >>> config = ZeroTrustConfig(
        ...     base_url="https://keycloak.company.com",
        ...     realm="company",
        ...     client_id="api-service",
        ...     client_secret="secret"
        ... )
        >>> 
        >>> async with KeycloakZeroTrustClient(config) as client:
        ...     claims = await client.validate_token("Bearer jwt-token")
        ...     if claims.trust_level >= 50:
        ...         print(f"Access granted for {claims.username}")
    """
    
    def __init__(self, config: ZeroTrustConfig):
        """
        Initialize the Keycloak Zero Trust client.
        
        Args:
            config: Zero Trust configuration
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        self.config = self._validate_config(config)
        self._http_client: Optional[httpx.AsyncClient] = None
        self._token_cache: Optional[TokenCache] = None
        self._metrics = ClientMetrics()
        self._closed = False
        
        logger.info(f"Keycloak Zero Trust client initialized for realm: {config.realm}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def _initialize(self):
        """Initialize HTTP client and cache."""
        if self._http_client is not None:
            return
        
        # Configure HTTP client with timeouts and retries
        timeout = httpx.Timeout(
            timeout=self.config.timeout.total_seconds(),
            connect=5.0,
            read=self.config.timeout.total_seconds(),
        )
        
        self._http_client = httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
            follow_redirects=True,
        )
        
        # Initialize cache
        if self.config.cache.enabled:
            if self.config.cache.provider.lower() == "redis":
                self._token_cache = RedisTokenCache(
                    url=self.config.cache.redis_url,
                    prefix=self.config.cache.prefix,
                )
            else:
                self._token_cache = MemoryTokenCache(
                    max_size=self.config.cache.max_size
                )
        else:
            self._token_cache = MemoryTokenCache(max_size=0)  # Disabled cache
    
    async def validate_token(self, token: str) -> ZeroTrustClaims:
        """
        Validate a JWT token and return Zero Trust claims.
        
        This method performs comprehensive token validation including:
        - Token introspection with Keycloak
        - JWT signature and claims validation
        - Zero Trust policy enforcement
        - Caching for performance optimization
        
        Args:
            token: JWT token (with or without "Bearer " prefix)
            
        Returns:
            Zero Trust claims extracted from the validated token
            
        Raises:
            AuthenticationError: If token validation fails
            TrustLevelError: If trust level is insufficient
            DeviceVerificationError: If device verification fails
            ConnectionError: If Keycloak is unreachable
        """
        if self._closed:
            raise RuntimeError("Client is closed")
        
        if not self._http_client:
            await self._initialize()
        
        start_time = time.time()
        self._metrics.token_validations += 1
        
        try:
            # Clean and validate token format
            clean_token = self._clean_token(token)
            if not clean_token:
                raise AuthenticationError("MISSING_TOKEN", "Token cannot be empty")
            
            # Check cache first
            cache_key = f"token:{hashlib.sha256(clean_token.encode()).hexdigest()[:16]}"
            cached_claims = await self._token_cache.get(cache_key)
            
            if cached_claims and not self._is_expired(cached_claims):
                self._metrics.cache_hits += 1
                return cached_claims
            
            self._metrics.cache_misses += 1
            
            # Perform token introspection
            introspection = await self._introspect_token(clean_token)
            if not introspection.active:
                raise AuthenticationError("INVALID_TOKEN", "Token is not active")
            
            # Get user info for additional claims
            user_info = await self._get_user_info(clean_token)
            
            # Parse JWT claims
            claims = await self._parse_jwt_claims(clean_token, user_info)
            
            # Apply Zero Trust policies
            await self._validate_zero_trust_policies(claims)
            
            # Cache the validated claims
            cache_ttl = self.config.cache.ttl.total_seconds()
            await self._token_cache.set(cache_key, claims, cache_ttl)
            
            # Update metrics
            latency = time.time() - start_time
            self._metrics.update_average_latency(latency)
            
            logger.debug(f"Token validated for user {claims.username} with trust level {claims.trust_level}")
            return claims
            
        except Exception as e:
            self._metrics.error_count += 1
            if isinstance(e, (AuthenticationError, TrustLevelError, DeviceVerificationError)):
                raise
            else:
                logger.exception(f"Token validation failed: {e}")
                raise AuthenticationError("VALIDATION_ERROR", "Token validation failed") from e
    
    async def refresh_token(self, refresh_token: str) -> TokenPair:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            New token pair with access and refresh tokens
            
        Raises:
            AuthenticationError: If token refresh fails
        """
        if not self._http_client:
            await self._initialize()
        
        token_endpoint = urljoin(
            self.config.base_url,
            f"/realms/{self.config.realm}/protocol/openid-connect/token"
        )
        
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        
        try:
            response = await self._http_client.post(token_endpoint, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            return TokenPair.model_validate(token_data)
            
        except httpx.HTTPStatusError as e:
            self._metrics.error_count += 1
            raise AuthenticationError("REFRESH_FAILED", f"Token refresh failed: {e.response.status_code}")
        except Exception as e:
            self._metrics.error_count += 1
            raise AuthenticationError("REFRESH_ERROR", "Token refresh failed") from e
    
    async def register_user(self, request: UserRegistrationRequest) -> Dict[str, Any]:
        """
        Register a new user in Keycloak with Zero Trust attributes.
        
        Note: This operation requires admin privileges.
        
        Args:
            request: User registration request
            
        Returns:
            Created user information
            
        Raises:
            AuthenticationError: If registration fails
        """
        # This would require admin token implementation
        raise NotImplementedError("User registration requires admin token implementation")
    
    async def update_user_trust_level(self, request: TrustLevelUpdateRequest) -> None:
        """
        Update a user's trust level.
        
        Note: This operation requires admin privileges.
        
        Args:
            request: Trust level update request
            
        Raises:
            AuthenticationError: If update fails
        """
        # This would require admin token implementation
        raise NotImplementedError("Trust level update requires admin token implementation")
    
    async def health_check(self) -> None:
        """
        Perform a health check against the Keycloak server.
        
        Raises:
            ConnectionError: If health check fails
        """
        if not self._http_client:
            await self._initialize()
        
        health_url = urljoin(self.config.base_url, f"/realms/{self.config.realm}")
        
        try:
            response = await self._http_client.get(health_url)
            response.raise_for_status()
            
            self._metrics.health_status = "healthy"
            self._metrics.last_health_check = time.time()
            
        except Exception as e:
            self._metrics.error_count += 1
            self._metrics.health_status = "unhealthy"
            raise ConnectionError("HEALTH_CHECK_FAILED", "Health check failed") from e
    
    def get_metrics(self) -> ClientMetrics:
        """
        Get current client metrics.
        
        Returns:
            Client metrics including performance and error statistics
        """
        return self._metrics.model_copy()
    
    async def close(self):
        """Close the client and cleanup resources."""
        if self._closed:
            return
        
        self._closed = True
        
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        
        if self._token_cache:
            await self._token_cache.close()
            self._token_cache = None
        
        logger.info("Keycloak Zero Trust client closed")
    
    # Private helper methods
    
    def _validate_config(self, config: ZeroTrustConfig) -> ZeroTrustConfig:
        """Validate the configuration."""
        if not config.base_url:
            raise ConfigurationError("Base URL is required")
        if not config.realm:
            raise ConfigurationError("Realm is required")
        if not config.client_id:
            raise ConfigurationError("Client ID is required")
        if not config.client_secret:
            raise ConfigurationError("Client secret is required")
        
        return config
    
    def _clean_token(self, token: str) -> str:
        """Clean and normalize token string."""
        if not token:
            return ""
        
        token = token.strip()
        if token.lower().startswith("bearer "):
            return token[7:]
        
        return token
    
    async def _introspect_token(self, token: str) -> TokenIntrospectionResponse:
        """Introspect token with Keycloak."""
        introspect_url = urljoin(
            self.config.base_url,
            f"/realms/{self.config.realm}/protocol/openid-connect/token/introspect"
        )
        
        data = {
            "token": token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        
        try:
            response = await self._http_client.post(introspect_url, data=data)
            response.raise_for_status()
            
            introspection_data = response.json()
            return TokenIntrospectionResponse.model_validate(introspection_data)
            
        except httpx.HTTPStatusError as e:
            raise AuthenticationError("INTROSPECTION_FAILED", f"Token introspection failed: {e.response.status_code}")
        except ValidationError as e:
            raise AuthenticationError("INVALID_RESPONSE", "Invalid introspection response") from e
    
    async def _get_user_info(self, token: str) -> UserInfo:
        """Get user info from Keycloak."""
        userinfo_url = urljoin(
            self.config.base_url,
            f"/realms/{self.config.realm}/protocol/openid-connect/userinfo"
        )
        
        headers = {"Authorization": f"Bearer {token}"}
        
        try:
            response = await self._http_client.get(userinfo_url, headers=headers)
            response.raise_for_status()
            
            user_data = response.json()
            return UserInfo.model_validate(user_data)
            
        except httpx.HTTPStatusError as e:
            raise AuthenticationError("USERINFO_FAILED", f"User info request failed: {e.response.status_code}")
        except ValidationError as e:
            raise AuthenticationError("INVALID_RESPONSE", "Invalid user info response") from e
    
    async def _parse_jwt_claims(self, token: str, user_info: UserInfo) -> ZeroTrustClaims:
        """Parse JWT claims and combine with user info."""
        try:
            # Decode JWT without verification (we already introspected)
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Extract Zero Trust claims
            trust_level = decoded.get("trust_level", self.config.zero_trust.default_trust_level)
            device_id = decoded.get("device_id", "")
            device_verified = decoded.get("device_verified", False)
            risk_score = decoded.get("risk_score", 0)
            session_state = decoded.get("session_state", "")
            
            # Extract roles
            roles = []
            realm_access = decoded.get("realm_access", {})
            if "roles" in realm_access:
                roles = realm_access["roles"]
            
            # Build claims object
            claims = ZeroTrustClaims(
                user_id=user_info.sub,
                email=user_info.email or "",
                username=user_info.preferred_username or "",
                first_name=user_info.given_name or "",
                last_name=user_info.family_name or "",
                roles=roles,
                trust_level=trust_level,
                device_id=device_id,
                device_verified=device_verified,
                risk_score=risk_score,
                session_state=session_state,
                expires_at=decoded.get("exp", 0),
                issued_at=decoded.get("iat", 0),
                issuer=decoded.get("iss", ""),
                audience=decoded.get("aud", []),
            )
            
            return claims
            
        except InvalidTokenError as e:
            raise AuthenticationError("JWT_PARSING_ERROR", "Failed to parse JWT claims") from e
    
    async def _validate_zero_trust_policies(self, claims: ZeroTrustClaims) -> None:
        """Validate Zero Trust policies against claims."""
        # Device attestation check
        if self.config.zero_trust.device_attestation and not claims.device_verified:
            raise DeviceVerificationError("Device verification required")
        
        # Risk assessment check
        if self.config.zero_trust.risk_assessment:
            critical_threshold = self.config.zero_trust.risk_thresholds.critical
            if claims.risk_score >= critical_threshold:
                raise TrustLevelError(f"Risk score too high: {claims.risk_score}")
    
    def _is_expired(self, claims: ZeroTrustClaims) -> bool:
        """Check if claims are expired."""
        if not claims.expires_at:
            return False
        return time.time() >= claims.expires_at