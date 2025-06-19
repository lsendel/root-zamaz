"""
Zero Trust Auth SDK for Python

A comprehensive Python SDK for integrating with the MVP Zero Trust Authentication system.
Provides a simple, typed interface for authentication, token management, and user operations.

Example usage:
    >>> from zerotrust_sdk import ZeroTrustClient
    >>> 
    >>> client = ZeroTrustClient(
    ...     base_url="https://auth.example.com",
    ...     api_key="your-api-key"
    ... )
    >>> 
    >>> # Authenticate user
    >>> response = client.authenticate(
    ...     email="user@example.com",
    ...     password="password123"
    ... )
    >>> 
    >>> # Validate token
    >>> validation = client.validate_token(response.access_token)
"""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ZeroTrustAPIError(Exception):
    """Exception raised for API errors from the Zero Trust Auth service."""
    
    def __init__(
        self,
        code: str,
        message: str,
        details: Optional[str] = None,
        trace_id: Optional[str] = None
    ):
        self.code = code
        self.message = message
        self.details = details
        self.trace_id = trace_id
        super().__init__(f"{code}: {message}")


class AuthenticationRequest:
    """Request object for user authentication."""
    
    def __init__(
        self,
        email: str,
        password: str,
        mfa: Optional[str] = None,
        remember: bool = False
    ):
        self.email = email
        self.password = password
        self.mfa = mfa
        self.remember = remember
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "email": self.email,
            "password": self.password,
            "remember": self.remember
        }
        if self.mfa:
            data["mfa"] = self.mfa
        return data


class TokenValidationRequest:
    """Request object for token validation."""
    
    def __init__(
        self,
        token: str,
        audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None
    ):
        self.token = token
        self.audience = audience
        self.required_scopes = required_scopes or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {"token": self.token}
        if self.audience:
            data["audience"] = self.audience
        if self.required_scopes:
            data["required_scopes"] = self.required_scopes
        return data


class RefreshTokenRequest:
    """Request object for token refresh."""
    
    def __init__(self, refresh_token: str):
        self.refresh_token = refresh_token
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {"refresh_token": self.refresh_token}


class LogoutRequest:
    """Request object for user logout."""
    
    def __init__(
        self,
        token: Optional[str] = None,
        session_id: Optional[str] = None,
        everywhere: bool = False
    ):
        self.token = token
        self.session_id = session_id
        self.everywhere = everywhere
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {"everywhere": self.everywhere}
        if self.token:
            data["token"] = self.token
        if self.session_id:
            data["session_id"] = self.session_id
        return data


class User:
    """User object representing a user in the system."""
    
    def __init__(self, data: Dict[str, Any]):
        self.id = data.get("id")
        self.email = data.get("email")
        self.first_name = data.get("first_name")
        self.last_name = data.get("last_name")
        self.display_name = data.get("display_name")
        self.avatar = data.get("avatar")
        self.roles = data.get("roles", [])
        self.permissions = data.get("permissions", [])
        self.trust_score = data.get("trust_score", 0.0)
        self.last_login_at = data.get("last_login_at")
        self.created_at = data.get("created_at")
        self.updated_at = data.get("updated_at")
        self.is_active = data.get("is_active", False)
        self.is_verified = data.get("is_verified", False)
        self.mfa_enabled = data.get("mfa_enabled", False)
        self.metadata = data.get("metadata", {})


class Claims:
    """JWT token claims object."""
    
    def __init__(self, data: Dict[str, Any]):
        self.subject = data.get("sub")
        self.audience = data.get("aud", [])
        self.issuer = data.get("iss")
        self.expires_at = data.get("exp")
        self.issued_at = data.get("iat")
        self.not_before = data.get("nbf")
        self.jti = data.get("jti")
        self.email = data.get("email")
        self.roles = data.get("roles", [])
        self.permissions = data.get("permissions", [])
        self.trust_score = data.get("trust_score", 0.0)
        self.session_id = data.get("session_id")
        self.custom = data.get("custom", {})


class AuthenticationResponse:
    """Response object from user authentication."""
    
    def __init__(self, data: Dict[str, Any]):
        self.access_token = data.get("access_token")
        self.refresh_token = data.get("refresh_token")
        self.token_type = data.get("token_type")
        self.expires_in = data.get("expires_in")
        self.expires_at = data.get("expires_at")
        self.scope = data.get("scope")
        self.requires_mfa = data.get("requires_mfa", False)
        self.mfa_challenge = data.get("mfa_challenge")
        self.partial_token = data.get("partial_token")
        self.user = User(data.get("user", {})) if data.get("user") else None
        self.session_id = data.get("session_id")
        self.trust_score = data.get("trust_score", 0.0)
        self.risk_factors = data.get("risk_factors", [])
        self.recommended_actions = data.get("recommended_actions", [])


class TokenValidationResponse:
    """Response object from token validation."""
    
    def __init__(self, data: Dict[str, Any]):
        self.valid = data.get("valid", False)
        self.claims = Claims(data.get("claims", {})) if data.get("claims") else None
        self.expires_at = data.get("expires_at")
        self.issued_at = data.get("issued_at")
        self.trust_score = data.get("trust_score", 0.0)
        self.permissions = data.get("permissions", [])
        self.roles = data.get("roles", [])
        self.metadata = data.get("metadata", {})


class ZeroTrustClient:
    """
    Zero Trust Auth SDK client for Python.
    
    Provides methods for authentication, token management, and user operations
    with the MVP Zero Trust Authentication system.
    """
    
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        debug: bool = False
    ):
        """
        Initialize the Zero Trust client.
        
        Args:
            base_url: Base URL of the Zero Trust Auth service
            api_key: API key for authenticating SDK requests
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retry attempts in seconds
            debug: Enable debug logging
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.debug = debug
        
        # Create session with retry strategy
        self.session = requests.Session()
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "MVP-ZeroTrust-SDK/1.0.0 (Python)",
            "X-API-Key": self.api_key
        })
    
    def authenticate(
        self,
        email: str,
        password: str,
        mfa: Optional[str] = None,
        remember: bool = False
    ) -> AuthenticationResponse:
        """
        Authenticate a user with email and password.
        
        Args:
            email: User's email address
            password: User's password
            mfa: MFA code (if required)
            remember: Whether to remember the login
            
        Returns:
            AuthenticationResponse object
            
        Raises:
            ZeroTrustAPIError: If authentication fails
        """
        request = AuthenticationRequest(email, password, mfa, remember)
        data = self._make_request("POST", "/api/v1/auth/login", request.to_dict())
        return AuthenticationResponse(data)
    
    def validate_token(
        self,
        token: str,
        audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None
    ) -> TokenValidationResponse:
        """
        Validate an access token.
        
        Args:
            token: Access token to validate
            audience: Required audience for the token
            required_scopes: Required scopes for the token
            
        Returns:
            TokenValidationResponse object
            
        Raises:
            ZeroTrustAPIError: If validation fails
        """
        request = TokenValidationRequest(token, audience, required_scopes)
        data = self._make_request("POST", "/api/v1/auth/validate", request.to_dict())
        return TokenValidationResponse(data)
    
    def refresh_token(self, refresh_token: str) -> AuthenticationResponse:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            AuthenticationResponse object with new tokens
            
        Raises:
            ZeroTrustAPIError: If refresh fails
        """
        request = RefreshTokenRequest(refresh_token)
        data = self._make_request("POST", "/api/v1/auth/refresh", request.to_dict())
        return AuthenticationResponse(data)
    
    def logout(
        self,
        token: Optional[str] = None,
        session_id: Optional[str] = None,
        everywhere: bool = False
    ) -> None:
        """
        Logout a user session.
        
        Args:
            token: Access token to logout
            session_id: Session ID to logout
            everywhere: Whether to logout from all sessions
            
        Raises:
            ZeroTrustAPIError: If logout fails
        """
        request = LogoutRequest(token, session_id, everywhere)
        self._make_request("POST", "/api/v1/auth/logout", request.to_dict())
    
    def get_user_profile(self, token: str) -> User:
        """
        Get the current user's profile.
        
        Args:
            token: Access token
            
        Returns:
            User object
            
        Raises:
            ZeroTrustAPIError: If request fails
        """
        data = self._make_request_with_auth("GET", "/api/v1/user/profile", None, token)
        return User(data)
    
    def update_user_profile(self, token: str, user_data: Dict[str, Any]) -> User:
        """
        Update the current user's profile.
        
        Args:
            token: Access token
            user_data: User data to update
            
        Returns:
            Updated User object
            
        Raises:
            ZeroTrustAPIError: If request fails
        """
        data = self._make_request_with_auth("PUT", "/api/v1/user/profile", user_data, token)
        return User(data)
    
    def health_check(self) -> None:
        """
        Check the health of the Zero Trust Auth service.
        
        Raises:
            ZeroTrustAPIError: If health check fails
        """
        url = urljoin(self.base_url, "/health")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            raise ZeroTrustAPIError("HEALTH_CHECK_FAILED", f"Health check failed: {e}")
    
    def set_debug(self, debug: bool) -> None:
        """Enable or disable debug logging."""
        self.debug = debug
    
    def get_config(self) -> Dict[str, Any]:
        """Get the current client configuration."""
        return {
            "base_url": self.base_url,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "debug": self.debug
        }
    
    def _make_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make a request to the API without authentication."""
        return self._make_request_with_auth(method, path, data)
    
    def _make_request_with_auth(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make a request to the API with optional authentication."""
        url = urljoin(self.base_url, path)
        
        headers = {
            "X-Request-ID": str(uuid.uuid4())
        }
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        if self.debug:
            print(f"SDK Request: {method} {url}")
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                headers=headers,
                timeout=self.timeout
            )
            
            if self.debug:
                print(f"SDK Response: {response.status_code} {response.text}")
            
            # Handle error responses
            if not response.ok:
                try:
                    error_data = response.json()
                    raise ZeroTrustAPIError(
                        error_data.get("code", "UNKNOWN_ERROR"),
                        error_data.get("message", "An unknown error occurred"),
                        error_data.get("details"),
                        error_data.get("trace_id")
                    )
                except json.JSONDecodeError:
                    raise ZeroTrustAPIError(
                        "HTTP_ERROR",
                        f"HTTP {response.status_code}: {response.text}"
                    )
            
            # Parse successful response
            if response.content:
                try:
                    return response.json()
                except json.JSONDecodeError as e:
                    raise ZeroTrustAPIError("PARSE_ERROR", f"Failed to parse response: {e}")
            
            return {}
            
        except requests.RequestException as e:
            raise ZeroTrustAPIError("REQUEST_FAILED", f"Request failed: {e}")
    
    def close(self) -> None:
        """Close the client and clean up resources."""
        if self.session:
            self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class ZeroTrustUtils:
    """Utility functions for common operations."""
    
    @staticmethod
    def is_token_expired(expires_at: Union[str, datetime, int]) -> bool:
        """
        Check if a token is expired based on expiration time.
        
        Args:
            expires_at: Token expiration time (ISO string, datetime, or timestamp)
            
        Returns:
            True if token is expired, False otherwise
        """
        if isinstance(expires_at, str):
            expiry = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        elif isinstance(expires_at, int):
            expiry = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        else:
            expiry = expires_at
        
        return datetime.now(timezone.utc) > expiry
    
    @staticmethod
    def is_token_expiring_soon(
        expires_at: Union[str, datetime, int],
        threshold_seconds: int
    ) -> bool:
        """
        Check if a token will expire within the specified duration.
        
        Args:
            expires_at: Token expiration time
            threshold_seconds: Threshold in seconds
            
        Returns:
            True if token is expiring soon, False otherwise
        """
        if isinstance(expires_at, str):
            expiry = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        elif isinstance(expires_at, int):
            expiry = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        else:
            expiry = expires_at
        
        threshold_time = datetime.now(timezone.utc).timestamp() + threshold_seconds
        return expiry.timestamp() < threshold_time
    
    @staticmethod
    def sanitize_email(email: str) -> str:
        """Sanitize an email address."""
        return email.lower().strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate an email address."""
        sanitized = ZeroTrustUtils.sanitize_email(email)
        parts = sanitized.split("@")
        return len(parts) == 2 and len(parts[0]) > 0 and len(parts[1]) > 0 and "." in parts[1]
    
    @staticmethod
    def is_authentication_error(error: Exception) -> bool:
        """Check if an error is an authentication error."""
        if isinstance(error, ZeroTrustAPIError):
            code = error.code.lower()
            return "auth" in code or "token" in code or "unauthorized" in code
        return False
    
    @staticmethod
    def is_retryable_error(error: Exception) -> bool:
        """Check if an error is retryable."""
        if isinstance(error, ZeroTrustAPIError):
            return error.code in ["RATE_LIMITED"] or \
                   "timeout" in error.code.lower() or \
                   "network" in error.code.lower()
        return True