# Python SDK for MVP Zero Trust Authentication

The Python SDK provides a comprehensive, type-hinted interface for integrating with the MVP Zero Trust Authentication system. It works with Python 3.8+ and includes support for popular frameworks like FastAPI, Django, and Flask.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Token Management](#token-management)
- [User Management](#user-management)
- [FastAPI Integration](#fastapi-integration)
- [Django Integration](#django-integration)
- [Flask Integration](#flask-integration)
- [Async Support](#async-support)
- [Error Handling](#error-handling)
- [Utilities](#utilities)
- [API Reference](#api-reference)

## Installation

### PyPI

```bash
pip install zerotrust-sdk
```

### Poetry

```bash
poetry add zerotrust-sdk
```

### Development Installation

```bash
git clone https://github.com/mvp/zerotrust-auth.git
cd zerotrust-auth/sdk/python
pip install -e .
```

## Quick Start

### Basic Client Setup

```python
from zerotrust_sdk import ZeroTrustClient

# Initialize the client
client = ZeroTrustClient(
    base_url="https://auth.example.com",
    api_key="your-api-key",
    timeout=30,
    debug=True
)

# Test connection
try:
    client.health_check()
    print("✅ Connected to Zero Trust Auth service!")
except Exception as error:
    print(f"❌ Connection failed: {error}")

# Always close the client when done
client.close()
```

### Context Manager Usage

```python
from zerotrust_sdk import ZeroTrustClient

# Recommended: Use context manager for automatic cleanup
with ZeroTrustClient(
    base_url="https://auth.example.com",
    api_key="your-api-key"
) as client:
    # Test connection
    client.health_check()
    print("✅ Connected to Zero Trust Auth service!")
    
    # Your code here...
    
# Client is automatically closed
```

## Authentication

### User Login

```python
from zerotrust_sdk import ZeroTrustClient, AuthenticationRequest

def authenticate_user(email: str, password: str):
    with ZeroTrustClient(
        base_url="https://auth.example.com",
        api_key="your-api-key"
    ) as client:
        try:
            response = client.authenticate(
                email=email,
                password=password,
                remember=True
            )
            
            if response.requires_mfa:
                print(f"MFA required: {response.mfa_challenge}")
                # Handle MFA flow here
                return {"requires_mfa": True, "challenge": response.mfa_challenge}
            
            print("✅ Authentication successful!")
            print(f"Access Token: {response.access_token}")
            print(f"User: {response.user.display_name} ({response.user.email})")
            print(f"Trust Score: {response.trust_score}")
            print(f"Expires At: {response.expires_at}")
            
            return response
            
        except Exception as error:
            print(f"❌ Authentication failed: {error}")
            raise

# Usage
result = authenticate_user("user@example.com", "secure-password")
```

### Token Validation

```python
def validate_token(client: ZeroTrustClient, token: str) -> bool:
    try:
        response = client.validate_token(
            token=token,
            required_scopes=["read:profile", "write:profile"],
            audience="api.example.com"
        )
        
        if not response.valid:
            print("❌ Token is invalid")
            return False
        
        print("✅ Token is valid!")
        print(f"User ID: {response.claims.subject}")
        print(f"Email: {response.claims.email}")
        print(f"Roles: {response.claims.roles}")
        print(f"Trust Score: {response.trust_score}")
        
        return True
        
    except Exception as error:
        print(f"Token validation error: {error}")
        return False
```

### Token Refresh

```python
def refresh_access_token(client: ZeroTrustClient, refresh_token: str):
    try:
        response = client.refresh_token(refresh_token)
        
        print("✅ Token refreshed successfully!")
        print(f"New Access Token: {response.access_token}")
        print(f"Expires At: {response.expires_at}")
        
        return response
        
    except Exception as error:
        print(f"❌ Token refresh failed: {error}")
        raise
```

### Logout

```python
def logout_user(client: ZeroTrustClient, token: str = None):
    try:
        client.logout(
            token=token,
            everywhere=True  # Logout from all devices
        )
        print("✅ Logged out successfully")
        
    except Exception as error:
        print(f"Logout error: {error}")
```

## Token Management

### Token Manager Class

```python
import time
from datetime import datetime, timezone
from typing import Optional
from zerotrust_sdk import ZeroTrustClient, ZeroTrustUtils

class TokenManager:
    def __init__(self, client: ZeroTrustClient):
        self.client = client
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._expires_at: Optional[datetime] = None
    
    def set_tokens(self, access_token: str, refresh_token: str, expires_at: str):
        """Store tokens securely."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
    
    def get_valid_token(self) -> Optional[str]:
        """Get a valid access token, refreshing if necessary."""
        if not self._access_token or not self._expires_at:
            return None
        
        # Check if token is expiring soon (within 5 minutes)
        if ZeroTrustUtils.is_token_expiring_soon(self._expires_at, 300):
            if not self._refresh_token:
                return None
            
            try:
                response = self.client.refresh_token(self._refresh_token)
                self.set_tokens(
                    response.access_token,
                    response.refresh_token,
                    response.expires_at
                )
                return response.access_token
                
            except Exception as error:
                print(f"Token refresh failed: {error}")
                self.clear_tokens()
                return None
        
        return self._access_token
    
    def clear_tokens(self):
        """Clear stored tokens."""
        self._access_token = None
        self._refresh_token = None
        self._expires_at = None

# Usage
with ZeroTrustClient(
    base_url="https://auth.example.com",
    api_key="your-api-key"
) as client:
    token_manager = TokenManager(client)
    
    # After login
    auth_response = client.authenticate("user@example.com", "password")
    token_manager.set_tokens(
        auth_response.access_token,
        auth_response.refresh_token,
        auth_response.expires_at
    )
    
    # Later, get a valid token
    valid_token = token_manager.get_valid_token()
    if valid_token:
        # Use token for API calls
        pass
```

## User Management

### Get User Profile

```python
def get_user_profile(client: ZeroTrustClient, token: str):
    try:
        user = client.get_user_profile(token)
        
        print("User Profile:")
        print(f"  ID: {user.id}")
        print(f"  Email: {user.email}")
        print(f"  Name: {user.first_name} {user.last_name}")
        print(f"  Display Name: {user.display_name}")
        print(f"  Roles: {user.roles}")
        print(f"  Trust Score: {user.trust_score}")
        print(f"  Active: {user.is_active}")
        print(f"  Verified: {user.is_verified}")
        print(f"  MFA Enabled: {user.mfa_enabled}")
        
        return user
        
    except Exception as error:
        print(f"Failed to get user profile: {error}")
        raise
```

### Update User Profile

```python
def update_user_profile(client: ZeroTrustClient, token: str, updates: dict):
    try:
        updated_user = client.update_user_profile(token, updates)
        
        print("✅ Profile updated successfully!")
        print(f"Updated Name: {updated_user.display_name}")
        
        return updated_user
        
    except Exception as error:
        print(f"Failed to update profile: {error}")
        raise

# Usage
updates = {
    "first_name": "John",
    "last_name": "Doe",
    "display_name": "John Doe",
    "metadata": {
        "department": "Engineering",
        "location": "San Francisco"
    }
}

with ZeroTrustClient(base_url="...", api_key="...") as client:
    updated_user = update_user_profile(client, token, updates)
```

## FastAPI Integration

### FastAPI Authentication Dependency

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, List
from zerotrust_sdk import ZeroTrustClient, Claims

app = FastAPI(title="Zero Trust API")

# Initialize SDK client
client = ZeroTrustClient(
    base_url="https://auth.example.com",
    api_key="your-api-key"
)

security = HTTPBearer()

class AuthService:
    def __init__(self, client: ZeroTrustClient):
        self.client = client
    
    async def get_current_user(
        self, 
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> Claims:
        try:
            response = self.client.validate_token(credentials.credentials)
            
            if not response.valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )
            
            return response.claims
            
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed"
            )
    
    def require_roles(self, required_roles: List[str]):
        async def role_checker(current_user: Claims = Depends(self.get_current_user)):
            user_roles = current_user.roles or []
            has_required_role = any(role in user_roles for role in required_roles)
            
            if not has_required_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required roles: {required_roles}"
                )
            
            return current_user
        
        return role_checker
    
    def require_scopes(self, required_scopes: List[str]):
        async def scope_checker(current_user: Claims = Depends(self.get_current_user)):
            user_scopes = current_user.permissions or []
            has_required_scope = all(scope in user_scopes for scope in required_scopes)
            
            if not has_required_scope:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required scopes: {required_scopes}"
                )
            
            return current_user
        
        return scope_checker

auth_service = AuthService(client)

# Public endpoints
@app.post("/auth/login")
async def login(email: str, password: str):
    try:
        response = client.authenticate(email, password)
        return {
            "access_token": response.access_token,
            "refresh_token": response.refresh_token,
            "token_type": "bearer",
            "expires_at": response.expires_at,
            "user": {
                "id": response.user.id,
                "email": response.user.email,
                "display_name": response.user.display_name
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

# Protected endpoints
@app.get("/profile")
async def get_profile(current_user: Claims = Depends(auth_service.get_current_user)):
    return {
        "user_id": current_user.subject,
        "email": current_user.email,
        "roles": current_user.roles,
        "trust_score": current_user.trust_score
    }

# Role-protected endpoints
@app.get("/admin/users")
async def list_users(
    current_user: Claims = Depends(auth_service.require_roles(["admin"]))
):
    return {"message": "Admin access granted", "user": current_user.subject}

# Scope-protected endpoints
@app.put("/profile")
async def update_profile(
    updates: dict,
    current_user: Claims = Depends(auth_service.require_scopes(["write:profile"]))
):
    # Update profile logic here
    return {"message": "Profile updated", "user": current_user.subject}

# Health check
@app.get("/health")
async def health_check():
    try:
        client.health_check()
        return {"status": "healthy"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service unavailable"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### FastAPI Middleware

```python
from fastapi import FastAPI, Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware
from zerotrust_sdk import ZeroTrustClient
import time

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, client: ZeroTrustClient, skip_paths: List[str] = None):
        super().__init__(app)
        self.client = client
        self.skip_paths = skip_paths or ["/health", "/docs", "/openapi.json"]
    
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for certain paths
        if request.url.path in self.skip_paths:
            return await call_next(request)
        
        # Extract token from Authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(
                content='{"error": "Authentication required"}',
                status_code=401,
                media_type="application/json"
            )
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        try:
            response = self.client.validate_token(token)
            if not response.valid:
                return Response(
                    content='{"error": "Invalid token"}',
                    status_code=401,
                    media_type="application/json"
                )
            
            # Add claims to request state
            request.state.claims = response.claims
            request.state.user_id = response.claims.subject
            
            return await call_next(request)
            
        except Exception:
            return Response(
                content='{"error": "Authentication failed"}',
                status_code=401,
                media_type="application/json"
            )

# Usage
app = FastAPI()
client = ZeroTrustClient(base_url="...", api_key="...")

app.add_middleware(
    AuthMiddleware,
    client=client,
    skip_paths=["/health", "/auth/login", "/docs"]
)
```

## Django Integration

### Django Authentication Backend

```python
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.conf import settings
from zerotrust_sdk import ZeroTrustClient

class ZeroTrustAuthBackend(BaseBackend):
    def __init__(self):
        self.client = ZeroTrustClient(
            base_url=settings.ZEROTRUST_BASE_URL,
            api_key=settings.ZEROTRUST_API_KEY
        )
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None
        
        try:
            response = self.client.authenticate(username, password)
            
            if response.requires_mfa:
                # Handle MFA flow
                return None
            
            # Get or create Django user
            user, created = User.objects.get_or_create(
                username=response.user.email,
                defaults={
                    'email': response.user.email,
                    'first_name': response.user.first_name,
                    'last_name': response.user.last_name,
                    'is_active': response.user.is_active,
                }
            )
            
            # Store tokens in session
            request.session['access_token'] = response.access_token
            request.session['refresh_token'] = response.refresh_token
            request.session['expires_at'] = response.expires_at
            
            return user
            
        except Exception as e:
            return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

# settings.py
AUTHENTICATION_BACKENDS = [
    'path.to.ZeroTrustAuthBackend',
    'django.contrib.auth.backends.ModelBackend',  # Fallback
]

ZEROTRUST_BASE_URL = 'https://auth.example.com'
ZEROTRUST_API_KEY = 'your-api-key'
```

### Django Middleware

```python
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from zerotrust_sdk import ZeroTrustClient

class ZeroTrustTokenMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        super().__init__(get_response)
        self.client = ZeroTrustClient(
            base_url=settings.ZEROTRUST_BASE_URL,
            api_key=settings.ZEROTRUST_API_KEY
        )
        self.skip_paths = ['/admin/', '/auth/', '/health/']
    
    def process_request(self, request):
        # Skip certain paths
        if any(request.path.startswith(path) for path in self.skip_paths):
            return None
        
        # Extract token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        try:
            response = self.client.validate_token(token)
            if not response.valid:
                return JsonResponse({'error': 'Invalid token'}, status=401)
            
            # Add claims to request
            request.zerotrust_claims = response.claims
            request.zerotrust_user_id = response.claims.subject
            
        except Exception:
            return JsonResponse({'error': 'Authentication failed'}, status=401)
        
        return None

# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'path.to.ZeroTrustTokenMiddleware',
    # ... other middleware
]
```

### Django Decorators

```python
from functools import wraps
from django.http import JsonResponse
from django.conf import settings
from zerotrust_sdk import ZeroTrustClient

client = ZeroTrustClient(
    base_url=settings.ZEROTRUST_BASE_URL,
    api_key=settings.ZEROTRUST_API_KEY
)

def require_auth(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        token = auth_header[7:]
        
        try:
            response = client.validate_token(token)
            if not response.valid:
                return JsonResponse({'error': 'Invalid token'}, status=401)
            
            request.zerotrust_claims = response.claims
            return view_func(request, *args, **kwargs)
            
        except Exception:
            return JsonResponse({'error': 'Authentication failed'}, status=401)
    
    return wrapped_view

def require_roles(*required_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not hasattr(request, 'zerotrust_claims'):
                return JsonResponse({'error': 'Authentication required'}, status=401)
            
            user_roles = request.zerotrust_claims.roles or []
            has_required_role = any(role in user_roles for role in required_roles)
            
            if not has_required_role:
                return JsonResponse({
                    'error': 'Insufficient permissions',
                    'required_roles': list(required_roles)
                }, status=403)
            
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    return decorator

# Usage in views
from django.http import JsonResponse

@require_auth
def profile_view(request):
    return JsonResponse({
        'user_id': request.zerotrust_claims.subject,
        'email': request.zerotrust_claims.email,
        'roles': request.zerotrust_claims.roles
    })

@require_auth
@require_roles('admin')
def admin_view(request):
    return JsonResponse({'message': 'Admin access granted'})
```

## Flask Integration

### Flask Authentication

```python
from flask import Flask, request, jsonify, g
from functools import wraps
from zerotrust_sdk import ZeroTrustClient
import os

app = Flask(__name__)

# Initialize client
client = ZeroTrustClient(
    base_url=os.getenv('ZEROTRUST_BASE_URL'),
    api_key=os.getenv('ZEROTRUST_API_KEY')
)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        try:
            response = client.validate_token(token)
            if not response.valid:
                return jsonify({'error': 'Invalid token'}), 401
            
            g.claims = response.claims
            g.user_id = response.claims.subject
            
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

def require_roles(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'claims'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user_roles = g.claims.roles or []
            has_required_role = any(role in user_roles for role in required_roles)
            
            if not has_required_role:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_roles': list(required_roles)
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Public routes
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    try:
        response = client.authenticate(email, password)
        return jsonify({
            'access_token': response.access_token,
            'refresh_token': response.refresh_token,
            'expires_at': response.expires_at,
            'user': {
                'id': response.user.id,
                'email': response.user.email,
                'display_name': response.user.display_name
            }
        })
    except Exception as e:
        return jsonify({'error': 'Invalid credentials'}), 401

# Protected routes
@app.route('/profile')
@require_auth
def get_profile():
    return jsonify({
        'user_id': g.claims.subject,
        'email': g.claims.email,
        'roles': g.claims.roles,
        'trust_score': g.claims.trust_score
    })

# Role-protected routes
@app.route('/admin/users')
@require_auth
@require_roles('admin')
def list_users():
    return jsonify({
        'message': 'Admin access granted',
        'user': g.user_id
    })

if __name__ == '__main__':
    app.run(debug=True)
```

## Async Support

### Async Client Implementation

```python
import asyncio
import aiohttp
from typing import Optional
from zerotrust_sdk import AuthenticationRequest, TokenValidationRequest

class AsyncZeroTrustClient:
    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            headers={
                'Content-Type': 'application/json',
                'X-API-Key': self.api_key,
                'User-Agent': 'MVP-ZeroTrust-SDK/1.0.0 (Python-Async)'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def authenticate(self, email: str, password: str, **kwargs):
        request_data = {
            'email': email,
            'password': password,
            **kwargs
        }
        
        async with self.session.post(
            f'{self.base_url}/api/v1/auth/login',
            json=request_data
        ) as response:
            if response.status >= 400:
                error_data = await response.json()
                raise Exception(f"Authentication failed: {error_data.get('message', 'Unknown error')}")
            
            return await response.json()
    
    async def validate_token(self, token: str, **kwargs):
        request_data = {
            'token': token,
            **kwargs
        }
        
        async with self.session.post(
            f'{self.base_url}/api/v1/auth/validate',
            json=request_data
        ) as response:
            if response.status >= 400:
                error_data = await response.json()
                raise Exception(f"Token validation failed: {error_data.get('message', 'Unknown error')}")
            
            return await response.json()
    
    async def health_check(self):
        async with self.session.get(f'{self.base_url}/health') as response:
            if response.status != 200:
                raise Exception(f"Health check failed with status: {response.status}")

# Usage
async def main():
    async with AsyncZeroTrustClient(
        base_url="https://auth.example.com",
        api_key="your-api-key"
    ) as client:
        # Test connection
        await client.health_check()
        print("✅ Connected to Zero Trust Auth service!")
        
        # Authenticate user
        auth_response = await client.authenticate("user@example.com", "password")
        print(f"Access token: {auth_response['access_token']}")
        
        # Validate token
        validation_response = await client.validate_token(auth_response['access_token'])
        print(f"Token valid: {validation_response['valid']}")

# Run async example
if __name__ == "__main__":
    asyncio.run(main())
```

## Error Handling

### Comprehensive Error Handling

```python
from zerotrust_sdk import ZeroTrustClient, ZeroTrustAPIError, ZeroTrustUtils
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self, client: ZeroTrustClient):
        self.client = client
    
    def authenticate_with_retry(self, email: str, password: str, max_retries: int = 3):
        """Authenticate with automatic retry logic."""
        last_error = None
        
        for attempt in range(1, max_retries + 1):
            try:
                return self.client.authenticate(email, password)
                
            except Exception as error:
                last_error = error
                logger.warning(f"Authentication attempt {attempt} failed: {error}")
                
                # Don't retry authentication errors
                if ZeroTrustUtils.is_authentication_error(error):
                    raise error
                
                # Only retry if error is retryable
                if not ZeroTrustUtils.is_retryable_error(error):
                    raise error
                
                if attempt < max_retries:
                    delay = min(2 ** (attempt - 1), 10)  # Exponential backoff, max 10s
                    logger.info(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
        
        raise Exception(f"Authentication failed after {max_retries} attempts: {last_error}")
    
    def handle_auth_error(self, error: Exception) -> str:
        """Convert authentication errors to user-friendly messages."""
        if isinstance(error, ZeroTrustAPIError):
            error_messages = {
                'INVALID_CREDENTIALS': 'Invalid email or password',
                'ACCOUNT_LOCKED': 'Account is temporarily locked. Please try again later.',
                'MFA_REQUIRED': 'Multi-factor authentication is required',
                'RATE_LIMITED': 'Too many attempts. Please wait before trying again.',
                'TOKEN_EXPIRED': 'Your session has expired. Please log in again.',
                'INSUFFICIENT_PERMISSIONS': 'You do not have permission to access this resource.'
            }
            return error_messages.get(error.code, error.message)
        
        return 'An unexpected error occurred. Please try again.'

# Usage
with ZeroTrustClient(base_url="...", api_key="...") as client:
    auth_service = AuthService(client)
    
    try:
        response = auth_service.authenticate_with_retry("user@example.com", "password")
        print("Login successful!")
        
    except Exception as error:
        error_message = auth_service.handle_auth_error(error)
        print(f"Login failed: {error_message}")
```

### Custom Exception Classes

```python
from zerotrust_sdk import ZeroTrustAPIError

class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass

class AuthorizationError(Exception):
    """Raised when user lacks required permissions."""
    pass

class TokenExpiredError(Exception):
    """Raised when token has expired."""
    pass

def handle_sdk_errors(func):
    """Decorator to convert SDK errors to custom exceptions."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ZeroTrustAPIError as e:
            if e.code in ['INVALID_CREDENTIALS', 'INVALID_TOKEN']:
                raise AuthenticationError(e.message) from e
            elif e.code in ['INSUFFICIENT_PERMISSIONS', 'MISSING_SCOPE']:
                raise AuthorizationError(e.message) from e
            elif e.code == 'TOKEN_EXPIRED':
                raise TokenExpiredError(e.message) from e
            else:
                raise  # Re-raise unknown API errors
        except Exception as e:
            # Handle non-API errors
            raise
    
    return wrapper

@handle_sdk_errors
def login_user(client: ZeroTrustClient, email: str, password: str):
    return client.authenticate(email, password)

# Usage
try:
    response = login_user(client, "user@example.com", "wrong-password")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except AuthorizationError as e:
    print(f"Authorization failed: {e}")
except TokenExpiredError as e:
    print(f"Token expired: {e}")
```

## Utilities

### Security and Validation Utilities

```python
from zerotrust_sdk import ZeroTrustUtils
from datetime import datetime, timezone

# Email validation
email = "  USER@EXAMPLE.COM  "
sanitized_email = ZeroTrustUtils.sanitize_email(email)
is_valid = ZeroTrustUtils.validate_email(sanitized_email)
print(f"Sanitized: {sanitized_email}, Valid: {is_valid}")

# Token expiration checking
expires_at = "2024-12-31T23:59:59Z"
is_expired = ZeroTrustUtils.is_token_expired(expires_at)
expiring_soon = ZeroTrustUtils.is_token_expiring_soon(expires_at, 300)  # 5 minutes
print(f"Expired: {is_expired}, Expiring soon: {expiring_soon}")

# Error classification
try:
    client.authenticate("invalid@example.com", "wrong-password")
except Exception as error:
    is_auth_error = ZeroTrustUtils.is_authentication_error(error)
    is_retryable = ZeroTrustUtils.is_retryable_error(error)
    print(f"Auth error: {is_auth_error}, Retryable: {is_retryable}")
```

### Configuration Management

```python
import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class ZeroTrustConfig:
    base_url: str
    api_key: str
    timeout: int = 30
    max_retries: int = 3
    debug: bool = False
    
    @classmethod
    def from_env(cls) -> 'ZeroTrustConfig':
        """Load configuration from environment variables."""
        return cls(
            base_url=os.getenv('ZEROTRUST_BASE_URL', ''),
            api_key=os.getenv('ZEROTRUST_API_KEY', ''),
            timeout=int(os.getenv('ZEROTRUST_TIMEOUT', '30')),
            max_retries=int(os.getenv('ZEROTRUST_MAX_RETRIES', '3')),
            debug=os.getenv('ZEROTRUST_DEBUG', 'false').lower() == 'true'
        )
    
    def validate(self) -> None:
        """Validate configuration."""
        if not self.base_url:
            raise ValueError("ZEROTRUST_BASE_URL is required")
        if not self.api_key:
            raise ValueError("ZEROTRUST_API_KEY is required")
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")

# Usage
config = ZeroTrustConfig.from_env()
config.validate()

with ZeroTrustClient(
    base_url=config.base_url,
    api_key=config.api_key,
    timeout=config.timeout,
    debug=config.debug
) as client:
    # Use client...
    pass
```

## API Reference

### Client Configuration

```python
class ZeroTrustClient:
    def __init__(
        self,
        base_url: str,          # Required: Base URL of the auth service
        api_key: str,           # Required: API key for authentication
        timeout: int = 30,      # Request timeout in seconds
        max_retries: int = 3,   # Max retry attempts
        retry_delay: float = 1.0, # Delay between retries in seconds
        debug: bool = False     # Enable debug logging
    )
```

### Authentication Methods

```python
# Authenticate user
def authenticate(self, email: str, password: str, mfa: str = None, remember: bool = False) -> AuthenticationResponse

# Validate token
def validate_token(self, token: str, audience: str = None, required_scopes: List[str] = None) -> TokenValidationResponse

# Refresh token
def refresh_token(self, refresh_token: str) -> AuthenticationResponse

# Logout user
def logout(self, token: str = None, session_id: str = None, everywhere: bool = False) -> None

# Health check
def health_check(self) -> None
```

### User Management Methods

```python
# Get user profile
def get_user_profile(self, token: str) -> User

# Update user profile
def update_user_profile(self, token: str, user_data: Dict[str, Any]) -> User
```

### Utility Methods

```python
# Token utilities
@staticmethod
def is_token_expired(expires_at: Union[str, datetime, int]) -> bool

@staticmethod
def is_token_expiring_soon(expires_at: Union[str, datetime, int], threshold_seconds: int) -> bool

# Security utilities
@staticmethod
def sanitize_email(email: str) -> str

@staticmethod
def validate_email(email: str) -> bool

# Error utilities
@staticmethod
def is_authentication_error(error: Exception) -> bool

@staticmethod
def is_retryable_error(error: Exception) -> bool
```

For complete type annotations and class definitions, see the [Python SDK source code](../../sdk/python/zerotrust_sdk/).