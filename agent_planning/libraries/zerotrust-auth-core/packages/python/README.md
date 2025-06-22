# Zero Trust Authentication Core - Python

> **Python implementation of the Zero Trust Authentication Core library**  
> **Version**: 1.0.0  
> **License**: MIT

## 🚀 **Quick Start**

### **Installation**

```bash
pip install zerotrust-auth-core
```

### **Basic Usage**

```python
import asyncio
from datetime import timedelta
from zerotrust_auth_core import (
    JWTManager, 
    TrustLevel, 
    create_default_jwt_config,
    TokenRequest
)

async def main():
    # Configure JWT manager
    config = create_default_jwt_config(
        secret="your-secret-key-32-characters-long",
        expiry_duration=timedelta(minutes=30),
        issuer="my-service"
    )
    
    jwt_manager = JWTManager(config)
    
    # Generate token with trust level
    token_request = TokenRequest(
        user_id="user123",
        email="user@example.com",
        roles=["user"],
        permissions=["read", "write"],
        trust_level=TrustLevel.MEDIUM,
        device_id="device-fingerprint-123"
    )
    
    token = await jwt_manager.generate_token(token_request)
    print(f"Access Token: {token.access_token}")
    print(f"Trust Level: {token.trust_level}")
    
    # Validate token
    claims = await jwt_manager.validate_token(token.access_token)
    print(f"User ID: {claims.user_id}")
    print(f"Trust Level: {claims.trust_level}")

# Run async code
asyncio.run(main())
```

## 🔐 **Trust Level System**

```python
import asyncio
from zerotrust_auth_core import (
    TrustCalculator,
    TrustLevel,
    TrustFactors,
    CalculationRequest
)

async def main():
    # Create trust calculator
    calculator = TrustCalculator()
    
    # Calculate trust based on factors
    factors = TrustFactors(
        device_verified=True,
        location_verified=True,
        behavior_normal=True,
        recent_activity=True,
        hardware_attestation=False,
        biometric_verified=False,
        network_trusted=True,
        previous_trust_level=TrustLevel.MEDIUM
    )
    
    trust_level = calculator.calculate(factors)
    print(f"Trust Level: {trust_level} ({trust_level.value})")
    
    # Check if trust level meets requirement
    required = TrustLevel.MEDIUM
    meets_requirement = trust_level.meets_requirement(required)
    print(f"Meets requirement: {meets_requirement}")

asyncio.run(main())
```

## 🛡️ **Token Blacklisting**

```python
import asyncio
from datetime import datetime, timedelta
from zerotrust_auth_core import MemoryBlacklist, RedisBlacklist

async def main():
    # Memory-based blacklist (for single-instance applications)
    memory_blacklist = MemoryBlacklist()
    
    # Add token to blacklist
    expires_at = datetime.now() + timedelta(hours=1)
    await memory_blacklist.add("token-jti", "User logout", expires_at)
    
    # Check if token is blacklisted
    token_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
    is_blacklisted = await memory_blacklist.is_blacklisted(token_string)
    print(f"Token blacklisted: {is_blacklisted}")
    
    # Set custom blacklist on JWT manager
    jwt_manager.set_blacklist(memory_blacklist)

asyncio.run(main())
```

## 🔄 **Advanced Configuration**

### **Custom Trust Calculator with Services**

```python
import asyncio
from typing import Optional
from zerotrust_auth_core import (
    TrustCalculator,
    DeviceService,
    BehaviorService,
    LocationService,
    DeviceHistory,
    BehaviorAnalysis,
    Location,
    TrustLevel
)

# Implement service interfaces
class MyDeviceService:
    async def verify_device(self, device_id: str) -> bool:
        # Your device verification logic
        return True
    
    async def get_device_history(self, device_id: str) -> Optional[DeviceHistory]:
        # Your device history logic
        return None
    
    async def check_hardware_attestation(self, device_id: str) -> bool:
        # Your hardware attestation logic
        return False
    
    async def is_device_trusted(self, device_id: str) -> bool:
        # Your device trust logic
        return True
    
    async def mark_device_as_trusted(self, device_id: str) -> None:
        # Your device trust marking logic
        pass

class MyBehaviorService:
    async def analyze_behavior(self, user_id: str, action: str) -> BehaviorAnalysis:
        # Your behavior analysis logic
        return BehaviorAnalysis(
            is_suspicious=False,
            anomaly_score=0.1,
            typical_login_times=[9, 10, 11, 14, 15, 16],
            typical_locations=["office", "home"],
            unusual_activity=[],
            last_analyzed=datetime.now(),
            confidence_score=0.95
        )
    
    # ... implement other methods

async def main():
    # Create calculator with custom services
    device_service = MyDeviceService()
    behavior_service = MyBehaviorService()
    
    calculator = TrustCalculator(
        device_service=device_service,
        behavior_service=behavior_service,
        config=CalculatorConfig(
            base_score=15,
            device_weight=30,
            behavior_weight=20
        )
    )
    
    # Calculate trust for user with comprehensive analysis
    request = CalculationRequest(
        user_id="user123",
        device_id="device456",
        action="login",
        last_activity=datetime.now(),
        session_start=datetime.now(),
        ip_address="192.168.1.100"
    )
    
    trust_level = await calculator.calculate_for_user(request)
    print(f"Calculated trust level: {trust_level}")

asyncio.run(main())
```

### **Redis-based Blacklist**

```python
import asyncio
import redis.asyncio as redis
from zerotrust_auth_core import RedisBlacklist, HybridBlacklist

class RedisClientWrapper:
    """Redis client wrapper implementing the RedisClient protocol."""
    
    def __init__(self, redis_client):
        self.client = redis_client
    
    async def set(self, key: str, value: str, ex: Optional[int] = None) -> None:
        await self.client.set(key, value, ex=ex)
    
    async def get(self, key: str) -> Optional[str]:
        result = await self.client.get(key)
        return result.decode() if result else None
    
    async def delete(self, key: str) -> None:
        await self.client.delete(key)
    
    async def exists(self, key: str) -> bool:
        return bool(await self.client.exists(key))
    
    async def keys(self, pattern: str) -> list:
        keys = await self.client.keys(pattern)
        return [key.decode() for key in keys]
    
    async def ttl(self, key: str) -> int:
        return await self.client.ttl(key)

async def main():
    # Create Redis client
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    wrapped_client = RedisClientWrapper(redis_client)
    
    # Redis-based blacklist (for distributed applications)
    redis_blacklist = RedisBlacklist(wrapped_client, "jwt:blacklist")
    jwt_manager.set_blacklist(redis_blacklist)
    
    # Hybrid blacklist (memory + Redis for performance and persistence)
    hybrid_blacklist = HybridBlacklist(wrapped_client, "jwt:blacklist")
    jwt_manager.set_blacklist(hybrid_blacklist)

asyncio.run(main())
```

## 🧪 **Testing**

```bash
# Install development dependencies
poetry install --with dev

# Run tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=html

# Run linting
flake8 src/
black --check src/
isort --check-only src/

# Run type checking
mypy src/

# Run security checks
bandit -r src/
safety check
```

### **Example Test**

```python
import pytest
from datetime import timedelta
from zerotrust_auth_core import (
    JWTManager,
    TrustLevel,
    create_default_jwt_config,
    TokenRequest
)

@pytest.mark.asyncio
async def test_jwt_manager_generate_token():
    """Test JWT token generation."""
    config = create_default_jwt_config(
        secret="test-secret-key-32-characters-long"
    )
    jwt_manager = JWTManager(config)
    
    request = TokenRequest(
        user_id="test-user",
        email="test@example.com",
        roles=["user"],
        permissions=["read"],
        trust_level=TrustLevel.MEDIUM
    )
    
    token = await jwt_manager.generate_token(request)
    
    assert token.access_token.count('.') == 2  # Valid JWT format
    assert token.trust_level == TrustLevel.MEDIUM
    assert token.token_type == "Bearer"

@pytest.mark.asyncio
async def test_jwt_manager_validate_token():
    """Test JWT token validation."""
    config = create_default_jwt_config(
        secret="test-secret-key-32-characters-long"
    )
    jwt_manager = JWTManager(config)
    
    request = TokenRequest(
        user_id="test-user",
        email="test@example.com",
        roles=["user"],
        permissions=["read"],
        trust_level=TrustLevel.HIGH
    )
    
    token = await jwt_manager.generate_token(request)
    claims = await jwt_manager.validate_token(token.access_token)
    
    assert claims.user_id == "test-user"
    assert claims.trust_level == TrustLevel.HIGH
    assert "user" in claims.roles
```

## 📚 **API Reference**

### **JWTManager**

```python
class JWTManager:
    def __init__(self, config: JWTConfig) -> None: ...
    
    async def generate_token(self, request: TokenRequest) -> Token: ...
    async def validate_token(self, token_string: str) -> JWTClaims: ...
    async def blacklist_token(self, token_string: str, reason: str) -> None: ...
    async def refresh_token(self, refresh_token: str, request: TokenRequest) -> Token: ...
    
    def set_blacklist(self, blacklist: Blacklist) -> None: ...
    def get_config(self) -> Dict[str, Union[str, int]]: ...
```

### **TrustCalculator**

```python
class TrustCalculator:
    def __init__(
        self,
        device_service: Optional[DeviceService] = None,
        behavior_service: Optional[BehaviorService] = None,
        location_service: Optional[LocationService] = None,
        config: Optional[CalculatorConfig] = None,
    ) -> None: ...
    
    def calculate(self, factors: TrustFactors) -> TrustLevel: ...
    async def calculate_for_user(self, request: CalculationRequest) -> TrustLevel: ...
    async def calculate_for_authentication(
        self, user_id: str, device_id: Optional[str] = None, ip_address: Optional[str] = None
    ) -> TrustLevel: ...
    
    @staticmethod
    def get_trust_level_for_operation(operation: str) -> TrustLevel: ...
    @staticmethod
    def validate_factors(factors: TrustFactors) -> None: ...
    @staticmethod
    def require_trust_level(required: TrustLevel): ...
```

### **Trust Levels**

```python
class TrustLevel(IntEnum):
    NONE = 0      # Untrusted
    LOW = 25      # Basic authentication
    MEDIUM = 50   # Known device
    HIGH = 75     # Verified device + location
    FULL = 100    # Hardware attestation
```

## 🔗 **Integration Examples**

### **FastAPI Integration**

```python
from fastapi import FastAPI, HTTPException, Depends, Header
from zerotrust_auth_core import JWTManager, TrustLevel, create_default_jwt_config

app = FastAPI()
jwt_manager = JWTManager(create_default_jwt_config())

async def get_current_user(authorization: str = Header(None)):
    """Authentication dependency."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = authorization[7:]  # Remove "Bearer " prefix
    
    try:
        claims = await jwt_manager.validate_token(token)
        return claims
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid token")

def require_trust_level(min_level: TrustLevel):
    """Trust level requirement dependency."""
    def dependency(user=Depends(get_current_user)):
        if user.trust_level < min_level:
            raise HTTPException(status_code=403, detail="Insufficient trust level")
        return user
    return dependency

@app.get("/api/profile")
async def get_profile(user=Depends(get_current_user)):
    return {"message": "Profile data", "user": user.dict()}

@app.delete("/api/resource/{resource_id}")
async def delete_resource(
    resource_id: str,
    user=Depends(require_trust_level(TrustLevel.HIGH))
):
    return {"message": f"Resource {resource_id} deleted"}
```

### **Django Integration**

```python
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from functools import wraps
from zerotrust_auth_core import JWTManager, TrustLevel, create_default_jwt_config

jwt_manager = JWTManager(create_default_jwt_config())

def jwt_required(trust_level: TrustLevel = TrustLevel.LOW):
    """JWT authentication decorator."""
    def decorator(view_func):
        @wraps(view_func)
        async def wrapper(request, *args, **kwargs):
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Missing token'}, status=401)
            
            token = auth_header[7:]
            
            try:
                claims = await jwt_manager.validate_token(token)
                if claims.trust_level < trust_level:
                    return JsonResponse({'error': 'Insufficient trust level'}, status=403)
                
                request.user_claims = claims
                return await view_func(request, *args, **kwargs)
            except Exception:
                return JsonResponse({'error': 'Invalid token'}, status=403)
        
        return wrapper
    return decorator

@require_http_methods(["GET"])
@jwt_required()
async def profile_view(request):
    return JsonResponse({
        'message': 'Profile data',
        'user': request.user_claims.dict()
    })

@require_http_methods(["DELETE"])
@jwt_required(TrustLevel.HIGH)
async def delete_resource_view(request, resource_id):
    return JsonResponse({'message': f'Resource {resource_id} deleted'})
```

## 🔒 **Security Considerations**

- **Secret Management**: Store JWT secrets securely (environment variables, key vaults)
- **Token Expiration**: Use short expiration times for access tokens
- **Blacklisting**: Implement token blacklisting for immediate revocation
- **Trust Levels**: Adjust trust calculations based on your security requirements
- **Key Rotation**: Enable automatic key rotation for enhanced security
- **Input Validation**: Always validate inputs before processing
- **Async Safety**: Use proper async/await patterns throughout your application

## 📄 **License**

MIT License - see [LICENSE](../../LICENSE) file for details.

---

**Zero Trust Authentication Core** - Building secure, scalable authentication for Python applications.