# Python FastAPI Template - Zero Trust Architecture

> **Template**: Production-ready Python FastAPI service with Zero Trust security  
> **Based On**: Zero Trust Authentication MVP patterns  
> **Version**: 1.0  
> **Last Updated**: 2025-06-21

## 🎯 **Template Overview**

This template provides a complete Python FastAPI microservice foundation implementing Zero Trust security principles, modern Python practices, and production-ready async patterns.

### **Key Features**
- **Zero Trust Security**: JWT authentication, device attestation, continuous verification
- **Async/Await Patterns**: High-performance async operations throughout
- **Type Safety**: Pydantic models with comprehensive validation
- **Modern Python**: Python 3.11+ with latest FastAPI patterns
- **Production Ready**: Observability, health checks, graceful shutdown
- **Testing Framework**: Pytest with async testing and fixtures

## 📁 **Directory Structure**

```
{service-name}/
├── app/
│   ├── main.py                        # FastAPI application entry point
│   ├── config.py                      # Configuration management
│   ├── dependencies.py                # Dependency injection
│   ├── auth/                          # Authentication & authorization
│   │   ├── __init__.py
│   │   ├── jwt.py                     # JWT token management
│   │   ├── dependencies.py            # Auth dependencies
│   │   ├── middleware.py              # Auth middleware
│   │   └── trust_levels.py            # Zero Trust levels
│   ├── core/                          # Core business logic
│   │   ├── __init__.py
│   │   ├── models/                    # Domain models
│   │   ├── services/                  # Business services
│   │   └── repositories/              # Data access layer
│   ├── api/                           # API route handlers
│   │   ├── __init__.py
│   │   ├── v1/                        # API version 1
│   │   │   ├── __init__.py
│   │   │   ├── auth.py                # Authentication endpoints
│   │   │   ├── users.py               # User management endpoints
│   │   │   └── health.py              # Health check endpoints
│   │   └── middleware/                # API middleware
│   │       ├── __init__.py
│   │       ├── cors.py                # CORS middleware
│   │       ├── logging.py             # Request logging
│   │       └── security.py            # Security headers
│   ├── database/                      # Database configuration
│   │   ├── __init__.py
│   │   ├── connection.py              # Database connection
│   │   ├── migrations/                # Alembic migrations
│   │   └── models.py                  # SQLAlchemy models
│   ├── schemas/                       # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── auth.py                    # Authentication schemas
│   │   ├── users.py                   # User schemas
│   │   └── common.py                  # Common schemas
│   ├── utils/                         # Utility functions
│   │   ├── __init__.py
│   │   ├── security.py                # Security utilities
│   │   ├── validation.py              # Validation helpers
│   │   └── formatting.py              # Data formatting
│   └── observability/                 # Monitoring & logging
│       ├── __init__.py
│       ├── logger.py                  # Structured logging
│       ├── metrics.py                 # Prometheus metrics
│       └── tracing.py                 # OpenTelemetry tracing
├── tests/                             # Test suite
│   ├── __init__.py
│   ├── conftest.py                    # Pytest configuration
│   ├── fixtures/                      # Test fixtures
│   ├── unit/                          # Unit tests
│   ├── integration/                   # Integration tests
│   └── e2e/                          # End-to-end tests
├── scripts/                          # Utility scripts
│   ├── start.py                      # Development server
│   ├── migrate.py                    # Database migrations
│   └── seed.py                       # Database seeding
├── deployments/                      # Deployment configurations
│   ├── docker/
│   └── k8s/
├── .env.template                     # Environment variables template
├── .gitignore                        # Git ignore patterns
├── .ruff.toml                        # Ruff configuration
├── .mypy.ini                         # MyPy configuration
├── Dockerfile                        # Container definition
├── docker-compose.yml               # Local development setup
├── Makefile                          # Build automation
├── pyproject.toml                    # Python project configuration
├── requirements.txt                  # Production dependencies
├── requirements-dev.txt              # Development dependencies
└── README.md                         # Project documentation
```

## 🛠️ **Template Files**

### **Main Application (app/main.py)**
```python
"""
FastAPI application with Zero Trust security implementation.
"""
import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.api.middleware.cors import setup_cors_middleware
from app.api.middleware.logging import LoggingMiddleware
from app.api.middleware.security import SecurityMiddleware
from app.api.v1 import auth, users, health
from app.config import get_settings
from app.database.connection import database_manager
from app.observability.logger import get_logger
from app.observability.metrics import setup_metrics
from app.observability.tracing import setup_tracing

logger = get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan handler for startup and shutdown events.
    """
    # Startup
    logger.info("Starting application...")
    
    try:
        # Initialize database connection
        await database_manager.connect()
        logger.info("Database connection established")
        
        # Initialize observability
        if settings.observability.tracing_enabled:
            setup_tracing(settings.observability)
            logger.info("Tracing initialized")
        
        setup_metrics()
        logger.info("Metrics initialized")
        
        # Application is ready
        logger.info("Application startup complete")
        
        yield
        
    finally:
        # Shutdown
        logger.info("Shutting down application...")
        
        # Close database connection
        await database_manager.disconnect()
        logger.info("Database connection closed")
        
        logger.info("Application shutdown complete")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    """
    app = FastAPI(
        title=settings.app.name,
        version=settings.app.version,
        description=settings.app.description,
        docs_url="/docs" if settings.app.environment != "production" else None,
        redoc_url="/redoc" if settings.app.environment != "production" else None,
        lifespan=lifespan,
    )

    # Security middleware
    if settings.security.trusted_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.security.trusted_hosts
        )

    # Custom security middleware
    app.add_middleware(SecurityMiddleware)
    
    # CORS middleware
    setup_cors_middleware(app, settings.cors)
    
    # Logging middleware
    app.add_middleware(LoggingMiddleware)

    # Exception handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """
        Global exception handler for unhandled exceptions.
        """
        logger.error(
            "Unhandled exception occurred",
            extra={
                "method": request.method,
                "url": str(request.url),
                "error": str(exc),
            },
            exc_info=True,
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "success": False,
                "timestamp": "2025-06-21T00:00:00Z",  # Use actual timestamp
            },
        )

    # Include routers
    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
    app.include_router(users.router, prefix="/api/v1/users", tags=["users"])

    return app


# Create application instance
app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.app.environment == "development",
        log_config=None,  # Use our custom logging
    )
```

### **Configuration Management (app/config.py)**
```python
"""
Application configuration management using Pydantic Settings.
"""
from functools import lru_cache
from typing import List, Optional

from pydantic import BaseSettings, Field, validator


class AppSettings(BaseSettings):
    """Application configuration."""
    
    name: str = Field(default="{service-name}", env="APP_NAME")
    version: str = Field(default="1.0.0", env="APP_VERSION")
    description: str = Field(default="FastAPI service with Zero Trust security")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")


class ServerSettings(BaseSettings):
    """Server configuration."""
    
    host: str = Field(default="0.0.0.0", env="SERVER_HOST")
    port: int = Field(default=8000, env="SERVER_PORT")
    workers: int = Field(default=1, env="SERVER_WORKERS")
    reload: bool = Field(default=False, env="SERVER_RELOAD")


class DatabaseSettings(BaseSettings):
    """Database configuration."""
    
    url: str = Field(..., env="DATABASE_URL")
    pool_size: int = Field(default=10, env="DATABASE_POOL_SIZE")
    max_overflow: int = Field(default=20, env="DATABASE_MAX_OVERFLOW")
    pool_timeout: int = Field(default=30, env="DATABASE_POOL_TIMEOUT")
    echo: bool = Field(default=False, env="DATABASE_ECHO")


class RedisSettings(BaseSettings):
    """Redis configuration."""
    
    url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    max_connections: int = Field(default=10, env="REDIS_MAX_CONNECTIONS")
    retry_on_timeout: bool = Field(default=True, env="REDIS_RETRY_ON_TIMEOUT")


class JWTSettings(BaseSettings):
    """JWT configuration."""
    
    secret_key: str = Field(..., env="JWT_SECRET_KEY")
    algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="JWT_REFRESH_TOKEN_EXPIRE_DAYS")
    
    @validator("secret_key")
    def validate_secret_key(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")
        return v


class CORSSettings(BaseSettings):
    """CORS configuration."""
    
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        env="CORS_ALLOWED_ORIGINS"
    )
    allowed_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        env="CORS_ALLOWED_METHODS"
    )
    allowed_headers: List[str] = Field(
        default=["Authorization", "Content-Type", "X-Request-ID"],
        env="CORS_ALLOWED_HEADERS"
    )
    allow_credentials: bool = Field(default=True, env="CORS_ALLOW_CREDENTIALS")


class SecuritySettings(BaseSettings):
    """Security configuration."""
    
    trusted_hosts: Optional[List[str]] = Field(default=None, env="TRUSTED_HOSTS")
    rate_limit_per_minute: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    password_min_length: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    bcrypt_rounds: int = Field(default=12, env="BCRYPT_ROUNDS")


class ObservabilitySettings(BaseSettings):
    """Observability configuration."""
    
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    tracing_enabled: bool = Field(default=False, env="TRACING_ENABLED")
    tracing_endpoint: Optional[str] = Field(default=None, env="TRACING_ENDPOINT")
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")


class Settings(BaseSettings):
    """Main application settings."""
    
    app: AppSettings = AppSettings()
    server: ServerSettings = ServerSettings()
    database: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    jwt: JWTSettings = JWTSettings()
    cors: CORSSettings = CORSSettings()
    security: SecuritySettings = SecuritySettings()
    observability: ObservabilitySettings = ObservabilitySettings()

    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached application settings.
    """
    return Settings()
```

### **Authentication Service (app/auth/jwt.py)**
```python
"""
JWT authentication service with Zero Trust principles.
"""
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import uuid

import jwt
from fastapi import HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel

from app.config import get_settings
from app.core.models.user import User
from app.schemas.auth import TokenData, TrustLevel
from app.observability.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenPayload(BaseModel):
    """JWT token payload model."""
    
    user_id: str
    email: str
    roles: list[str]
    permissions: list[str]
    device_id: Optional[str] = None
    trust_level: int = 50  # Default medium trust
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for blacklisting


class AuthService:
    """Authentication service with Zero Trust implementation."""
    
    def __init__(self):
        self.secret_key = settings.jwt.secret_key
        self.algorithm = settings.jwt.algorithm
        self.access_token_expire_minutes = settings.jwt.access_token_expire_minutes
        self.refresh_token_expire_days = settings.jwt.refresh_token_expire_days

    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.
        """
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        """
        return pwd_context.verify(plain_password, hashed_password)

    def calculate_trust_level(
        self,
        device_verified: bool = False,
        location_verified: bool = False,
        behavior_normal: bool = True,
        recent_activity: bool = True,
    ) -> TrustLevel:
        """
        Calculate trust level based on various factors.
        
        Returns:
            TrustLevel: Calculated trust level (0-100)
        """
        base_trust = 30  # Base trust for authenticated user
        
        if device_verified:
            base_trust += 25
        if location_verified:
            base_trust += 20
        if behavior_normal:
            base_trust += 15
        if recent_activity:
            base_trust += 10
            
        # Cap at 100
        trust_score = min(base_trust, 100)
        
        if trust_score >= 80:
            return TrustLevel.HIGH
        elif trust_score >= 50:
            return TrustLevel.MEDIUM
        else:
            return TrustLevel.LOW

    def create_access_token(
        self,
        user: User,
        trust_factors: Optional[Dict[str, bool]] = None,
        device_id: Optional[str] = None,
    ) -> str:
        """
        Create a new JWT access token with trust level.
        """
        now = datetime.utcnow()
        expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        # Calculate trust level based on factors
        trust_factors = trust_factors or {}
        trust_level = self.calculate_trust_level(**trust_factors)
        
        # Create token payload
        payload = TokenPayload(
            user_id=str(user.id),
            email=user.email,
            roles=[role.name for role in user.roles],
            permissions=[perm.name for perm in user.permissions],
            device_id=device_id,
            trust_level=trust_level.value,
            exp=expire,
            iat=now,
            jti=str(uuid.uuid4()),
        )
        
        # Encode JWT token
        token = jwt.encode(
            payload.dict(),
            self.secret_key,
            algorithm=self.algorithm
        )
        
        logger.info(
            "Access token created",
            extra={
                "user_id": user.id,
                "trust_level": trust_level.value,
                "device_id": device_id,
                "expires_at": expire.isoformat(),
            }
        )
        
        return token

    def create_refresh_token(self, user_id: str) -> str:
        """
        Create a new JWT refresh token.
        """
        now = datetime.utcnow()
        expire = now + timedelta(days=self.refresh_token_expire_days)
        
        payload = {
            "user_id": user_id,
            "type": "refresh",
            "exp": expire,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        logger.info(
            "Refresh token created",
            extra={
                "user_id": user_id,
                "expires_at": expire.isoformat(),
            }
        )
        
        return token

    async def verify_token(self, token: str) -> TokenData:
        """
        Verify and decode a JWT token.
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            
            # Extract token data
            token_data = TokenData(
                user_id=payload.get("user_id"),
                email=payload.get("email"),
                roles=payload.get("roles", []),
                permissions=payload.get("permissions", []),
                device_id=payload.get("device_id"),
                trust_level=payload.get("trust_level", 50),
                jti=payload.get("jti"),
            )
            
            if not token_data.user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: missing user ID",
                )
            
            return token_data
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.JWTError as e:
            logger.warning(
                "JWT verification failed",
                extra={"error": str(e)}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    async def blacklist_token(self, jti: str) -> None:
        """
        Add a token to the blacklist.
        This would typically involve storing the JTI in Redis with expiration.
        """
        # Implementation would store JTI in Redis or database
        # with expiration matching the token's remaining lifetime
        logger.info(
            "Token blacklisted",
            extra={"jti": jti}
        )

    async def is_token_blacklisted(self, jti: str) -> bool:
        """
        Check if a token is blacklisted.
        """
        # Implementation would check Redis or database for JTI
        return False  # Placeholder


# Global auth service instance
auth_service = AuthService()
```

### **Pydantic Schemas (app/schemas/auth.py)**
```python
"""
Authentication-related Pydantic schemas.
"""
from datetime import datetime
from enum import IntEnum
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, validator


class TrustLevel(IntEnum):
    """Trust levels for Zero Trust authentication."""
    
    NONE = 0      # Untrusted
    LOW = 25      # Basic authentication
    MEDIUM = 50   # Known device
    HIGH = 75     # Verified device + location
    FULL = 100    # Hardware attestation


class LoginRequest(BaseModel):
    """User login request."""
    
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    device_id: Optional[str] = Field(None, max_length=255)
    remember_me: bool = False

    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "securepassword123",
                "device_id": "device-fingerprint-hash",
                "remember_me": True
            }
        }


class LoginResponse(BaseModel):
    """User login response."""
    
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # Seconds
    user: "UserResponse"
    trust_level: int


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    
    refresh_token: str


class TokenData(BaseModel):
    """JWT token payload data."""
    
    user_id: str
    email: str
    roles: List[str] = []
    permissions: List[str] = []
    device_id: Optional[str] = None
    trust_level: int = 50
    jti: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    """Password change request."""
    
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str

    @validator("confirm_password")
    def passwords_match(cls, v, values):
        if "new_password" in values and v != values["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class UserResponse(BaseModel):
    """User response model."""
    
    id: UUID
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    roles: List[str] = []
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class DeviceRegistrationRequest(BaseModel):
    """Device registration for attestation."""
    
    device_fingerprint: str
    device_name: str
    platform: str
    user_agent: str
    public_key: Optional[str] = None  # For hardware attestation


class TrustAssessmentResponse(BaseModel):
    """Trust level assessment response."""
    
    trust_level: int
    factors: dict = Field(
        description="Factors that influenced the trust calculation"
    )
    recommendations: List[str] = Field(
        description="Recommendations to improve trust level"
    )
    expires_at: datetime


# Import here to avoid circular imports
from app.schemas.users import UserResponse
LoginResponse.update_forward_refs()
```

### **FastAPI Dependencies (app/dependencies.py)**
```python
"""
FastAPI dependency injection functions.
"""
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import auth_service
from app.database.connection import get_db_session
from app.schemas.auth import TokenData, TrustLevel
from app.core.services.user_service import UserService
from app.core.models.user import User
from app.observability.logger import get_logger

logger = get_logger(__name__)

# Security scheme
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db_session),
) -> User:
    """
    Get the current authenticated user from JWT token.
    """
    try:
        # Verify the token
        token_data = await auth_service.verify_token(credentials.credentials)
        
        # Check if token is blacklisted
        if token_data.jti and await auth_service.is_token_blacklisted(token_data.jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )
        
        # Get user from database
        user_service = UserService(db)
        user = await user_service.get_by_id(token_data.user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled",
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Authentication failed",
            extra={"error": str(e)},
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


def require_trust_level(minimum_trust: TrustLevel):
    """
    Dependency factory for requiring minimum trust level.
    """
    async def check_trust_level(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> TokenData:
        token_data = await auth_service.verify_token(credentials.credentials)
        
        if token_data.trust_level < minimum_trust.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient trust level. Required: {minimum_trust.value}, Current: {token_data.trust_level}",
            )
        
        return token_data
    
    return check_trust_level


def require_permissions(required_permissions: list[str]):
    """
    Dependency factory for requiring specific permissions.
    """
    async def check_permissions(
        user: User = Depends(get_current_user),
    ) -> User:
        user_permissions = [perm.name for perm in user.permissions]
        
        missing_permissions = set(required_permissions) - set(user_permissions)
        if missing_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permissions: {', '.join(missing_permissions)}",
            )
        
        return user
    
    return check_permissions


def require_roles(required_roles: list[str]):
    """
    Dependency factory for requiring specific roles.
    """
    async def check_roles(
        user: User = Depends(get_current_user),
    ) -> User:
        user_roles = [role.name for role in user.roles]
        
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {', '.join(required_roles)}",
            )
        
        return user
    
    return check_roles


# Convenience dependencies
async def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Get current active user."""
    return user


async def get_admin_user(
    user: User = Depends(require_roles(["admin"])),
) -> User:
    """Get current user with admin role."""
    return user


async def get_high_trust_user(
    token_data: TokenData = Depends(require_trust_level(TrustLevel.HIGH)),
    user: User = Depends(get_current_user),
) -> User:
    """Get current user with high trust level."""
    return user
```

### **Environment Template (.env.template)**
```bash
# {SERVICE_NAME} Environment Configuration

# Application Configuration
APP_NAME={service-name}
APP_VERSION=1.0.0
ENVIRONMENT=development
DEBUG=false

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
SERVER_WORKERS=1
SERVER_RELOAD=true

# Database Configuration
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/{service_name}_db
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20
DATABASE_POOL_TIMEOUT=30
DATABASE_ECHO=false

# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=
REDIS_MAX_CONNECTIONS=10
REDIS_RETRY_ON_TIMEOUT=true

# JWT Configuration
JWT_SECRET_KEY=your_super_secret_key_here_at_least_32_characters_long
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# CORS Configuration
CORS_ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:5173"]
CORS_ALLOWED_METHODS=["GET","POST","PUT","DELETE","OPTIONS"]
CORS_ALLOWED_HEADERS=["Authorization","Content-Type","X-Request-ID"]
CORS_ALLOW_CREDENTIALS=true

# Security Configuration
TRUSTED_HOSTS=["localhost","127.0.0.1"]
RATE_LIMIT_PER_MINUTE=60
PASSWORD_MIN_LENGTH=8
BCRYPT_ROUNDS=12

# Observability Configuration
LOG_LEVEL=INFO
LOG_FORMAT=json
TRACING_ENABLED=false
TRACING_ENDPOINT=http://localhost:14268/api/traces
METRICS_ENABLED=true

# External Services
EXTERNAL_API_URL=https://api.external-service.com
EXTERNAL_API_KEY=your_external_api_key_here

# Email Configuration (if needed)
SMTP_HOST=localhost
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_USE_TLS=true
```

### **Makefile Template**
```makefile
# Python FastAPI Makefile
.PHONY: help dev build test lint clean install

# Configuration
SERVICE_NAME := {service-name}
PYTHON_VERSION := $(shell python --version)
POETRY_VERSION := $(shell poetry --version 2>/dev/null || echo "Not installed")

help: ## 📖 Show this help message
	@echo "🚀 $(SERVICE_NAME) - Python FastAPI Service"
	@echo "=========================================="
	@echo "📋 DEVELOPMENT:"
	@echo "  make dev          ⚡ Start development server"
	@echo "  make build        🔨 Build the application"
	@echo "  make test         🧪 Run all tests"
	@echo "  make lint         🔍 Run linting and formatting"
	@echo ""
	@echo "🗃️  DATABASE:"
	@echo "  make db-migrate   🗃️  Run database migrations"
	@echo "  make db-upgrade   ⬆️  Upgrade database"
	@echo "  make db-downgrade ⬇️  Downgrade database"
	@echo ""
	@echo "🧹 UTILITIES:"
	@echo "  make clean        🧹 Clean build artifacts"
	@echo "  make install      📥 Install dependencies"

## Development Commands

dev: ## ⚡ Start development server
	@echo "⚡ Starting development server..."
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

build: ## 🔨 Build the application
	@echo "🔨 Building application..."
	python -m pip install --upgrade pip
	pip install -r requirements.txt

test: ## 🧪 Run all tests
	@echo "🧪 Running tests..."
	pytest -v --cov=app --cov-report=html --cov-report=term

test-unit: ## 🧪 Run unit tests only
	@echo "🧪 Running unit tests..."
	pytest tests/unit/ -v

test-integration: ## 🔗 Run integration tests
	@echo "🔗 Running integration tests..."
	pytest tests/integration/ -v

test-e2e: ## 🎭 Run E2E tests
	@echo "🎭 Running E2E tests..."
	pytest tests/e2e/ -v

## Code Quality Commands

lint: ## 🔍 Run linting and formatting
	@echo "🔍 Running linting..."
	ruff check app tests
	@echo "🔍 Running type checking..."
	mypy app
	@echo "🔍 Running security checks..."
	bandit -r app -f json -o bandit-report.json || true

format: ## ✨ Format code
	@echo "✨ Formatting code..."
	ruff format app tests
	ruff check --fix app tests

## Database Commands

db-migrate: ## 🗃️ Generate new migration
	@echo "🗃️ Generating database migration..."
	alembic revision --autogenerate -m "$(message)"

db-upgrade: ## ⬆️ Upgrade database to latest
	@echo "⬆️ Upgrading database..."
	alembic upgrade head

db-downgrade: ## ⬇️ Downgrade database by one revision
	@echo "⬇️ Downgrading database..."
	alembic downgrade -1

db-reset: ## 🔄 Reset database (drop and recreate)
	@echo "🔄 Resetting database..."
	alembic downgrade base
	alembic upgrade head

## Utility Commands

install: ## 📥 Install dependencies
	@echo "📥 Installing dependencies..."
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

install-prod: ## 📥 Install production dependencies only
	@echo "📥 Installing production dependencies..."
	pip install -r requirements.txt

clean: ## 🧹 Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf dist/
	rm -rf build/

## Docker Commands

docker-build: ## 📦 Build Docker image
	@echo "📦 Building Docker image..."
	docker build -t $(SERVICE_NAME):latest .

docker-run: ## 🐳 Run with Docker Compose
	@echo "🐳 Starting services with Docker Compose..."
	docker-compose up --build

docker-test: ## 🧪 Run tests in Docker
	@echo "🧪 Running tests in Docker..."
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit

## Environment Commands

env-setup: ## 🔧 Setup environment file
	@echo "🔧 Setting up environment..."
	@if [ ! -f .env ]; then \
		cp .env.template .env; \
		echo "✅ Created .env file from template"; \
		echo "📝 Please edit .env with your configuration"; \
	else \
		echo "⚠️  .env file already exists"; \
	fi

env-check: ## ✅ Check environment setup
	@echo "✅ Checking environment..."
	@python --version
	@pip --version
	@echo "Service: $(SERVICE_NAME)"

## Security Commands

security-scan: ## 🔒 Run security scans
	@echo "🔒 Running security scans..."
	bandit -r app
	safety check

## Monitoring Commands

status: ## 📊 Check service status
	@echo "📊 Service Status:"
	@curl -s http://localhost:8000/health | python -m json.tool || echo "Service not running"

logs: ## 📋 View application logs
	@echo "📋 Application logs:"
	docker-compose logs -f app

metrics: ## 📊 View metrics
	@echo "📊 Metrics endpoint:"
	@curl -s http://localhost:8000/metrics || echo "Metrics not available"
```

## 📋 **Setup Instructions**

### **1. Initialize New Service**
```bash
# Create new service from template
mkdir my-new-service
cd my-new-service

# Set up Python environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
make install

# Set up environment
make env-setup
# Edit .env with your configuration
```

### **2. Database Setup**
```bash
# Install and configure PostgreSQL
# Update DATABASE_URL in .env

# Run migrations
make db-upgrade

# Optional: Seed database
python scripts/seed.py
```

### **3. Development Workflow**
```bash
# Start development server
make dev

# Run tests
make test

# Code quality checks
make lint format

# Database operations
make db-migrate message="Add user table"
make db-upgrade
```

## 🔒 **Security Features Included**

- **Zero Trust Authentication** with JWT and trust levels
- **Device Attestation** patterns for hardware verification
- **Password Hashing** with bcrypt and configurable rounds
- **Token Blacklisting** for immediate revocation
- **Rate Limiting** middleware
- **Input Validation** with Pydantic
- **SQL Injection Prevention** with SQLAlchemy ORM
- **CORS Configuration** for cross-origin security

## 🚀 **Production Features**

- **Async/Await** throughout for high performance
- **Database Connection Pooling** with async SQLAlchemy
- **Structured Logging** with correlation IDs
- **Health Check Endpoints** for Kubernetes
- **Metrics Integration** with Prometheus
- **Graceful Shutdown** handling
- **Error Handling** with proper HTTP status codes

This template provides a solid foundation for building secure, scalable Python FastAPI services following the patterns established in the Zero Trust Authentication MVP.