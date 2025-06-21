# 🐍 Python Code Standards & Best Practices (2025)

> **Python-specific standards for Zero Trust SDK & Scripts**  
> **Last Updated**: 2025-06-21  
> **Enforced by**: Ruff, mypy, bandit

## 🎯 **Python Quality Tools Stack**

| Tool | Purpose | Version | Config |
|------|---------|---------|--------|
| **Ruff** | Ultra-fast linting & formatting | v0.7+ | `.ruff.toml` |
| **mypy** | Static type checking | latest | `pyproject.toml` |
| **bandit** | Security analysis | latest | built-in |
| **pytest** | Testing framework | latest | `pytest.ini` |
| **coverage** | Code coverage | latest | `.coveragerc` |

## 📋 **Mandatory Python Rules**

### **1. Type Annotations (100% Coverage)**
```python
# ✅ REQUIRED: Full type annotations for all functions
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class UserService:
    """Service for managing user operations in Zero Trust system."""
    
    def __init__(self, user_repository: "UserRepository") -> None:
        self._user_repository = user_repository
        self._logger = logging.getLogger(self.__class__.__name__)
    
    async def get_user_by_email(
        self, 
        email: str, 
        *, 
        include_roles: bool = False
    ) -> Optional["User"]:
        """Retrieve a user by their email address.
        
        Args:
            email: The user's email address (must be valid format).
            include_roles: Whether to include user roles in response.
            
        Returns:
            The user if found, None otherwise.
            
        Raises:
            ValidationError: If email format is invalid.
            ServiceError: If database operation fails.
        """
        if not self._is_valid_email(email):
            raise ValidationError(f"Invalid email format: {email}")
        
        try:
            user = await self._user_repository.find_by_email(
                email, 
                include_roles=include_roles
            )
            
            if user:
                self._logger.info(
                    "User retrieved successfully",
                    extra={"user_id": user.id, "email": email}
                )
            
            return user
            
        except RepositoryError as e:
            self._logger.error(
                "Failed to retrieve user by email",
                extra={"email": email, "error": str(e)},
                exc_info=True
            )
            raise ServiceError("User retrieval failed") from e
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format using regex."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

# ❌ FORBIDDEN: Missing type annotations
def get_user_by_email(email):  # CI WILL FAIL - missing types
    user = repository.find_by_email(email)
    return user
```

### **2. Error Handling & Logging**
```python
# ✅ REQUIRED: Proper exception hierarchy
class ZeroTrustSDKError(Exception):
    """Base exception for all SDK errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code

class ValidationError(ZeroTrustSDKError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None) -> None:
        super().__init__(message, "VALIDATION_ERROR")
        self.field = field

class ServiceError(ZeroTrustSDKError):
    """Raised when service operation fails."""
    
    def __init__(self, message: str, original_error: Optional[Exception] = None) -> None:
        super().__init__(message, "SERVICE_ERROR")
        self.original_error = original_error

# ✅ REQUIRED: Structured logging with context
import structlog

logger = structlog.get_logger()

class AuthenticationService:
    """Handle user authentication with comprehensive logging."""
    
    async def authenticate_user(
        self, 
        credentials: "AuthCredentials"
    ) -> "AuthResult":
        """Authenticate user with detailed audit trail."""
        
        # Structured logging with context
        log = logger.bind(
            operation="authenticate_user",
            email=credentials.email,
            timestamp=datetime.utcnow().isoformat()
        )
        
        try:
            log.info("Authentication attempt started")
            
            # Validate credentials
            if not self._validate_credentials(credentials):
                log.warning("Authentication failed - invalid credentials")
                raise ValidationError("Invalid credentials format")
            
            # Check user exists
            user = await self._user_service.get_user_by_email(credentials.email)
            if not user:
                log.warning("Authentication failed - user not found")
                raise AuthenticationError("Invalid email or password")
            
            # Verify password
            if not self._password_hasher.verify(credentials.password, user.password_hash):
                log.warning("Authentication failed - invalid password")
                self._track_failed_attempt(user.id)
                raise AuthenticationError("Invalid email or password")
            
            # Generate tokens
            tokens = await self._token_service.generate_tokens(user)
            
            log.info(
                "Authentication successful",
                extra={"user_id": user.id, "session_id": tokens.session_id}
            )
            
            return AuthResult(
                user=user,
                access_token=tokens.access_token,
                refresh_token=tokens.refresh_token,
                expires_at=tokens.expires_at
            )
            
        except (ValidationError, AuthenticationError):
            # Re-raise known errors
            raise
        except Exception as e:
            log.error(
                "Authentication failed due to unexpected error",
                extra={"error": str(e)},
                exc_info=True
            )
            raise ServiceError("Authentication service unavailable") from e

# ❌ FORBIDDEN: Bare except clauses and poor logging
def authenticate_user(credentials):
    try:
        user = get_user(credentials.email)
        if user.password == credentials.password:  # Plain text comparison!
            return user
    except:  # CI WILL FAIL - bare except
        print("Error occurred")  # CI WILL FAIL - print statement
        return None
```

### **3. Data Classes & Models**
```python
# ✅ REQUIRED: Proper data models with validation
from dataclasses import dataclass, field
from typing import List, Optional, ClassVar
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    """User role enumeration."""
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"

class UserStatus(str, Enum):
    """User status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"

@dataclass(frozen=True)
class User:
    """Immutable user data model."""
    
    id: str
    email: str
    name: str
    roles: List[UserRole]
    status: UserStatus
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None
    preferences: Dict[str, Any] = field(default_factory=dict)
    
    # Class-level validation
    def __post_init__(self) -> None:
        """Validate user data after initialization."""
        if not self.id:
            raise ValueError("User ID cannot be empty")
        
        if not self._is_valid_email(self.email):
            raise ValueError(f"Invalid email format: {self.email}")
        
        if not self.name.strip():
            raise ValueError("User name cannot be empty")
        
        if not self.roles:
            raise ValueError("User must have at least one role")
    
    @staticmethod
    def _is_valid_email(email: str) -> bool:
        """Validate email format."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def has_role(self, role: UserRole) -> bool:
        """Check if user has specific role."""
        return role in self.roles
    
    def is_active(self) -> bool:
        """Check if user is active."""
        return self.status == UserStatus.ACTIVE

@dataclass
class CreateUserRequest:
    """Request model for creating new users."""
    
    email: str
    name: str
    password: str
    roles: List[UserRole] = field(default_factory=lambda: [UserRole.USER])
    
    def __post_init__(self) -> None:
        """Validate create user request."""
        if len(self.password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        if not any(c.isupper() for c in self.password):
            raise ValueError("Password must contain uppercase letter")
        
        if not any(c.islower() for c in self.password):
            raise ValueError("Password must contain lowercase letter")
        
        if not any(c.isdigit() for c in self.password):
            raise ValueError("Password must contain digit")

# ❌ FORBIDDEN: Mutable data without validation
class User:  # CI WILL FAIL - missing type annotations
    def __init__(self, id, email, name):
        self.id = id
        self.email = email  # No validation
        self.name = name
        self.roles = []  # Mutable default
```

## 🔒 **Security Standards**

### **1. Input Validation & Sanitization**
```python
# ✅ REQUIRED: Comprehensive input validation
import re
from typing import Pattern
from html import escape

class InputValidator:
    """Centralized input validation with security focus."""
    
    EMAIL_PATTERN: ClassVar[Pattern[str]] = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    # Prevent common injection patterns
    SQL_INJECTION_PATTERNS: ClassVar[List[Pattern[str]]] = [
        re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)', re.IGNORECASE),
        re.compile(r'(\b(UNION|JOIN|EXEC|EXECUTE)\b)', re.IGNORECASE),
        re.compile(r'(--|\||;|/\*|\*/)', re.IGNORECASE),
    ]
    
    XSS_PATTERNS: ClassVar[List[Pattern[str]]] = [
        re.compile(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
    ]
    
    @classmethod
    def validate_email(cls, email: str) -> str:
        """Validate and sanitize email address."""
        if not email or len(email) > 254:
            raise ValidationError("Email length invalid")
        
        email = email.strip().lower()
        
        if not cls.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email format")
        
        return email
    
    @classmethod
    def validate_text_input(
        cls, 
        text: str, 
        *, 
        max_length: int = 1000,
        allow_html: bool = False
    ) -> str:
        """Validate and sanitize text input."""
        if not isinstance(text, str):
            raise ValidationError("Input must be string")
        
        if len(text) > max_length:
            raise ValidationError(f"Input too long (max {max_length} chars)")
        
        # Check for SQL injection patterns
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if pattern.search(text):
                raise ValidationError("Potentially malicious input detected")
        
        # Handle HTML content
        if not allow_html:
            # Check for XSS patterns
            for pattern in cls.XSS_PATTERNS:
                if pattern.search(text):
                    raise ValidationError("HTML content not allowed")
            
            # Escape HTML entities
            text = escape(text)
        
        return text.strip()
    
    @classmethod
    def validate_password(cls, password: str) -> None:
        """Validate password strength."""
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters")
        
        if len(password) > 128:
            raise ValidationError("Password too long")
        
        checks = [
            (any(c.islower() for c in password), "lowercase letter"),
            (any(c.isupper() for c in password), "uppercase letter"),
            (any(c.isdigit() for c in password), "digit"),
            (any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password), "special character"),
        ]
        
        for check_passed, requirement in checks:
            if not check_passed:
                raise ValidationError(f"Password must contain at least one {requirement}")

# ❌ FORBIDDEN: No input validation
def create_user(email, name, password):
    # Direct database insertion without validation - SECURITY RISK
    query = f"INSERT INTO users (email, name, password) VALUES ('{email}', '{name}', '{password}')"
    execute_sql(query)  # SQL injection vulnerability
```

### **2. Secure Configuration Management**
```python
# ✅ REQUIRED: Environment-based configuration
import os
from typing import Optional
from dataclasses import dataclass

@dataclass(frozen=True)
class SecurityConfig:
    """Security-focused configuration."""
    
    jwt_secret: str
    jwt_expiry_minutes: int = 60
    password_hash_rounds: int = 12
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    
    @classmethod
    def from_environment(cls) -> "SecurityConfig":
        """Load configuration from environment variables."""
        jwt_secret = os.getenv("JWT_SECRET")
        if not jwt_secret:
            raise ValueError("JWT_SECRET environment variable is required")
        
        if len(jwt_secret) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        
        return cls(
            jwt_secret=jwt_secret,
            jwt_expiry_minutes=int(os.getenv("JWT_EXPIRY_MINUTES", "60")),
            password_hash_rounds=int(os.getenv("PASSWORD_HASH_ROUNDS", "12")),
            max_login_attempts=int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")),
            lockout_duration_minutes=int(os.getenv("LOCKOUT_DURATION_MINUTES", "30")),
        )

@dataclass(frozen=True) 
class DatabaseConfig:
    """Database configuration with security defaults."""
    
    url: str
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    ssl_required: bool = True
    
    @classmethod
    def from_environment(cls) -> "DatabaseConfig":
        """Load database config from environment."""
        url = os.getenv("DATABASE_URL")
        if not url:
            raise ValueError("DATABASE_URL environment variable is required")
        
        # Ensure SSL for production
        if "sslmode=disable" in url and os.getenv("ENVIRONMENT") == "production":
            raise ValueError("SSL must be enabled in production")
        
        return cls(
            url=url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
            ssl_required=os.getenv("DB_SSL_REQUIRED", "true").lower() == "true",
        )

# ❌ FORBIDDEN: Hardcoded secrets
JWT_SECRET = "hardcoded-secret-key"  # CI WILL FAIL - bandit will catch this
DATABASE_URL = "postgresql://user:password@localhost/db"  # CI WILL FAIL
```

## 🧪 **Testing Standards**

### **1. Pytest with Comprehensive Coverage**
```python
# File: test_user_service.py
import pytest
from unittest.mock import AsyncMock, Mock
from datetime import datetime
from typing import AsyncGenerator

from zerotrust_sdk.services import UserService
from zerotrust_sdk.models import User, UserRole, UserStatus
from zerotrust_sdk.exceptions import ValidationError, ServiceError

class TestUserService:
    """Comprehensive test suite for UserService."""
    
    @pytest.fixture
    async def mock_repository(self) -> AsyncMock:
        """Create mock user repository."""
        return AsyncMock()
    
    @pytest.fixture
    async def user_service(self, mock_repository: AsyncMock) -> UserService:
        """Create UserService with mocked dependencies."""
        return UserService(user_repository=mock_repository)
    
    @pytest.fixture
    def sample_user(self) -> User:
        """Create sample user for testing."""
        return User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            roles=[UserRole.USER],
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_success(
        self, 
        user_service: UserService,
        mock_repository: AsyncMock,
        sample_user: User
    ) -> None:
        """Test successful user retrieval by email."""
        # Arrange
        email = "test@example.com"
        mock_repository.find_by_email.return_value = sample_user
        
        # Act
        result = await user_service.get_user_by_email(email)
        
        # Assert
        assert result == sample_user
        mock_repository.find_by_email.assert_called_once_with(
            email, 
            include_roles=False
        )
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(
        self,
        user_service: UserService,
        mock_repository: AsyncMock
    ) -> None:
        """Test user retrieval when user doesn't exist."""
        # Arrange
        email = "nonexistent@example.com"
        mock_repository.find_by_email.return_value = None
        
        # Act
        result = await user_service.get_user_by_email(email)
        
        # Assert
        assert result is None
        mock_repository.find_by_email.assert_called_once_with(
            email,
            include_roles=False
        )
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_invalid_email(
        self,
        user_service: UserService,
        mock_repository: AsyncMock
    ) -> None:
        """Test user retrieval with invalid email format."""
        # Arrange
        invalid_email = "invalid-email"
        
        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            await user_service.get_user_by_email(invalid_email)
        
        assert "Invalid email format" in str(exc_info.value)
        mock_repository.find_by_email.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_repository_error(
        self,
        user_service: UserService,
        mock_repository: AsyncMock
    ) -> None:
        """Test user retrieval when repository raises error."""
        # Arrange
        email = "test@example.com"
        repository_error = Exception("Database connection failed")
        mock_repository.find_by_email.side_effect = repository_error
        
        # Act & Assert
        with pytest.raises(ServiceError) as exc_info:
            await user_service.get_user_by_email(email)
        
        assert "User retrieval failed" in str(exc_info.value)
        assert exc_info.value.original_error == repository_error
    
    @pytest.mark.parametrize("email,expected", [
        ("valid@example.com", True),
        ("user.name@domain.co.uk", True),
        ("test+tag@example.org", True),
        ("invalid-email", False),
        ("@domain.com", False),
        ("user@", False),
        ("", False),
    ])
    def test_is_valid_email(
        self,
        user_service: UserService,
        email: str,
        expected: bool
    ) -> None:
        """Test email validation with various formats."""
        result = user_service._is_valid_email(email)
        assert result == expected

# ✅ REQUIRED: Integration tests with real dependencies
@pytest.mark.integration
class TestUserServiceIntegration:
    """Integration tests with real database."""
    
    @pytest.fixture
    async def database_url(self) -> str:
        """Get test database URL."""
        return os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
    
    @pytest.fixture
    async def user_service(self, database_url: str) -> AsyncGenerator[UserService, None]:
        """Create UserService with real database."""
        # Setup test database
        repository = UserRepository(database_url)
        await repository.initialize()
        
        service = UserService(repository)
        
        yield service
        
        # Cleanup
        await repository.cleanup()
    
    @pytest.mark.asyncio
    async def test_create_and_retrieve_user(
        self, 
        user_service: UserService
    ) -> None:
        """Test full user lifecycle with real database."""
        # Create user
        create_request = CreateUserRequest(
            email="integration@example.com",
            name="Integration Test User",
            password="SecurePass123!",
            roles=[UserRole.USER]
        )
        
        created_user = await user_service.create_user(create_request)
        assert created_user.email == "integration@example.com"
        
        # Retrieve user
        retrieved_user = await user_service.get_user_by_email("integration@example.com")
        assert retrieved_user is not None
        assert retrieved_user.id == created_user.id
        assert retrieved_user.name == "Integration Test User"
```

### **2. Property-Based Testing**
```python
# ✅ REQUIRED: Property-based testing for complex logic
import hypothesis
from hypothesis import strategies as st

class TestUserValidation:
    """Property-based tests for user validation."""
    
    @hypothesis.given(
        email=st.emails(),
        name=st.text(min_size=1, max_size=100).filter(lambda x: x.strip())
    )
    def test_valid_users_always_validate(self, email: str, name: str) -> None:
        """Valid users should always pass validation."""
        user = User(
            id="test-id",
            email=email,
            name=name,
            roles=[UserRole.USER],
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        # Should not raise exception
        assert user.email == email
        assert user.name == name
    
    @hypothesis.given(
        password=st.text(min_size=8).filter(
            lambda p: (
                any(c.islower() for c in p) and
                any(c.isupper() for c in p) and
                any(c.isdigit() for c in p) and
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in p)
            )
        )
    )
    def test_strong_passwords_always_validate(self, password: str) -> None:
        """Strong passwords should always pass validation."""
        # Should not raise exception
        InputValidator.validate_password(password)
```

## ⚡ **Performance Standards**

### **1. Async/Await Best Practices**
```python
# ✅ REQUIRED: Proper async patterns
import asyncio
import aiohttp
from typing import List, Dict, Any
from contextlib import asynccontextmanager

class ZeroTrustAPIClient:
    """Async API client with connection pooling."""
    
    def __init__(self, base_url: str, timeout: int = 30) -> None:
        self._base_url = base_url
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None
    
    @asynccontextmanager
    async def _get_session(self) -> AsyncGenerator[aiohttp.ClientSession, None]:
        """Get or create aiohttp session with connection pooling."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=100,  # Total connection pool size
                limit_per_host=30,  # Per-host connection limit
                keepalive_timeout=30,
                enable_cleanup_closed=True
            )
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self._timeout,
                headers={"User-Agent": "ZeroTrust-SDK/1.0"}
            )
        
        yield self._session
    
    async def get_users(
        self, 
        *, 
        limit: int = 100, 
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get users with pagination."""
        async with self._get_session() as session:
            params = {"limit": limit, "offset": offset}
            
            async with session.get(
                f"{self._base_url}/users",
                params=params
            ) as response:
                response.raise_for_status()
                data = await response.json()
                return data["users"]
    
    async def get_multiple_users(
        self, 
        user_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """Get multiple users concurrently."""
        async with self._get_session() as session:
            # Create concurrent tasks
            tasks = [
                self._get_single_user(session, user_id)
                for user_id in user_ids
            ]
            
            # Execute concurrently with proper error handling
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful results
            users = []
            for result in results:
                if isinstance(result, Exception):
                    logger.warning(f"Failed to fetch user: {result}")
                else:
                    users.append(result)
            
            return users
    
    async def _get_single_user(
        self, 
        session: aiohttp.ClientSession, 
        user_id: str
    ) -> Dict[str, Any]:
        """Get single user (helper for concurrent requests)."""
        async with session.get(f"{self._base_url}/users/{user_id}") as response:
            response.raise_for_status()
            return await response.json()
    
    async def close(self) -> None:
        """Cleanup resources."""
        if self._session and not self._session.closed:
            await self._session.close()

# ❌ FORBIDDEN: Blocking operations in async code
async def bad_async_function():
    # Blocking I/O in async function - CI WILL FAIL
    import time
    time.sleep(1)  # Blocks the entire event loop
    
    # Sync database call in async function
    users = database.get_users()  # Should be await database.get_users()
    return users
```

### **2. Memory Optimization**
```python
# ✅ REQUIRED: Memory-efficient data processing
from typing import Iterator, Generator
import sys

class UserProcessor:
    """Memory-efficient user data processing."""
    
    def process_large_dataset(
        self, 
        user_data_file: str
    ) -> Generator[Dict[str, Any], None, None]:
        """Process large user datasets without loading all into memory."""
        import json
        
        with open(user_data_file, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, 1):
                try:
                    user_data = json.loads(line.strip())
                    
                    # Validate and process each user
                    processed_user = self._process_single_user(user_data)
                    if processed_user:
                        yield processed_user
                        
                except json.JSONDecodeError as e:
                    logger.warning(
                        f"Invalid JSON on line {line_number}: {e}",
                        extra={"line_number": line_number, "line_content": line[:100]}
                    )
                    continue
                except Exception as e:
                    logger.error(
                        f"Error processing user on line {line_number}: {e}",
                        extra={"line_number": line_number},
                        exc_info=True
                    )
                    continue
    
    def _process_single_user(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process single user data."""
        try:
            # Validate required fields
            required_fields = ['id', 'email', 'name']
            if not all(field in user_data for field in required_fields):
                return None
            
            # Transform and validate
            return {
                'id': str(user_data['id']),
                'email': InputValidator.validate_email(user_data['email']),
                'name': InputValidator.validate_text_input(user_data['name']),
                'roles': user_data.get('roles', ['user']),
                'created_at': user_data.get('created_at'),
            }
            
        except (ValidationError, ValueError) as e:
            logger.warning(f"User validation failed: {e}")
            return None
    
    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        return {
            'rss_mb': memory_info.rss / 1024 / 1024,  # Resident Set Size
            'vms_mb': memory_info.vms / 1024 / 1024,  # Virtual Memory Size
            'percent': process.memory_percent(),
        }

# ❌ FORBIDDEN: Loading large datasets into memory
def bad_process_users(user_data_file: str) -> List[Dict[str, Any]]:
    import json
    
    # Loading entire file into memory - BAD for large files
    with open(user_data_file, 'r') as file:
        all_data = file.read()  # Could be gigabytes!
    
    users = []
    for line in all_data.split('\n'):
        user = json.loads(line)
        users.append(user)  # Growing list in memory
    
    return users
```

## 🔧 **Static Analysis Configuration**

### **Ruff Configuration (Enforced)**
```toml
# .ruff.toml
[lint]
select = [
    "E",      # pycodestyle errors
    "W",      # pycodestyle warnings
    "F",      # Pyflakes
    "I",      # isort
    "N",      # pep8-naming
    "D",      # pydocstyle
    "UP",     # pyupgrade
    "S",      # bandit (security)
    "B",      # flake8-bugbear
    "A",      # flake8-builtins
    "C4",     # flake8-comprehensions
    "T20",    # flake8-print
    "PT",     # flake8-pytest-style
    "RET",    # flake8-return
    "SIM",    # flake8-simplify
    "ARG",    # flake8-unused-arguments
    "PL",     # Pylint
    "TRY",    # tryceratops
    "RUF",    # Ruff-specific rules
]

ignore = [
    "D100",   # Missing docstring in public module
    "D104",   # Missing docstring in public package
    "ANN101", # Missing type annotation for self
    "ANN102", # Missing type annotation for cls
]
```

### **mypy Configuration**
```toml
# pyproject.toml
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true
```

## 🚀 **CI/CD Integration**

### **Make Targets**
```bash
# Python quality checks
make lint-python        # Ruff linting
make type-check-python   # mypy type checking
make security-python     # bandit security scan
make format-python       # Ruff formatting
make test-python         # pytest with coverage

# Combined quality check
make quality-ci          # All checks (CI mode)
```

### **Coverage Requirements**
```ini
# .coveragerc
[run]
source = sdk/python
omit = 
    */tests/*
    */test_*
    */__pycache__/*
    */venv/*

[report]
fail_under = 85
precision = 2
show_missing = true
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
```

---

**Remember**: Python code must maintain 100% type annotation coverage and pass all security scans. No bare except clauses or print statements allowed in production code.