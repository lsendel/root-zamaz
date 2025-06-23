"""
FastAPI example demonstrating Keycloak Zero Trust integration.

This example shows how to integrate Keycloak Zero Trust authentication
with FastAPI, including middleware, dependency injection, and various
security patterns.

Usage:
    pip install keycloak-zerotrust[fastapi]
    python fastapi_example.py

Environment variables:
    KEYCLOAK_BASE_URL=https://keycloak.company.com
    KEYCLOAK_REALM=company
    KEYCLOAK_CLIENT_ID=api-service
    KEYCLOAK_CLIENT_SECRET=secret
"""

import asyncio
import logging
import os
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from keycloak_zerotrust import (
    KeycloakZeroTrustClient,
    ZeroTrustConfig,
    ZeroTrustClaims,
    AuthenticationError,
    TrustLevelError,
    DeviceVerificationError,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Zero Trust API Demo",
    description="FastAPI application with Keycloak Zero Trust authentication",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://app.company.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Keycloak client
keycloak_client: Optional[KeycloakZeroTrustClient] = None

# Security scheme
security = HTTPBearer()


# Pydantic models
class UserProfile(BaseModel):
    user_id: str
    username: str
    email: str
    first_name: str
    last_name: str
    roles: List[str]
    trust_level: int
    device_verified: bool
    risk_score: int


class TransferRequest(BaseModel):
    amount: float
    to_account: str
    currency: str = "USD"


class TransferResponse(BaseModel):
    transaction_id: str
    amount: float
    currency: str
    status: str
    user_id: str
    trust_level: int


class DeviceVerificationRequest(BaseModel):
    device_fingerprint: str
    platform: str
    biometric_data: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    keycloak_status: str
    timestamp: float


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize Keycloak client on startup."""
    global keycloak_client
    
    # Load configuration from environment
    config = ZeroTrustConfig(
        base_url=os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080"),
        realm=os.getenv("KEYCLOAK_REALM", "demo"),
        client_id=os.getenv("KEYCLOAK_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET", "demo-secret"),
    )
    
    # Initialize client
    keycloak_client = KeycloakZeroTrustClient(config)
    await keycloak_client._initialize()
    
    # Test connection
    try:
        await keycloak_client.health_check()
        logger.info("✅ Connected to Keycloak successfully")
    except Exception as e:
        logger.warning(f"⚠️ Keycloak health check failed: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    global keycloak_client
    if keycloak_client:
        await keycloak_client.close()


# Authentication dependencies
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> ZeroTrustClaims:
    """
    Dependency to get current authenticated user.
    
    Validates the JWT token and returns Zero Trust claims.
    """
    if not keycloak_client:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service not available"
        )
    
    try:
        token = credentials.credentials
        claims = await keycloak_client.validate_token(token)
        return claims
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": e.error_code, "message": e.message}
        )
    except Exception as e:
        logger.exception(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )


def require_trust_level(min_level: int):
    """
    Dependency factory to require minimum trust level.
    
    Args:
        min_level: Minimum required trust level (0-100)
    """
    async def check_trust_level(
        current_user: ZeroTrustClaims = Depends(get_current_user)
    ) -> ZeroTrustClaims:
        if current_user.trust_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_TRUST_LEVEL",
                    "message": f"Required trust level: {min_level}, current: {current_user.trust_level}"
                }
            )
        return current_user
    
    return check_trust_level


def require_role(required_role: str):
    """
    Dependency factory to require specific role.
    
    Args:
        required_role: Required role name
    """
    async def check_role(
        current_user: ZeroTrustClaims = Depends(get_current_user)
    ) -> ZeroTrustClaims:
        if required_role not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_ROLE",
                    "message": f"Required role: {required_role}"
                }
            )
        return current_user
    
    return check_role


def require_device_verification():
    """Dependency to require device verification."""
    async def check_device_verification(
        current_user: ZeroTrustClaims = Depends(get_current_user)
    ) -> ZeroTrustClaims:
        if not current_user.device_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "DEVICE_NOT_VERIFIED",
                    "message": "Device verification required"
                }
            )
        return current_user
    
    return check_device_verification


# Public endpoints
@app.get("/")
async def root():
    """Welcome endpoint."""
    return {
        "message": "Welcome to FastAPI Zero Trust API",
        "version": "1.0.0",
        "framework": "FastAPI",
        "documentation": "/docs"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    import time
    
    keycloak_status = "unknown"
    if keycloak_client:
        try:
            await keycloak_client.health_check()
            keycloak_status = "healthy"
        except Exception:
            keycloak_status = "unhealthy"
    
    return HealthResponse(
        status="healthy",
        keycloak_status=keycloak_status,
        timestamp=time.time()
    )


# Protected endpoints
@app.get("/api/v1/profile", response_model=UserProfile)
async def get_profile(
    current_user: ZeroTrustClaims = Depends(get_current_user)
):
    """Get user profile (requires authentication)."""
    return UserProfile(
        user_id=current_user.user_id,
        username=current_user.username,
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        roles=current_user.roles,
        trust_level=current_user.trust_level,
        device_verified=current_user.device_verified,
        risk_score=current_user.risk_score,
    )


@app.get("/api/v1/admin")
async def admin_endpoint(
    current_user: ZeroTrustClaims = Depends(require_role("admin"))
):
    """Admin-only endpoint."""
    return {
        "message": "Admin access granted",
        "admin_user": current_user.username,
        "roles": current_user.roles,
        "trust_level": current_user.trust_level,
    }


@app.get("/api/v1/sensitive")
async def sensitive_data(
    current_user: ZeroTrustClaims = Depends(require_trust_level(50))
):
    """Sensitive data requiring trust level 50+."""
    return {
        "message": "Sensitive data access granted",
        "user_id": current_user.user_id,
        "trust_level": current_user.trust_level,
        "data": "This is sensitive information",
    }


@app.post("/api/v1/transfer", response_model=TransferResponse)
async def transfer_funds(
    request: TransferRequest,
    current_user: ZeroTrustClaims = Depends(require_trust_level(75)),
    _: ZeroTrustClaims = Depends(require_device_verification()),
):
    """Transfer funds (requires trust level 75+ and device verification)."""
    if request.amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transfer amount must be positive"
        )
    
    # Generate transaction ID
    import uuid
    transaction_id = f"txn_{uuid.uuid4().hex[:8]}"
    
    logger.info(f"Transfer processed: {current_user.user_id} -> {request.to_account}, "
               f"Amount: {request.amount} {request.currency}")
    
    return TransferResponse(
        transaction_id=transaction_id,
        amount=request.amount,
        currency=request.currency,
        status="completed",
        user_id=current_user.user_id,
        trust_level=current_user.trust_level,
    )


@app.post("/api/v1/device/verify")
async def verify_device(
    request: DeviceVerificationRequest,
    current_user: ZeroTrustClaims = Depends(require_trust_level(25)),
):
    """Device verification endpoint."""
    # Simulate device verification process
    verification_score = 85  # Simulated score
    
    return {
        "message": "Device verification completed",
        "user_id": current_user.user_id,
        "device_fingerprint": request.device_fingerprint,
        "platform": request.platform,
        "verification_score": verification_score,
        "verification_status": "verified",
    }


@app.get("/api/v1/risk-assessment")
async def risk_assessment(
    current_user: ZeroTrustClaims = Depends(require_trust_level(25))
):
    """Risk assessment demonstration."""
    # Determine risk level
    risk_level = "low"
    if current_user.risk_score > 50:
        risk_level = "medium"
    if current_user.risk_score > 75:
        risk_level = "high"
    
    # Generate recommendations
    recommendations = []
    if current_user.risk_score > 50:
        recommendations.append("Consider additional verification")
    if not current_user.device_verified:
        recommendations.append("Device verification recommended")
    if current_user.trust_level < 50:
        recommendations.append("Increase trust level for enhanced access")
    
    return {
        "user_id": current_user.user_id,
        "risk_score": current_user.risk_score,
        "risk_level": risk_level,
        "trust_level": current_user.trust_level,
        "device_verified": current_user.device_verified,
        "recommendations": recommendations,
    }


@app.get("/api/v1/metrics")
async def get_metrics(
    current_user: ZeroTrustClaims = Depends(require_role("admin"))
):
    """Get system metrics (admin only)."""
    if not keycloak_client:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Metrics service not available"
        )
    
    metrics = keycloak_client.get_metrics()
    return {
        "framework": "fastapi",
        "keycloak_metrics": metrics.model_dump(),
        "admin_user": current_user.username,
    }


# Error handling for trust level errors
@app.exception_handler(TrustLevelError)
async def trust_level_error_handler(request: Request, exc: TrustLevelError):
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "INSUFFICIENT_TRUST_LEVEL", 
            "message": str(exc)
        }
    )


@app.exception_handler(DeviceVerificationError)
async def device_verification_error_handler(request: Request, exc: DeviceVerificationError):
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "DEVICE_NOT_VERIFIED",
            "message": str(exc)
        }
    )


# Run the application
if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", "8084"))
    
    print(f"🚀 Starting FastAPI server on port {port}")
    print("📖 API Documentation:")
    print(f"   Swagger UI: http://localhost:{port}/docs")
    print(f"   ReDoc: http://localhost:{port}/redoc")
    print("")
    print("🔑 Authentication: Include 'Authorization: Bearer <token>' header")
    print("🛡️  Zero Trust: Real-time trust level and device verification")
    print("🐍 Framework: FastAPI with async Zero Trust middleware")
    
    uvicorn.run(
        "fastapi_example:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info",
    )