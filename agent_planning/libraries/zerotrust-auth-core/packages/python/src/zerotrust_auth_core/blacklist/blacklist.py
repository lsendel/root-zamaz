"""Token blacklisting implementations for JWT revocation."""

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Optional, Protocol

import jwt
from pydantic import BaseModel


class BlacklistEntry(BaseModel):
    """Blacklist entry representation."""

    jti: str
    reason: str
    expires_at: datetime
    created_at: datetime
    user_id: Optional[str] = None


class BlacklistStats(BaseModel):
    """Blacklist statistics."""

    total_entries: int
    expired_entries: int
    active_entries: int
    last_cleanup: datetime
    memory_usage: Optional[int] = None  # bytes


class Blacklist(ABC):
    """Blacklist interface for token blacklisting implementations."""

    @abstractmethod
    async def add(self, jti: str, reason: str, expires_at: datetime) -> None:
        """Add a token to the blacklist."""
        ...

    @abstractmethod
    async def is_blacklisted(self, token_string: str) -> bool:
        """Check if a token is blacklisted."""
        ...

    @abstractmethod
    async def remove(self, jti: str) -> None:
        """Remove a token from the blacklist."""
        ...

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up expired entries from the blacklist."""
        ...

    @abstractmethod
    async def get_stats(self) -> BlacklistStats:
        """Get blacklist statistics."""
        ...


class MemoryBlacklist(Blacklist):
    """Memory-based blacklist implementation."""

    def __init__(self):
        """Initialize memory blacklist."""
        self._entries: Dict[str, BlacklistEntry] = {}
        self._last_cleanup = datetime.now()
        self._cleanup_interval = timedelta(hours=1)

    async def add(self, jti: str, reason: str, expires_at: datetime) -> None:
        """Add a token to the blacklist."""
        if not jti:
            raise ValueError("JTI cannot be empty")
        if not reason:
            raise ValueError("Reason cannot be empty")

        entry = BlacklistEntry(
            jti=jti,
            reason=reason,
            expires_at=expires_at,
            created_at=datetime.now(),
        )

        self._entries[jti] = entry

        # Auto-cleanup if needed
        if datetime.now() - self._last_cleanup > self._cleanup_interval:
            await self.cleanup()

    async def is_blacklisted(self, token_string: str) -> bool:
        """Check if a token is blacklisted."""
        jti = await self._extract_jti(token_string)

        entry = self._entries.get(jti)
        if not entry:
            return False

        # Check if entry has expired
        if datetime.now() > entry.expires_at:
            # Remove expired entry
            del self._entries[jti]
            return False

        return True

    async def remove(self, jti: str) -> None:
        """Remove a token from the blacklist."""
        if not jti:
            raise ValueError("JTI cannot be empty")

        self._entries.pop(jti, None)

    async def cleanup(self) -> None:
        """Clean up expired entries from the blacklist."""
        now = datetime.now()
        expired_keys = [
            jti for jti, entry in self._entries.items() if now > entry.expires_at
        ]

        for jti in expired_keys:
            del self._entries[jti]

        self._last_cleanup = now

    async def get_stats(self) -> BlacklistStats:
        """Get blacklist statistics."""
        now = datetime.now()
        active_entries = 0
        expired_entries = 0

        for entry in self._entries.values():
            if now > entry.expires_at:
                expired_entries += 1
            else:
                active_entries += 1

        # Estimate memory usage (rough estimate: 200 bytes per entry)
        memory_usage = len(self._entries) * 200

        return BlacklistStats(
            total_entries=active_entries + expired_entries,
            expired_entries=expired_entries,
            active_entries=active_entries,
            last_cleanup=self._last_cleanup,
            memory_usage=memory_usage,
        )

    async def _extract_jti(self, token_string: str) -> str:
        """Extract JTI from token string."""
        if not token_string:
            raise ValueError("Token string cannot be empty")

        # Remove Bearer prefix if present
        token_string = token_string.replace("Bearer ", "", 1)

        try:
            # Decode without verification to extract JTI
            payload = jwt.decode(token_string, options={"verify_signature": False})

            if "jti" not in payload:
                raise ValueError("JTI not found in token")

            return payload["jti"]
        except Exception as e:
            raise ValueError(f"Failed to extract JTI: {e}")


class RedisClient(Protocol):
    """Redis client interface for Redis-based blacklist."""

    async def set(
        self, key: str, value: str, ex: Optional[int] = None
    ) -> None:
        """Set a key-value pair with optional expiration."""
        ...

    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        ...

    async def delete(self, key: str) -> None:
        """Delete a key."""
        ...

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        ...

    async def keys(self, pattern: str) -> list:
        """Get keys matching pattern."""
        ...

    async def ttl(self, key: str) -> int:
        """Get TTL for a key."""
        ...


class RedisBlacklist(Blacklist):
    """Redis-based blacklist implementation."""

    def __init__(self, client: RedisClient, prefix: str = "jwt:blacklist"):
        """Initialize Redis blacklist."""
        self.client = client
        self.prefix = prefix

    async def add(self, jti: str, reason: str, expires_at: datetime) -> None:
        """Add a token to the Redis blacklist."""
        if not jti:
            raise ValueError("JTI cannot be empty")
        if not reason:
            raise ValueError("Reason cannot be empty")

        key = self._get_key(jti)
        entry = BlacklistEntry(
            jti=jti,
            reason=reason,
            expires_at=expires_at,
            created_at=datetime.now(),
        )

        ttl = int((expires_at - datetime.now()).total_seconds())
        if ttl <= 0:
            raise ValueError("Token already expired")

        await self.client.set(key, entry.json(), ex=ttl)

    async def is_blacklisted(self, token_string: str) -> bool:
        """Check if a token is blacklisted in Redis."""
        jti = await self._extract_jti(token_string)
        key = self._get_key(jti)

        return await self.client.exists(key)

    async def remove(self, jti: str) -> None:
        """Remove a token from the Redis blacklist."""
        if not jti:
            raise ValueError("JTI cannot be empty")

        key = self._get_key(jti)
        await self.client.delete(key)

    async def cleanup(self) -> None:
        """Clean up expired entries (Redis handles this automatically via TTL)."""
        # Redis automatically removes expired keys, but we can force cleanup
        pattern = f"{self.prefix}:*"
        keys = await self.client.keys(pattern)

        expired_keys = []
        for key in keys:
            ttl = await self.client.ttl(key)
            if ttl < 0:
                expired_keys.append(key)

        for key in expired_keys:
            await self.client.delete(key)

    async def get_stats(self) -> BlacklistStats:
        """Get blacklist statistics from Redis."""
        pattern = f"{self.prefix}:*"
        keys = await self.client.keys(pattern)

        active_entries = 0
        expired_entries = 0

        for key in keys:
            ttl = await self.client.ttl(key)
            if ttl > 0:
                active_entries += 1
            else:
                expired_entries += 1

        return BlacklistStats(
            total_entries=active_entries + expired_entries,
            expired_entries=expired_entries,
            active_entries=active_entries,
            last_cleanup=datetime.now(),  # Redis cleanup is continuous
        )

    def _get_key(self, jti: str) -> str:
        """Generate Redis key for a JTI."""
        return f"{self.prefix}:{jti}"

    async def _extract_jti(self, token_string: str) -> str:
        """Extract JTI from token string."""
        if not token_string:
            raise ValueError("Token string cannot be empty")

        # Remove Bearer prefix if present
        token_string = token_string.replace("Bearer ", "", 1)

        try:
            # Decode without verification to extract JTI
            payload = jwt.decode(token_string, options={"verify_signature": False})

            if "jti" not in payload:
                raise ValueError("JTI not found in token")

            return payload["jti"]
        except Exception as e:
            raise ValueError(f"Failed to extract JTI: {e}")


class HybridBlacklist(Blacklist):
    """Hybrid blacklist combining memory and Redis for high performance."""

    def __init__(self, redis_client: RedisClient, prefix: Optional[str] = None):
        """Initialize hybrid blacklist."""
        self.memory = MemoryBlacklist()
        self.redis = RedisBlacklist(redis_client, prefix or "jwt:blacklist")
        self.sync_enabled = True

    async def add(self, jti: str, reason: str, expires_at: datetime) -> None:
        """Add a token to both memory and Redis blacklists."""
        # Add to memory first (fast)
        await self.memory.add(jti, reason, expires_at)

        # Add to Redis for persistence (may be slower)
        if self.sync_enabled:
            try:
                await self.redis.add(jti, reason, expires_at)
            except Exception as e:
                # Log error but don't fail - memory blacklist is still active
                raise ValueError(f"Failed to sync to Redis: {e}")

    async def is_blacklisted(self, token_string: str) -> bool:
        """Check memory first, then Redis if not found."""
        # Check memory first (fastest)
        memory_result = await self.memory.is_blacklisted(token_string)
        if memory_result:
            return True

        # Check Redis if not in memory
        if self.sync_enabled:
            return await self.redis.is_blacklisted(token_string)

        return False

    async def remove(self, jti: str) -> None:
        """Remove from both memory and Redis."""
        # Remove from memory
        await self.memory.remove(jti)

        # Remove from Redis
        if self.sync_enabled:
            await self.redis.remove(jti)

    async def cleanup(self) -> None:
        """Clean up both memory and Redis."""
        # Cleanup memory
        await self.memory.cleanup()

        # Cleanup Redis
        if self.sync_enabled:
            await self.redis.cleanup()

    async def get_stats(self) -> BlacklistStats:
        """Get combined statistics."""
        mem_stats = await self.memory.get_stats()

        if not self.sync_enabled:
            return mem_stats

        try:
            redis_stats = await self.redis.get_stats()

            # Combine stats (Redis is authoritative for total counts)
            return BlacklistStats(
                total_entries=redis_stats.total_entries,
                expired_entries=redis_stats.expired_entries,
                active_entries=redis_stats.active_entries,
                last_cleanup=mem_stats.last_cleanup,
                memory_usage=mem_stats.memory_usage,
            )
        except Exception:
            # Return memory stats if Redis fails
            return mem_stats

    def set_sync_enabled(self, enabled: bool) -> None:
        """Enable or disable Redis synchronization."""
        self.sync_enabled = enabled