"""
Redis Cache Manager
"""
import json
import logging
from typing import Any, Optional
import redis.asyncio as redis
from config.settings import settings

logger = logging.getLogger(__name__)


class CacheManager:
    """Redis cache manager for Orizon Enterprise"""

    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self._connected = False

    async def connect(self):
        """Connect to Redis"""
        if not self._connected:
            try:
                self.redis_client = await redis.from_url(
                    settings.redis.cache_url,
                    encoding="utf-8",
                    decode_responses=True
                )
                self._connected = True
                logger.info("Connected to Redis cache")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                raise

    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis_client and self._connected:
            await self.redis_client.close()
            self._connected = False
            logger.info("Disconnected from Redis cache")

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            if not self._connected:
                await self.connect()

            value = await self.redis_client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """Set value in cache with optional TTL"""
        try:
            if not self._connected:
                await self.connect()

            serialized = json.dumps(value)
            if ttl:
                await self.redis_client.setex(key, ttl, serialized)
            else:
                await self.redis_client.set(key, serialized)

            return True
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            if not self._connected:
                await self.connect()

            await self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            if not self._connected:
                await self.connect()

            return await self.redis_client.exists(key) > 0
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False

    async def get_many(self, keys: list[str]) -> dict:
        """Get multiple values from cache"""
        try:
            if not self._connected:
                await self.connect()

            values = await self.redis_client.mget(keys)
            result = {}
            for key, value in zip(keys, values):
                if value:
                    result[key] = json.loads(value)
            return result
        except Exception as e:
            logger.error(f"Cache get_many error: {e}")
            return {}

    async def set_many(
        self,
        mapping: dict[str, Any],
        ttl: Optional[int] = None
    ) -> bool:
        """Set multiple values in cache"""
        try:
            if not self._connected:
                await self.connect()

            serialized = {k: json.dumps(v) for k, v in mapping.items()}

            if ttl:
                pipe = self.redis_client.pipeline()
                for key, value in serialized.items():
                    pipe.setex(key, ttl, value)
                await pipe.execute()
            else:
                await self.redis_client.mset(serialized)

            return True
        except Exception as e:
            logger.error(f"Cache set_many error: {e}")
            return False

    async def clear_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        try:
            if not self._connected:
                await self.connect()

            keys = []
            async for key in self.redis_client.scan_iter(match=pattern):
                keys.append(key)

            if keys:
                return await self.redis_client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Cache clear_pattern error: {e}")
            return 0

    # Helper methods for common cache operations

    def get_scan_key(self, scan_id: str) -> str:
        """Get cache key for scan results"""
        return f"scan:{scan_id}"

    def get_subdomain_key(self, subdomain: str) -> str:
        """Get cache key for subdomain data"""
        return f"subdomain:{subdomain}"

    def get_user_scans_key(self, user_id: str) -> str:
        """Get cache key for user's scans"""
        return f"user:{user_id}:scans"

    async def set_scan_results(
        self,
        scan_id: str,
        results: dict,
        ttl: int = 3600
    ) -> bool:
        """Cache scan results"""
        return await self.set(self.get_scan_key(scan_id), results, ttl)

    async def get_scan_results(self, scan_id: str) -> Optional[dict]:
        """Get cached scan results"""
        return await self.get(self.get_scan_key(scan_id))

    async def invalidate_scan(self, scan_id: str) -> bool:
        """Invalidate scan cache"""
        return await self.delete(self.get_scan_key(scan_id))


# Global cache manager instance
cache_manager = CacheManager()
