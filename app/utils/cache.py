"""
Indicator caching layer for improved threat matching performance
"""

import json
import time
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod


class IndicatorCache(ABC):
    """Abstract base class for indicator caching"""

    @abstractmethod
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached indicator"""
        pass

    @abstractmethod
    def set(self, key: str, value: Dict[str, Any], ttl: int = 3600) -> None:
        """Cache indicator with TTL"""
        pass

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete cached indicator"""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear entire cache"""
        pass


class InMemoryCache(IndicatorCache):
    """Simple in-memory cache with TTL support"""

    def __init__(self, max_size: int = 10000):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl_map: Dict[str, float] = {}
        self.max_size = max_size

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached value if not expired"""
        if key not in self.cache:
            return None

        # Check if expired
        if key in self.ttl_map:
            if time.time() > self.ttl_map[key]:
                del self.cache[key]
                del self.ttl_map[key]
                return None

        return self.cache[key]

    def set(self, key: str, value: Dict[str, Any], ttl: int = 3600) -> None:
        """Cache value with TTL"""
        # Simple LRU: if at capacity, remove oldest entry
        if len(self.cache) >= self.max_size and key not in self.cache:
            oldest_key = min(self.ttl_map.keys(), key=lambda k: self.ttl_map[k])
            del self.cache[oldest_key]
            del self.ttl_map[oldest_key]

        self.cache[key] = value
        self.ttl_map[key] = time.time() + ttl

    def delete(self, key: str) -> None:
        """Remove cached entry"""
        self.cache.pop(key, None)
        self.ttl_map.pop(key, None)

    def clear(self) -> None:
        """Clear all cache"""
        self.cache.clear()
        self.ttl_map.clear()


class RedisCache(IndicatorCache):
    """Redis-based indicator cache"""

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        """Initialize Redis cache"""
        try:
            import redis
            self.redis = redis.Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=True,
                socket_connect_timeout=5
            )
            # Test connection
            self.redis.ping()
            self.available = True
        except Exception as e:
            print(f"Redis not available: {e}. Falling back to in-memory cache.")
            self.redis = None
            self.available = False

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached indicator from Redis"""
        if not self.available:
            return None

        try:
            value = self.redis.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception:
            return None

    def set(self, key: str, value: Dict[str, Any], ttl: int = 3600) -> None:
        """Cache indicator in Redis with TTL"""
        if not self.available:
            return

        try:
            self.redis.setex(key, ttl, json.dumps(value))
        except Exception:
            pass

    def delete(self, key: str) -> None:
        """Delete cached indicator"""
        if not self.available:
            return

        try:
            self.redis.delete(key)
        except Exception:
            pass

    def clear(self) -> None:
        """Clear entire cache"""
        if not self.available:
            return

        try:
            self.redis.flushdb()
        except Exception:
            pass


class CachedIndicatorManager:
    """Manages cached indicator lookups"""

    def __init__(self, cache: Optional[IndicatorCache] = None,
                 use_redis: bool = False):
        """
        Initialize cached indicator manager.
        
        Args:
            cache: Custom cache implementation
            use_redis: Try to use Redis, fall back to in-memory if unavailable
        """
        if cache:
            self.cache = cache
        elif use_redis:
            self.cache = RedisCache()
        else:
            self.cache = InMemoryCache()

    def get_cache_key(self, value: str, indicator_type: str) -> str:
        """Generate cache key for indicator"""
        return f"indicator:{indicator_type}:{value}"

    def get_cached(self, value: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Get cached indicator"""
        key = self.get_cache_key(value, indicator_type)
        return self.cache.get(key)

    def cache_indicator(self, value: str, indicator_type: str, 
                       indicator_data: Dict[str, Any], ttl: int = 3600) -> None:
        """Cache an indicator"""
        key = self.get_cache_key(value, indicator_type)
        self.cache.set(key, indicator_data, ttl)

    def invalidate_indicator(self, value: str, indicator_type: str) -> None:
        """Invalidate cached indicator"""
        key = self.get_cache_key(value, indicator_type)
        self.cache.delete(key)

    def invalidate_by_type(self, indicator_type: str) -> None:
        """Invalidate all indicators of a type (clears cache for simplicity)"""
        # For in-memory cache, this is simple. For Redis, could implement scans.
        self.cache.clear()
