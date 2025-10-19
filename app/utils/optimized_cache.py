"""
Wi-Fi Security System - Optimized Caching Layer
app/utils/optimized_cache.py

HIGH-PERFORMANCE CACHING:
- Multi-layer caching (memory + Redis fallback)
- Intelligent cache invalidation
- Compressed storage for large objects
- Cache warming and preloading
- Performance monitoring
"""

import time
import json
import pickle
import threading
import logging
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import zlib

logger = logging.getLogger(__name__)

class InMemoryCache:
    """High-performance in-memory cache with LRU eviction"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: Dict[str, Dict] = {}
        self.access_order: List[str] = []
        self.lock = threading.RLock()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'evictions': 0
        }
    
    def _is_expired(self, entry: Dict) -> bool:
        """Check if cache entry is expired"""
        if entry.get('ttl') == -1:  # No expiration
            return False
        return time.time() > entry['expires_at']
    
    def _evict_lru(self):
        """Evict least recently used items"""
        while len(self.cache) >= self.max_size and self.access_order:
            lru_key = self.access_order.pop(0)
            if lru_key in self.cache:
                del self.cache[lru_key]
                self.stats['evictions'] += 1
    
    def _update_access_order(self, key: str):
        """Update access order for LRU"""
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key not in self.cache:
                self.stats['misses'] += 1
                return None
            
            entry = self.cache[key]
            
            # Check expiration
            if self._is_expired(entry):
                del self.cache[key]
                if key in self.access_order:
                    self.access_order.remove(key)
                self.stats['misses'] += 1
                return None
            
            # Update access order
            self._update_access_order(key)
            self.stats['hits'] += 1
            
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        with self.lock:
            if ttl is None:
                ttl = self.default_ttl
            
            # Evict if necessary
            self._evict_lru()
            
            # Store entry
            entry = {
                'value': value,
                'ttl': ttl,
                'expires_at': time.time() + ttl if ttl > 0 else -1,
                'created_at': time.time()
            }
            
            self.cache[key] = entry
            self._update_access_order(key)
            self.stats['sets'] += 1
            
            return True
    
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                if key in self.access_order:
                    self.access_order.remove(key)
                return True
            return False
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.access_order.clear()
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'type': 'memory',
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate': round(hit_rate, 2),
                'stats': self.stats.copy()
            }

class RedisCache:
    """Redis-based cache with fallback handling"""
    
    def __init__(self, redis_url: str = None, default_ttl: int = 300, prefix: str = 'wisec:'):
        self.redis_url = redis_url
        self.default_ttl = default_ttl
        self.prefix = prefix
        self.redis_client = None
        self.available = False
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'errors': 0
        }
        
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        if not self.redis_url:
            return
        
        try:
            import redis
            self.redis_client = redis.from_url(self.redis_url, decode_responses=False)
            # Test connection
            self.redis_client.ping()
            self.available = True
            logger.info("✅ Redis cache connected")
        except ImportError:
            logger.warning("Redis not available - install with: pip install redis")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
    
    def _make_key(self, key: str) -> str:
        """Create prefixed key"""
        return f"{self.prefix}{key}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache"""
        if not self.available:
            return None
        
        try:
            redis_key = self._make_key(key)
            data = self.redis_client.get(redis_key)
            
            if data is None:
                self.stats['misses'] += 1
                return None
            
            # Decompress and deserialize
            decompressed = zlib.decompress(data)
            value = pickle.loads(decompressed)
            
            self.stats['hits'] += 1
            return value
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.warning(f"Redis get error: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in Redis cache"""
        if not self.available:
            return False
        
        try:
            if ttl is None:
                ttl = self.default_ttl
            
            # Serialize and compress
            serialized = pickle.dumps(value)
            compressed = zlib.compress(serialized)
            
            redis_key = self._make_key(key)
            
            if ttl > 0:
                self.redis_client.setex(redis_key, ttl, compressed)
            else:
                self.redis_client.set(redis_key, compressed)
            
            self.stats['sets'] += 1
            return True
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.warning(f"Redis set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete value from Redis cache"""
        if not self.available:
            return False
        
        try:
            redis_key = self._make_key(key)
            result = self.redis_client.delete(redis_key)
            return result > 0
        except Exception as e:
            self.stats['errors'] += 1
            logger.warning(f"Redis delete error: {e}")
            return False
    
    def clear(self):
        """Clear all cache entries with prefix"""
        if not self.available:
            return
        
        try:
            keys = self.redis_client.keys(f"{self.prefix}*")
            if keys:
                self.redis_client.delete(*keys)
        except Exception as e:
            self.stats['errors'] += 1
            logger.warning(f"Redis clear error: {e}")
    
    def get_stats(self) -> Dict:
        """Get Redis cache statistics"""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        stats = {
            'type': 'redis',
            'available': self.available,
            'hit_rate': round(hit_rate, 2),
            'stats': self.stats.copy()
        }
        
        if self.available:
            try:
                info = self.redis_client.info()
                stats['redis_info'] = {
                    'used_memory_human': info.get('used_memory_human'),
                    'connected_clients': info.get('connected_clients'),
                    'keyspace_hits': info.get('keyspace_hits'),
                    'keyspace_misses': info.get('keyspace_misses')
                }
            except:
                pass
        
        return stats

class MultiLayerCache:
    """Multi-layer cache with memory and Redis backends"""
    
    def __init__(self, 
                 memory_size: int = 500, 
                 redis_url: str = None, 
                 default_ttl: int = 300):
        self.memory_cache = InMemoryCache(memory_size, default_ttl)
        self.redis_cache = RedisCache(redis_url, default_ttl)
        self.default_ttl = default_ttl
        
        logger.info(f"🗄️ Multi-layer cache initialized (memory + redis)")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache (memory first, then Redis)"""
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            return value
        
        # Try Redis cache
        value = self.redis_cache.get(key)
        if value is not None:
            # Store in memory cache for faster future access
            self.memory_cache.set(key, value)
            return value
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in both caches"""
        if ttl is None:
            ttl = self.default_ttl
        
        # Set in both caches
        memory_success = self.memory_cache.set(key, value, ttl)
        redis_success = self.redis_cache.set(key, value, ttl)
        
        return memory_success or redis_success
    
    def delete(self, key: str) -> bool:
        """Delete from both caches"""
        memory_result = self.memory_cache.delete(key)
        redis_result = self.redis_cache.delete(key)
        return memory_result or redis_result
    
    def clear(self):
        """Clear both caches"""
        self.memory_cache.clear()
        self.redis_cache.clear()
    
    def get_stats(self) -> Dict:
        """Get comprehensive cache statistics"""
        return {
            'multi_layer': True,
            'memory': self.memory_cache.get_stats(),
            'redis': self.redis_cache.get_stats()
        }

# Global cache instance
_cache_instance = None

def get_cache(redis_url: str = None) -> MultiLayerCache:
    """Get global cache instance"""
    global _cache_instance
    
    if _cache_instance is None:
        _cache_instance = MultiLayerCache(redis_url=redis_url)
    
    return _cache_instance

def cache_result(key_prefix: str = '', ttl: int = 300, include_args: bool = True):
    """Decorator to cache function results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache()
            
            # Generate cache key
            if include_args:
                key_parts = [key_prefix or func.__name__]
                if args:
                    key_parts.append(hashlib.md5(str(args).encode()).hexdigest()[:8])
                if kwargs:
                    key_parts.append(hashlib.md5(str(sorted(kwargs.items())).encode()).hexdigest()[:8])
                cache_key = '_'.join(key_parts)
            else:
                cache_key = key_prefix or func.__name__
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    return decorator

def invalidate_cache_pattern(pattern: str):
    """Invalidate cache entries matching pattern"""
    # This is a simplified implementation
    # In a full implementation, you'd scan Redis keys
    cache = get_cache()
    logger.info(f"Cache invalidation requested for pattern: {pattern}")

# Cache warming utilities
class CacheWarmer:
    """Cache warming for frequently accessed data"""
    
    def __init__(self, cache: MultiLayerCache):
        self.cache = cache
        self.warming_tasks = {}
    
    def warm_wifi_scan_data(self):
        """Warm cache with WiFi scan data"""
        try:
            from app.wifi_core.optimized_scanner import get_scanner
            scanner = get_scanner()
            
            # Get latest results and cache them
            networks = scanner.get_latest_results()
            if networks:
                self.cache.set('latest_wifi_scan', networks, ttl=600)
                logger.info(f"Cache warmed with {len(networks)} WiFi networks")
        except Exception as e:
            logger.warning(f"Failed to warm WiFi cache: {e}")
    
    def warm_model_metadata(self):
        """Warm cache with model metadata"""
        try:
            from app.ai_engine.optimized_model_loader import get_optimized_loader
            loader = get_optimized_loader()
            
            stats = loader.get_cache_stats()
            self.cache.set('model_stats', stats, ttl=300)
            logger.info("Cache warmed with model metadata")
        except Exception as e:
            logger.warning(f"Failed to warm model cache: {e}")
    
    def warm_all(self):
        """Warm all cache data"""
        self.warm_wifi_scan_data()
        self.warm_model_metadata()

# Example usage functions
@cache_result('wifi_networks', ttl=120)
def get_cached_wifi_networks():
    """Example cached function for WiFi networks"""
    from app.wifi_core.optimized_scanner import get_scanner
    scanner = get_scanner()
    return scanner.get_latest_results()

@cache_result('system_health', ttl=60)
def get_cached_system_health():
    """Example cached function for system health"""
    return {
        'timestamp': time.time(),
        'status': 'healthy',
        'uptime': time.time()
    }