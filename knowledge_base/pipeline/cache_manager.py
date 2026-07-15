from typing import Any, Dict

class CacheManager:
    _caches: Dict[str, Any] = {}
    
    @classmethod
    def get(cls, key: str) -> Any:
        return cls._caches.get(key)
        
    @classmethod
    def set(cls, key: str, value: Any) -> None:
        cls._caches[key] = value
        
    @classmethod
    def clear(cls, key: str = None) -> None:
        if key:
            if key in cls._caches:
                del cls._caches[key]
        else:
            cls._caches.clear()
            
    @classmethod
    def has(cls, key: str) -> bool:
        return key in cls._caches
