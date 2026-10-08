"""Shared process-local host rate and concurrent run admission limits."""
import threading
import time


class HostRateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}

    def reserve(self, host: str, interval: float, deadline: float) -> float:
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next.get(host, now))
            if scheduled >= deadline:
                raise TimeoutError("Host rate limit exceeds deadline")
            self._next[host] = scheduled + interval
            return max(0, scheduled - now)

    def defer(self, host: str, seconds: float) -> None:
        with self._lock:
            self._next[host] = max(self._next.get(host, 0), time.monotonic() + seconds)
