"""Bounded process-local login throttle; never records usernames/passwords."""
import threading
import time
from collections import deque


class LoginLimiter:
    def __init__(self, clock=time.monotonic):
        self.clock=clock
        self.entries={}
        self.lock=threading.Lock()

    def admit(self, address):
        with self.lock:
            now=self.clock()
            for key in list(self.entries):
                queue=self.entries[key]
                while queue and queue[0]<=now-60:queue.popleft()
                if not queue:del self.entries[key]
            if address not in self.entries and len(self.entries)>=1024:return False
            queue=self.entries.setdefault(address,deque())
            if len(queue)>=10:return False
            queue.append(now)
            return True
