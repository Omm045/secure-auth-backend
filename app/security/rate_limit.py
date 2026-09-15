import time
from collections import defaultdict,deque
from fastapi import HTTPException,Request
_hits=defaultdict(deque)
def enforce_rate_limit(request:Request,limit:int, on_limited=None):
    key=request.client.host if request.client else "unknown"; now=time.monotonic(); q=_hits[key]
    while q and now-q[0]>60: q.popleft()
    if len(q)>=limit:
        if on_limited: on_limited()
        raise HTTPException(429,"Too many requests")
    q.append(now)
