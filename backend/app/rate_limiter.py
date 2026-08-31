import os
import time
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status

class TokenBucketRateLimiter:
    """
    In-memory Token-Bucket rate limiter for sensitive endpoints.
    Protects authentication and log ingestion from automated brute forcing and denial of service.
    """

    def __init__(self):
        self.buckets: Dict[str, Tuple[float, float]] = {}

    def check_rate_limit(
        self,
        request: Request,
        key_prefix: str = "general",
        max_tokens: int = 30,
        refill_rate_per_sec: float = 1.0
    ):
        # Bypass rate limiting during automated test execution
        if os.environ.get("TESTING") == "1":
            return

        client_ip = request.client.host if request.client else "127.0.0.1"
        key = f"{key_prefix}:{client_ip}"
        current_time = time.time()

        tokens, last_updated = self.buckets.get(key, (float(max_tokens), current_time))
        
        elapsed = current_time - last_updated
        tokens = min(float(max_tokens), tokens + (elapsed * refill_rate_per_sec))

        if tokens < 1.0:
            retry_after = int((1.0 - tokens) / refill_rate_per_sec) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Please retry after {retry_after} second(s).",
                headers={"Retry-After": str(retry_after)}
            )

        self.buckets[key] = (tokens - 1.0, current_time)

rate_limiter = TokenBucketRateLimiter()
