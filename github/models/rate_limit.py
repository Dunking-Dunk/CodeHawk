from pydantic import BaseModel
from typing import Dict

class RateLimitDetail(BaseModel):
    limit: int
    remaining: int
    reset: int
    used: int

class RateLimitResponse(BaseModel):
    resources: Dict[str, RateLimitDetail]
    rate: RateLimitDetail