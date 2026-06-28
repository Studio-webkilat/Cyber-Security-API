from pydantic import BaseModel, HttpUrl
from typing import Dict, List

class SecurityScanRequest(BaseModel):
    target_url: HttpUrl
    scan_type: str = "basic"

class ScanData(BaseModel):
    score: int
    details: Dict[str, str]
    recommendations: List[str]

class SecurityResponse(BaseModel):
    status: str
    message: str
    data: ScanData
