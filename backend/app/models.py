import time
from typing import Optional
from sqlmodel import SQLModel, Field
from pydantic import BaseModel, field_validator

class ThreatCache(SQLModel, table=True):
    """Database model for storing and caching threat scan results."""
    file_hash: str = Field(primary_key=True, index=True)
    file_name: Optional[str] = None
    risk_percentage: float = 0.0
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    verdict: str = "CLEAN"  # CLEAN | SUSPICIOUS | MALICIOUS | UNKNOWN
    threat_category: Optional[str] = "Undetected / Benign"
    engine_details: Optional[str] = None  # JSON string of vendor breakdown
    scanned_at: float = Field(default_factory=time.time)

class HashScanRequest(BaseModel):
    """Payload schema for manual hash scanning."""
    hash_value: str

    @field_validator("hash_value")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        clean = v.strip().lower()
        if len(clean) not in (32, 40, 64):
            raise ValueError("Invalid hash length. Must be MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars).")
        if not all(c in "0123456789abcdef" for c in clean):
            raise ValueError("Hash contains invalid non-hexadecimal characters.")
        return clean

class ThreatReport(BaseModel):
    """API Response model for threat analysis."""
    file_hash: str
    file_name: Optional[str] = None
    risk_percentage: float
    malicious_count: int
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int
    verdict: str
    threat_category: Optional[str] = None
    scanned_at: float

class ScanResponse(BaseModel):
    source: str
    status: str = "success"
    message: Optional[str] = None
    data: Optional[ThreatReport] = None
