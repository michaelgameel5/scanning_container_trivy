"""
Pydantic Schemas for Container Vulnerability Scanner API

This module defines request/response schemas for the FastAPI endpoints.
Schemas provide:
- Input validation
- API documentation (OpenAPI/Swagger)
- Type safety for request/response handling
- Serialization/deserialization of database models

Security Design Decisions:
- Input validation prevents malicious data injection
- Explicit field definitions prevent over-posting attacks
- Response schemas control what data is exposed to clients
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional
from datetime import datetime
import re


# =============================================================================
# Request Schemas
# =============================================================================

class ScanRequest(BaseModel):
    """
    Request schema for submitting a new image scan.
    
    Validates that the image name follows Docker image naming conventions.
    """
    image_name: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Docker image name to scan (e.g., nginx:latest, docker.io/library/alpine:3.14)"
    )
    
    @validator('image_name')
    def validate_image_name(cls, v):
        """
        Validate Docker image name format.
        
        Accepts formats:
        - image:tag
        - registry/image:tag
        - registry/namespace/image:tag
        - registry:port/namespace/image:tag
        
        Security: Prevents command injection by validating input format
        """
        # Remove leading/trailing whitespace
        v = v.strip()
        
        # Basic validation: alphanumeric, dots, dashes, underscores, colons, slashes
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]*$'
        if not re.match(pattern, v):
            raise ValueError('Invalid image name format. Use: [registry/]image[:tag]')
        
        return v


# =============================================================================
# Response Schemas
# =============================================================================

class VulnerabilityResponse(BaseModel):
    """
    Response schema for individual vulnerability details.
    """
    id: int
    vulnerability_id: str = Field(..., description="CVE identifier (e.g., CVE-2021-44228)")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    package_name: str = Field(..., description="Name of the vulnerable package")
    installed_version: Optional[str] = Field(None, description="Currently installed version")
    fixed_version: Optional[str] = Field(None, description="Version that fixes the vulnerability")
    title: Optional[str] = Field(None, description="Short vulnerability description")
    description: Optional[str] = Field(None, description="Detailed vulnerability description")
    target: Optional[str] = Field(None, description="Target file/layer where found")
    pkg_type: Optional[str] = Field(None, description="Package type (os, library, etc.)")
    
    class Config:
        from_attributes = True


class ImageResponse(BaseModel):
    """
    Response schema for image information.
    """
    id: int
    name: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ScanSummaryResponse(BaseModel):
    """
    Response schema for scan summary (used in list views).
    Includes vulnerability counts for quick dashboard display.
    """
    id: int
    image_id: int
    image_name: str = Field(..., description="Docker image name")
    job_name: Optional[str] = Field(None, description="Kubernetes Job name")
    status: str = Field(..., description="Scan status: pending, running, completed, failed")
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unknown_count: int = 0
    total_count: int = 0
    
    class Config:
        from_attributes = True


class ScanDetailResponse(BaseModel):
    """
    Response schema for detailed scan view including all vulnerabilities.
    """
    id: int
    image_id: int
    image_name: str
    job_name: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unknown_count: int = 0
    total_count: int = 0
    vulnerabilities: List[VulnerabilityResponse] = []
    
    class Config:
        from_attributes = True


class ScanCreatedResponse(BaseModel):
    """
    Response schema when a new scan is created.
    """
    id: int
    image_name: str
    job_name: str
    status: str
    message: str = Field(..., description="Human-readable status message")


class HealthResponse(BaseModel):
    """
    Response schema for health check endpoint.
    """
    status: str = "healthy"
    database: str = "connected"
    version: str = "1.0.0"


class StatsResponse(BaseModel):
    """
    Response schema for dashboard statistics.
    """
    total_images: int
    total_scans: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    recent_scans: List[ScanSummaryResponse]


class ErrorResponse(BaseModel):
    """
    Standard error response schema.
    """
    detail: str
    status_code: int = 500
