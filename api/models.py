"""
Database Models for Container Vulnerability Scanner

This module defines the SQLAlchemy ORM models for storing:
- Docker images being scanned
- Scan execution records with status tracking
- Vulnerability findings (CVEs) with severity levels

Security Design Decisions:
- Foreign keys ensure data integrity between related tables
- Timestamps track scan history for compliance/audit purposes
- Separate tables allow for efficient querying and indexing
- Status tracking enables monitoring of scan job lifecycle
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from database import Base


class ScanStatus(str, enum.Enum):
    """
    Scan job lifecycle states.
    
    PENDING: Job created but not yet started
    RUNNING: Trivy scan in progress
    COMPLETED: Scan finished successfully
    FAILED: Scan encountered an error
    """
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    """
    CVE severity levels as defined by CVSS scoring.
    Used for filtering and prioritization of remediation efforts.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Image(Base):
    """
    Represents a Docker image that has been scanned.
    
    Each unique image name is stored once, with multiple scans
    referencing the same image record. This supports:
    - Historical vulnerability tracking over time
    - Efficient storage (no duplicate image names)
    - Easy querying of all scans for a specific image
    """
    __tablename__ = "images"

    id = Column(Integer, primary_key=True, index=True)
    # Full image name including registry and tag (e.g., docker.io/library/nginx:1.21)
    name = Column(String(512), unique=True, nullable=False, index=True)
    # First time this image was submitted for scanning
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # Last time any scan was run on this image
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # One image can have multiple scans (historical tracking)
    scans = relationship("Scan", back_populates="image", cascade="all, delete-orphan")


class Scan(Base):
    """
    Represents a single scan execution for an image.
    
    Each scan is linked to a Kubernetes Job that runs Trivy.
    Status is updated by the worker as the job progresses.
    Multiple scans per image allow tracking vulnerability changes over time.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    # Reference to the image being scanned
    image_id = Column(Integer, ForeignKey("images.id", ondelete="CASCADE"), nullable=False)
    # Kubernetes Job name for tracking/debugging
    job_name = Column(String(255), nullable=True, index=True)
    # Current status of the scan job
    status = Column(String(50), default=ScanStatus.PENDING.value, nullable=False)
    # Error message if scan failed
    error_message = Column(Text, nullable=True)
    # Timestamps for tracking scan duration
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Vulnerability counts for quick dashboard queries (denormalized for performance)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    unknown_count = Column(Integer, default=0)
    total_count = Column(Integer, default=0)
    
    # Relationships
    image = relationship("Image", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    """
    Represents a single CVE/vulnerability found during a scan.
    
    Contains all relevant information from Trivy output:
    - CVE identifier for tracking and research
    - Severity for prioritization
    - Package information for remediation
    - Version info to understand fix availability
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    # Reference to the scan that found this vulnerability
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    # CVE identifier (e.g., CVE-2021-44228)
    vulnerability_id = Column(String(64), nullable=False, index=True)
    # Severity level from Trivy
    severity = Column(String(20), nullable=False, index=True)
    # Package where vulnerability was found
    package_name = Column(String(255), nullable=False)
    # Currently installed version with the vulnerability
    installed_version = Column(String(128), nullable=True)
    # Version that fixes the vulnerability (if available)
    fixed_version = Column(String(128), nullable=True)
    # Short description of the vulnerability
    title = Column(Text, nullable=True)
    # Detailed description
    description = Column(Text, nullable=True)
    # Target file/layer where vulnerability was found
    target = Column(String(512), nullable=True)
    # Package type (os, library, etc.)
    pkg_type = Column(String(64), nullable=True)
    
    # Relationship
    scan = relationship("Scan", back_populates="vulnerabilities")
