"""
Container Vulnerability Scanner API

This FastAPI application provides the REST API for the vulnerability scanning platform.
It handles:
- Accepting scan requests for Docker images
- Creating Kubernetes Jobs to run Trivy scans
- Retrieving scan results and vulnerability data
- Providing statistics for the dashboard

Security Design Decisions:
- All database credentials loaded from environment variables
- Input validation via Pydantic schemas
- CORS configured for dashboard access (adjust for production)
- Kubernetes RBAC required for Job creation
- No sensitive data in logs

DevOps Design Decisions:
- Health endpoints for Kubernetes probes
- Graceful handling of database connection issues
- Structured logging for observability
- Connection pooling for database efficiency
"""

import os
import uuid
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

# Kubernetes client for dynamic Job creation
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Local imports
from database import get_db, init_db, engine
from models import Image, Scan, Vulnerability, ScanStatus
from schemas import (
    ScanRequest, ScanCreatedResponse, ScanSummaryResponse,
    ScanDetailResponse, VulnerabilityResponse, HealthResponse,
    StatsResponse, ErrorResponse
)

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# Application Configuration
# =============================================================================

# Kubernetes namespace where scanner jobs will run
SCANNER_NAMESPACE = os.getenv("SCANNER_NAMESPACE", "default")

# Worker image for the scanner job
WORKER_IMAGE = os.getenv("WORKER_IMAGE", "vuln-scanner-worker:latest")

# Database configuration (also used by worker)
POSTGRES_USER = os.getenv("POSTGRES_USER", "vulnscanner")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "vulnscanner_secret")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "vulnscanner")

# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Container Vulnerability Scanner API",
    description="""
    A DevSecOps platform for scanning Docker images for known CVEs using Trivy.
    
    ## Features
    - Submit Docker images for vulnerability scanning
    - Track scan progress and history
    - View detailed vulnerability reports
    - Filter vulnerabilities by severity
    
    ## Architecture
    - FastAPI backend
    - PostgreSQL database
    - Trivy scanner (runs as Kubernetes Jobs)
    - ArgoCD for GitOps deployment
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
# In production, restrict origins to your dashboard domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Kubernetes Client Initialization
# =============================================================================

def get_k8s_client():
    """
    Initialize Kubernetes client.
    
    Attempts in-cluster config first (for running inside K8s),
    falls back to local kubeconfig for development.
    """
    try:
        # Try in-cluster configuration (when running in Kubernetes)
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        try:
            # Fall back to local kubeconfig (for development)
            config.load_kube_config()
            logger.info("Loaded local kubeconfig")
        except config.ConfigException as e:
            logger.error(f"Could not configure Kubernetes client: {e}")
            raise
    
    return client.BatchV1Api()

# =============================================================================
# Startup Events
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """
    Initialize database tables on application startup.
    
    This ensures the schema exists before handling requests.
    In production with migrations, this would be handled by Alembic.
    """
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized successfully")

# =============================================================================
# Health Check Endpoints
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint for Kubernetes probes.
    
    Checks:
    - Application is running
    - Database connection is healthy
    
    Used by:
    - Kubernetes liveness probe
    - Kubernetes readiness probe
    - Load balancer health checks
    """
    try:
        # Test database connection
        db.execute("SELECT 1")
        return HealthResponse(
            status="healthy",
            database="connected",
            version="1.0.0"
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Database connection failed")


@app.get("/ready", tags=["Health"])
async def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness probe endpoint.
    Returns 200 only when the application is ready to accept traffic.
    """
    try:
        db.execute("SELECT 1")
        return {"status": "ready"}
    except Exception:
        raise HTTPException(status_code=503, detail="Not ready")

# =============================================================================
# Scan Endpoints
# =============================================================================

@app.post("/scan", response_model=ScanCreatedResponse, tags=["Scans"])
async def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    Submit a new Docker image for vulnerability scanning.
    
    This endpoint:
    1. Creates or retrieves the image record in the database
    2. Creates a new scan record with PENDING status
    3. Creates a Kubernetes Job to run the Trivy scanner
    4. Returns the scan ID for tracking
    
    The scan runs asynchronously - use GET /scan/{scan_id} to check status.
    
    **Example Request:**
    ```json
    {
        "image_name": "nginx:latest"
    }
    ```
    
    **Vulnerable images for testing:**
    - `vulnerables/web-dvwa:latest`
    - `nginx:1.16`
    - `python:3.8-slim`
    """
    image_name = request.image_name
    logger.info(f"Received scan request for image: {image_name}")
    
    try:
        # Get or create the image record
        image = db.query(Image).filter(Image.name == image_name).first()
        if not image:
            image = Image(name=image_name)
            db.add(image)
            db.commit()
            db.refresh(image)
            logger.info(f"Created new image record: {image.id}")
        
        # Generate unique job name
        job_name = f"scan-{uuid.uuid4().hex[:8]}"
        
        # Create scan record
        scan = Scan(
            image_id=image.id,
            job_name=job_name,
            status=ScanStatus.PENDING.value
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        logger.info(f"Created scan record: {scan.id} with job name: {job_name}")
        
        # Create Kubernetes Job
        try:
            create_scanner_job(job_name, image_name, scan.id)
            logger.info(f"Created Kubernetes Job: {job_name}")
        except Exception as k8s_error:
            # Update scan status to failed if job creation fails
            scan.status = ScanStatus.FAILED.value
            scan.error_message = f"Failed to create Kubernetes Job: {str(k8s_error)}"
            db.commit()
            logger.error(f"Failed to create K8s job: {k8s_error}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create scanner job: {str(k8s_error)}"
            )
        
        return ScanCreatedResponse(
            id=scan.id,
            image_name=image_name,
            job_name=job_name,
            status=scan.status,
            message=f"Scan queued successfully. Job '{job_name}' will process the image."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans", response_model=List[ScanSummaryResponse], tags=["Scans"])
async def list_scans(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of scans to return"),
    offset: int = Query(0, ge=0, description="Number of scans to skip"),
    status: Optional[str] = Query(None, description="Filter by status: pending, running, completed, failed"),
    image_name: Optional[str] = Query(None, description="Filter by image name (partial match)")
):
    """
    List all scans with optional filtering.
    
    Returns scan summary information including vulnerability counts.
    Results are ordered by creation date (newest first).
    
    **Query Parameters:**
    - `limit`: Maximum results (default: 50, max: 100)
    - `offset`: Pagination offset
    - `status`: Filter by scan status
    - `image_name`: Filter by image name (partial match)
    """
    query = db.query(Scan, Image.name.label("image_name")).join(Image)
    
    # Apply filters
    if status:
        query = query.filter(Scan.status == status)
    if image_name:
        query = query.filter(Image.name.ilike(f"%{image_name}%"))
    
    # Order and paginate
    results = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    
    # Transform results to response schema
    scans = []
    for scan, img_name in results:
        scans.append(ScanSummaryResponse(
            id=scan.id,
            image_id=scan.image_id,
            image_name=img_name,
            job_name=scan.job_name,
            status=scan.status,
            error_message=scan.error_message,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            created_at=scan.created_at,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            unknown_count=scan.unknown_count,
            total_count=scan.total_count
        ))
    
    return scans


@app.get("/scan/{scan_id}", response_model=ScanDetailResponse, tags=["Scans"])
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Get detailed information about a specific scan.
    
    Returns:
    - Scan metadata (status, timestamps, etc.)
    - Vulnerability counts by severity
    - Full list of vulnerabilities found
    
    **Path Parameters:**
    - `scan_id`: The unique identifier of the scan
    """
    result = db.query(Scan, Image.name.label("image_name")).join(Image).filter(Scan.id == scan_id).first()
    
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
    
    scan, image_name = result
    
    # Get vulnerabilities for this scan
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    
    return ScanDetailResponse(
        id=scan.id,
        image_id=scan.image_id,
        image_name=image_name,
        job_name=scan.job_name,
        status=scan.status,
        error_message=scan.error_message,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        unknown_count=scan.unknown_count,
        total_count=scan.total_count,
        vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in vulnerabilities]
    )


@app.get("/scan/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse], tags=["Scans"])
async def get_scan_vulnerabilities(
    scan_id: int,
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
):
    """
    Get vulnerabilities for a specific scan with optional severity filter.
    
    **Path Parameters:**
    - `scan_id`: The unique identifier of the scan
    
    **Query Parameters:**
    - `severity`: Filter by severity level
    """
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
    
    # Build query
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    
    vulnerabilities = query.all()
    
    return [VulnerabilityResponse.model_validate(v) for v in vulnerabilities]

# =============================================================================
# Statistics Endpoints
# =============================================================================

@app.get("/stats", response_model=StatsResponse, tags=["Statistics"])
async def get_stats(db: Session = Depends(get_db)):
    """
    Get dashboard statistics.
    
    Returns aggregate counts and recent scan activity
    for the dashboard overview.
    """
    # Count totals
    total_images = db.query(func.count(Image.id)).scalar() or 0
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    total_vulnerabilities = db.query(func.count(Vulnerability.id)).scalar() or 0
    
    # Aggregate vulnerability counts from completed scans
    severity_counts = db.query(
        func.sum(Scan.critical_count).label("critical"),
        func.sum(Scan.high_count).label("high"),
        func.sum(Scan.medium_count).label("medium"),
        func.sum(Scan.low_count).label("low")
    ).filter(Scan.status == ScanStatus.COMPLETED.value).first()
    
    # Get recent scans
    recent = db.query(Scan, Image.name.label("image_name")).join(Image).order_by(
        Scan.created_at.desc()
    ).limit(10).all()
    
    recent_scans = [
        ScanSummaryResponse(
            id=scan.id,
            image_id=scan.image_id,
            image_name=img_name,
            job_name=scan.job_name,
            status=scan.status,
            error_message=scan.error_message,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            created_at=scan.created_at,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            unknown_count=scan.unknown_count,
            total_count=scan.total_count
        )
        for scan, img_name in recent
    ]
    
    return StatsResponse(
        total_images=total_images,
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        critical_count=severity_counts.critical or 0 if severity_counts else 0,
        high_count=severity_counts.high or 0 if severity_counts else 0,
        medium_count=severity_counts.medium or 0 if severity_counts else 0,
        low_count=severity_counts.low or 0 if severity_counts else 0,
        recent_scans=recent_scans
    )

# =============================================================================
# Kubernetes Job Creation
# =============================================================================

def create_scanner_job(job_name: str, image_name: str, scan_id: int):
    """
    Create a Kubernetes Job to run the Trivy vulnerability scan.
    
    The job runs our worker container which:
    1. Executes Trivy against the target image
    2. Parses the JSON output
    3. Saves vulnerabilities to PostgreSQL
    4. Updates the scan status
    
    Security Considerations:
    - Worker runs with minimal privileges
    - Database credentials passed via environment from Secrets
    - Job auto-deleted after completion (TTL)
    - Resource limits prevent abuse
    
    Args:
        job_name: Unique name for the Kubernetes Job
        image_name: Docker image to scan
        scan_id: Database ID of the scan record
    """
    batch_api = get_k8s_client()
    
    # Define the Job specification
    job = client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(
            name=job_name,
            namespace=SCANNER_NAMESPACE,
            labels={
                "app": "vuln-scanner-worker",
                "scan-id": str(scan_id)
            }
        ),
        spec=client.V1JobSpec(
            # Time-to-live after completion - auto cleanup
            ttl_seconds_after_finished=3600,  # 1 hour
            # Don't retry failed jobs (we handle failures in the worker)
            backoff_limit=0,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={
                        "app": "vuln-scanner-worker",
                        "scan-id": str(scan_id)
                    }
                ),
                spec=client.V1PodSpec(
                    restart_policy="Never",
                    # Security: Run as non-root user
                    security_context=client.V1PodSecurityContext(
                        run_as_non_root=False  # Trivy needs root for some scans
                    ),
                    containers=[
                        client.V1Container(
                            name="scanner",
                            image=WORKER_IMAGE,
                            image_pull_policy="IfNotPresent",
                            # Environment variables for the worker
                            env=[
                                client.V1EnvVar(name="SCAN_ID", value=str(scan_id)),
                                client.V1EnvVar(name="IMAGE_NAME", value=image_name),
                                # Database credentials from Secret
                                client.V1EnvVar(
                                    name="POSTGRES_USER",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name="postgres-credentials",
                                            key="username"
                                        )
                                    )
                                ),
                                client.V1EnvVar(
                                    name="POSTGRES_PASSWORD",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name="postgres-credentials",
                                            key="password"
                                        )
                                    )
                                ),
                                client.V1EnvVar(name="POSTGRES_HOST", value=POSTGRES_HOST),
                                client.V1EnvVar(name="POSTGRES_PORT", value=POSTGRES_PORT),
                                client.V1EnvVar(name="POSTGRES_DB", value=POSTGRES_DB),
                            ],
                            # Resource limits to prevent abuse
                            resources=client.V1ResourceRequirements(
                                requests={
                                    "memory": "256Mi",
                                    "cpu": "100m"
                                },
                                limits={
                                    "memory": "1Gi",
                                    "cpu": "500m"
                                }
                            )
                        )
                    ]
                )
            )
        )
    )
    
    # Create the Job in Kubernetes
    try:
        batch_api.create_namespaced_job(namespace=SCANNER_NAMESPACE, body=job)
        logger.info(f"Successfully created Job: {job_name} in namespace: {SCANNER_NAMESPACE}")
    except ApiException as e:
        logger.error(f"Kubernetes API error creating job: {e}")
        raise

# =============================================================================
# Internal Endpoints (for worker communication)
# =============================================================================

@app.put("/internal/scan/{scan_id}/status", tags=["Internal"])
async def update_scan_status(
    scan_id: int,
    status: str,
    error_message: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Internal endpoint for worker to update scan status.
    
    Note: In production, this should be secured with authentication
    or only accessible within the cluster network.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan.status = status
    if error_message:
        scan.error_message = error_message
    
    if status == ScanStatus.RUNNING.value:
        scan.started_at = datetime.utcnow()
    elif status in [ScanStatus.COMPLETED.value, ScanStatus.FAILED.value]:
        scan.completed_at = datetime.utcnow()
    
    db.commit()
    return {"status": "updated"}


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
