#!/usr/bin/env python3
"""
Container Vulnerability Scanner - Worker

This worker script runs as a Kubernetes Job to scan Docker images using Trivy.
It performs the following tasks:
1. Updates scan status to RUNNING
2. Executes Trivy scan against the target image
3. Parses the JSON output to extract vulnerabilities
4. Saves vulnerability data to PostgreSQL
5. Updates scan status to COMPLETED or FAILED

Security Design Decisions:
- Uses official Trivy for comprehensive vulnerability detection
- Database credentials loaded from environment variables
- Proper error handling and status reporting
- Graceful cleanup on failure

DevOps Design Decisions:
- Runs as an ephemeral Kubernetes Job
- Auto-cleanup via TTL after completion
- Structured logging for debugging
- Exit codes reflect scan status
"""

import os
import sys
import json
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Optional

import psycopg2
from psycopg2.extras import execute_batch

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# Environment Configuration
# =============================================================================
SCAN_ID = os.getenv("SCAN_ID")
IMAGE_NAME = os.getenv("IMAGE_NAME")

# Database configuration
POSTGRES_USER = os.getenv("POSTGRES_USER", "vulnscanner")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "vulnscanner_secret")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "vulnscanner")

# Trivy configuration
TRIVY_TIMEOUT = os.getenv("TRIVY_TIMEOUT", "600")  # 10 minutes default
TRIVY_SEVERITY = os.getenv("TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN")


class ScanStatus:
    """Scan status constants matching the API."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DatabaseConnection:
    """
    Context manager for PostgreSQL connections.
    
    Handles connection lifecycle and ensures proper cleanup.
    Uses context manager pattern for safe resource management.
    """
    
    def __init__(self):
        self.conn = None
        self.cursor = None
    
    def __enter__(self):
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                database=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD
            )
            self.cursor = self.conn.cursor()
            logger.info("Database connection established")
            return self
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
        logger.info("Database connection closed")
    
    def execute(self, query: str, params: tuple = None):
        """Execute a single query."""
        self.cursor.execute(query, params)
    
    def executemany(self, query: str, params_list: list):
        """Execute a query with multiple parameter sets."""
        execute_batch(self.cursor, query, params_list)
    
    def fetchone(self):
        """Fetch one result."""
        return self.cursor.fetchone()
    
    def commit(self):
        """Commit the transaction."""
        self.conn.commit()


def update_scan_status(db: DatabaseConnection, status: str, error_message: str = None):
    """
    Update the scan status in the database.
    
    Args:
        db: Database connection
        status: New status (pending, running, completed, failed)
        error_message: Optional error message for failed scans
    """
    if status == ScanStatus.RUNNING:
        db.execute(
            "UPDATE scans SET status = %s, started_at = %s WHERE id = %s",
            (status, datetime.utcnow(), SCAN_ID)
        )
    elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
        db.execute(
            "UPDATE scans SET status = %s, completed_at = %s, error_message = %s WHERE id = %s",
            (status, datetime.utcnow(), error_message, SCAN_ID)
        )
    else:
        db.execute(
            "UPDATE scans SET status = %s WHERE id = %s",
            (status, SCAN_ID)
        )
    db.commit()
    logger.info(f"Updated scan {SCAN_ID} status to: {status}")


def run_trivy_scan(image_name: str) -> Dict:
    """
    Execute Trivy scan against the target Docker image.
    
    Args:
        image_name: Docker image to scan (e.g., nginx:latest)
    
    Returns:
        Parsed JSON output from Trivy
    
    Raises:
        Exception: If Trivy scan fails
    """
    logger.info(f"Starting Trivy scan for image: {image_name}")
    
    # Build Trivy command
    # --format json: Output in JSON for parsing
    # --severity: Filter by severity levels
    # --timeout: Prevent hanging on large images
    # --no-progress: Clean output for logs
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", TRIVY_SEVERITY,
        "--timeout", f"{TRIVY_TIMEOUT}s",
        "--no-progress",
        image_name
    ]
    
    logger.info(f"Executing command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=int(TRIVY_TIMEOUT) + 60  # Extra buffer for subprocess
        )
        
        # Log stderr for debugging (contains progress info)
        if result.stderr:
            logger.info(f"Trivy stderr: {result.stderr[:1000]}")
        
        # Parse JSON output
        if result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy JSON output: {e}")
                logger.error(f"Raw output: {result.stdout[:500]}")
                raise Exception(f"Failed to parse Trivy output: {e}")
        else:
            # Empty output might mean no vulnerabilities found
            logger.warning("Trivy returned empty output")
            return {"Results": []}
            
    except subprocess.TimeoutExpired:
        raise Exception(f"Trivy scan timed out after {TRIVY_TIMEOUT} seconds")
    except subprocess.SubprocessError as e:
        raise Exception(f"Trivy scan failed: {e}")


def parse_vulnerabilities(trivy_output: Dict) -> List[Dict]:
    """
    Parse Trivy JSON output to extract vulnerability information.
    
    Trivy output structure:
    {
        "Results": [
            {
                "Target": "nginx:latest",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgName": "log4j",
                        "InstalledVersion": "2.14.0",
                        "FixedVersion": "2.17.0",
                        "Severity": "CRITICAL",
                        "Title": "...",
                        "Description": "..."
                    }
                ]
            }
        ]
    }
    
    Args:
        trivy_output: Parsed JSON from Trivy
    
    Returns:
        List of vulnerability dictionaries ready for database insertion
    """
    vulnerabilities = []
    
    results = trivy_output.get("Results", [])
    
    for result in results:
        target = result.get("Target", "")
        pkg_type = result.get("Type", "")
        vulns = result.get("Vulnerabilities", [])
        
        if not vulns:
            continue
        
        for vuln in vulns:
            vulnerabilities.append({
                "vulnerability_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "package_name": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "title": vuln.get("Title", "")[:500] if vuln.get("Title") else None,
                "description": vuln.get("Description", "")[:2000] if vuln.get("Description") else None,
                "target": target[:500] if target else None,
                "pkg_type": pkg_type[:64] if pkg_type else None
            })
    
    logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Trivy output")
    return vulnerabilities


def save_vulnerabilities(db: DatabaseConnection, vulnerabilities: List[Dict]):
    """
    Save vulnerability records to the database.
    
    Uses batch insert for performance with large result sets.
    
    Args:
        db: Database connection
        vulnerabilities: List of vulnerability dictionaries
    """
    if not vulnerabilities:
        logger.info("No vulnerabilities to save")
        return
    
    insert_query = """
        INSERT INTO vulnerabilities 
        (scan_id, vulnerability_id, severity, package_name, installed_version, 
         fixed_version, title, description, target, pkg_type)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    
    params_list = [
        (
            SCAN_ID,
            v["vulnerability_id"],
            v["severity"],
            v["package_name"],
            v["installed_version"],
            v["fixed_version"],
            v["title"],
            v["description"],
            v["target"],
            v["pkg_type"]
        )
        for v in vulnerabilities
    ]
    
    db.executemany(insert_query, params_list)
    logger.info(f"Saved {len(vulnerabilities)} vulnerabilities to database")


def update_vulnerability_counts(db: DatabaseConnection, vulnerabilities: List[Dict]):
    """
    Update the scan record with vulnerability counts by severity.
    
    These denormalized counts enable fast dashboard queries
    without needing to aggregate vulnerability tables.
    
    Args:
        db: Database connection
        vulnerabilities: List of vulnerability dictionaries
    """
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN")
        if severity in counts:
            counts[severity] += 1
        else:
            counts["UNKNOWN"] += 1
    
    total = sum(counts.values())
    
    db.execute(
        """
        UPDATE scans SET 
            critical_count = %s,
            high_count = %s,
            medium_count = %s,
            low_count = %s,
            unknown_count = %s,
            total_count = %s
        WHERE id = %s
        """,
        (
            counts["CRITICAL"],
            counts["HIGH"],
            counts["MEDIUM"],
            counts["LOW"],
            counts["UNKNOWN"],
            total,
            SCAN_ID
        )
    )
    
    logger.info(f"Updated vulnerability counts: {counts}, total: {total}")


def main():
    """
    Main entry point for the vulnerability scanner worker.
    
    Workflow:
    1. Validate required environment variables
    2. Update scan status to RUNNING
    3. Execute Trivy scan
    4. Parse and save vulnerabilities
    5. Update scan status to COMPLETED
    
    On any error, status is updated to FAILED with error message.
    Exit code 0 indicates success, non-zero indicates failure.
    """
    logger.info("=" * 60)
    logger.info("Container Vulnerability Scanner Worker Starting")
    logger.info("=" * 60)
    
    # Validate required environment variables
    if not SCAN_ID:
        logger.error("SCAN_ID environment variable is required")
        sys.exit(1)
    
    if not IMAGE_NAME:
        logger.error("IMAGE_NAME environment variable is required")
        sys.exit(1)
    
    logger.info(f"Scan ID: {SCAN_ID}")
    logger.info(f"Image: {IMAGE_NAME}")
    logger.info(f"Database Host: {POSTGRES_HOST}")
    
    try:
        with DatabaseConnection() as db:
            # Update status to running
            update_scan_status(db, ScanStatus.RUNNING)
            
            # Run Trivy scan
            trivy_output = run_trivy_scan(IMAGE_NAME)
            
            # Parse vulnerabilities
            vulnerabilities = parse_vulnerabilities(trivy_output)
            
            # Save to database
            save_vulnerabilities(db, vulnerabilities)
            
            # Update counts
            update_vulnerability_counts(db, vulnerabilities)
            
            # Mark as completed
            update_scan_status(db, ScanStatus.COMPLETED)
            
            logger.info("=" * 60)
            logger.info("Scan completed successfully!")
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
            logger.info("=" * 60)
            
    except Exception as e:
        logger.error(f"Scan failed with error: {e}")
        
        # Try to update status to failed
        try:
            with DatabaseConnection() as db:
                update_scan_status(db, ScanStatus.FAILED, str(e)[:500])
        except Exception as db_error:
            logger.error(f"Failed to update scan status: {db_error}")
        
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
