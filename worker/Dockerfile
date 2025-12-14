# =============================================================================
# Container Vulnerability Scanner - Worker
# =============================================================================
# This image is based on the official Trivy image and includes Python
# for parsing results and saving to PostgreSQL.
#
# Design Decisions:
# - Based on aquasec/trivy for up-to-date vulnerability database
# - Python added for database connectivity and result parsing
# - psycopg2 for PostgreSQL connection
# - Minimal additional packages to reduce attack surface
#
# Security Considerations:
# - Uses official Trivy image as base (regularly updated CVE database)
# - No unnecessary packages installed
# - Credentials passed via environment variables
# =============================================================================

FROM aquasec/trivy:latest

# Install Python and PostgreSQL client
# Alpine-based image uses apk package manager
USER root

RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-psycopg2 \
    && rm -rf /var/cache/apk/*

# Create directory for worker script
WORKDIR /worker

# Copy the scanner script
COPY scan.py /worker/scan.py

# Make script executable
RUN chmod +x /worker/scan.py

# Set Python path
ENV PYTHONUNBUFFERED=1

# Entry point runs the scanner script
# The script handles all Trivy execution and result processing
ENTRYPOINT ["python3", "/worker/scan.py"]
