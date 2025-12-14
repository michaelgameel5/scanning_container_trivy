"""
Database Connection Configuration for Container Vulnerability Scanner

This module handles PostgreSQL database connection setup using SQLAlchemy.

Security Design Decisions:
- Database credentials are loaded from environment variables (never hardcoded)
- Connection string is constructed dynamically for flexibility
- Session management follows best practices for connection pooling
- Base class is shared across all models for consistent schema management
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Load database configuration from environment variables
# These will be provided via Kubernetes Secrets mounted as env vars
# This follows the 12-factor app methodology for configuration
POSTGRES_USER = os.getenv("POSTGRES_USER", "vulnscanner")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "vulnscanner_secret")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "vulnscanner")

# Construct the database URL
# Format: postgresql://user:password@host:port/database
DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

# Create SQLAlchemy engine with connection pooling
# pool_pre_ping: Ensures connections are valid before use (handles DB restarts)
# pool_size: Number of connections to maintain in the pool
# max_overflow: Additional connections allowed beyond pool_size during high load
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10
)

# SessionLocal class will be used to create database sessions
# autocommit=False: Explicit transaction control for data integrity
# autoflush=False: Manual control over when changes are flushed to DB
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all ORM models
# All models inherit from this to share the same metadata
Base = declarative_base()


def get_db():
    """
    Dependency function for FastAPI to get database sessions.
    
    This generator function:
    1. Creates a new database session
    2. Yields it for use in the request
    3. Ensures the session is closed after the request completes
    
    Usage in FastAPI:
        @app.get("/items")
        def read_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize the database by creating all tables.
    
    This function is called on application startup to ensure
    all required tables exist. SQLAlchemy will:
    - Create tables that don't exist
    - Skip tables that already exist (safe for restarts)
    
    Note: In production, consider using Alembic for migrations
    to handle schema changes gracefully.
    """
    # Import models to register them with Base.metadata
    import models
    Base.metadata.create_all(bind=engine)
