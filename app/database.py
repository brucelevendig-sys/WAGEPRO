"""
Database configuration for WAGEPRO
Railway PostgreSQL as PRIMARY database (single source of truth)
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Railway PostgreSQL as PRIMARY database
# Public URL for external access (local PC, etc.)
RAILWAY_POSTGRES_URL = 'postgresql://postgres:hdqWskypFFPJTwbAMdArrqDvmaOXomqF@mainline.proxy.rlwy.net:55832/railway'

# Check for Railway internal DATABASE_URL (when running ON Railway)
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# Determine database URL
if DATABASE_URL.startswith('postgres'):
    # Running ON Railway - use internal URL
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
    print("[DB] Using Railway internal PostgreSQL")
else:
    # Running locally - use Railway public URL (PRIMARY)
    SQLALCHEMY_DATABASE_URL = RAILWAY_POSTGRES_URL
    print("[DB] Using Railway PostgreSQL (remote)")

engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
