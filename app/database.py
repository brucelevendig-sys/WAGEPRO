"""
Database configuration for WAGEPRO
Supports both SQLite (local) and PostgreSQL (Railway production)
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Check for PostgreSQL DATABASE_URL (Railway sets this)
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# Determine database URL
if DATABASE_URL.startswith('postgres'):
    # Railway uses postgres:// but SQLAlchemy needs postgresql://
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
else:
    # Local SQLite database
    SQLALCHEMY_DATABASE_URL = "sqlite:///C:/WAGEPRO/wagepro.db"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False}  # Needed for SQLite
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
