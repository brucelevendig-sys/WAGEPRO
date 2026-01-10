"""
User Model for WAGEPRO
Authentication and access control
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum as SQLEnum, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.database import Base


class UserRole(str, enum.Enum):
    """User roles for access control"""
    ADMIN = "admin"
    MANAGER = "manager"
    VIEWER = "viewer"


class User(Base):
    """
    User accounts for system access
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    # Authentication
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)

    # Profile
    full_name = Column(String(100), nullable=False)
    email = Column(String(200), unique=True, nullable=True)

    # Role & Status
    role = Column(SQLEnum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Site assignment (for managers)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=True)
    site = relationship("Site")

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username} ({self.role.value})>"
