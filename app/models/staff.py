"""
Staff Model for WAGEPRO
Employee/staff member management
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Float, Date, Enum as SQLEnum, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.database import Base


class EmploymentType(str, enum.Enum):
    """Employment type enumeration"""
    FULL_TIME = "full_time"
    PART_TIME = "part_time"
    CASUAL = "casual"
    CONTRACT = "contract"
    SEASONAL = "seasonal"
    ADMIN = "admin"  # Admin staff - bypass rate/GPS validation


class StaffMember(Base):
    """
    Staff/Employee Model
    """
    __tablename__ = "staff_members"

    id = Column(Integer, primary_key=True, index=True)

    # Personal Information
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    id_number = Column(String(50), unique=True, nullable=True, index=True)

    # Contact Information
    email = Column(String(200), unique=True, nullable=True)
    phone = Column(String(50))
    mobile = Column(String(50))
    address = Column(Text)
    emergency_contact_name = Column(String(200))
    emergency_contact_phone = Column(String(50))

    # Employment Details
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=True, index=True)
    employment_type = Column(SQLEnum(EmploymentType), default=EmploymentType.CASUAL, nullable=False, index=True)
    position = Column(String(100))
    department = Column(String(100))

    # Employment Dates
    hire_date = Column(Date, nullable=True)
    end_date = Column(Date, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # Compensation
    hourly_rate = Column(Float, nullable=True, default=0.0)
    daily_rate = Column(Float, nullable=True, default=0.0)

    # Loan Management
    max_loan_amount = Column(Float, nullable=True, default=0.0)

    # Banking
    bank_name = Column(String(100))
    bank_account = Column(String(100))
    tax_number = Column(String(50))

    # Additional Information
    notes = Column(Text)

    # Attendance / Check-in Settings
    is_responsible = Column(Boolean, default=False)  # Must upload progress pictures
    pin_code = Column(String(6), nullable=True)  # 4-6 digit PIN for check-in
    gps_exempt = Column(Boolean, default=False)  # Can clock in from any location (multi-site/managers)
    allow_emergency_clock = Column(Boolean, default=False)  # Can clock in on no-work days

    # Face Recognition / Biometrics
    face_descriptor = Column(Text, nullable=True)  # JSON array of 128-dimension face encoding
    face_enrolled_at = Column(DateTime, nullable=True)  # Timestamp of enrollment

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    site = relationship("Site", back_populates="staff_members", foreign_keys=[site_id])

    @property
    def full_name(self):
        """Computed full name"""
        return f"{self.first_name} {self.last_name}"

    @property
    def display_name(self):
        """Display name with position"""
        if self.position:
            return f"{self.full_name} ({self.position})"
        return self.full_name

    def __repr__(self):
        return f"<StaffMember {self.full_name} - {self.employment_type.value}>"
