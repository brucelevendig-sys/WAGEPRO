"""
Site Model for WAGEPRO
Represents different work locations (farm, home, fourways, etc.)
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database import Base


class Site(Base):
    """
    Work sites/locations where staff can be assigned
    Examples: Farm, Home, Fourways Office
    """
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True, index=True)

    # Site Details
    name = Column(String(100), nullable=False, unique=True, index=True)
    code = Column(String(20), nullable=True, unique=True)  # e.g., "FRM", "HOM", "FRW"
    description = Column(Text, nullable=True)

    # Location
    address = Column(Text, nullable=True)

    # GPS Coordinates for geofencing
    gps_latitude = Column(Float, nullable=True)
    gps_longitude = Column(Float, nullable=True)
    gps_radius_meters = Column(Integer, default=100)  # Acceptable check-in radius

    # Banking Details
    bank_name = Column(String(100), nullable=True)
    account_number = Column(String(50), nullable=True)

    # Status
    is_active = Column(Boolean, default=True, nullable=False)

    # Standby Person (for no-work days)
    standby_staff_id = Column(Integer, ForeignKey("staff_members.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships - use string format for forward references
    staff_members = relationship("StaffMember", back_populates="site", foreign_keys="StaffMember.site_id")
    standby_staff = relationship("StaffMember", foreign_keys="Site.standby_staff_id")

    def __repr__(self):
        return f"<Site {self.name}>"
