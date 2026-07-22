from sqlalchemy import Column, String, Boolean
from app.models import Base
from sqlalchemy.orm import relationship

class Organization(Base):
    __tablename__ = 'organizations'

    id = Column(String, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    is_active = Column(Boolean, default=True)
    
    users = relationship("User", back_populates="organization")
    teams = relationship("Team", back_populates="organization")