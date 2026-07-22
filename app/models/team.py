from sqlalchemy import Column, String, ForeignKey
from app.models import Base
from sqlalchemy.orm import relationship

class Team(Base):
    __tablename__ = 'teams'

    id = Column(String, primary_key=True, index=True)
    name = Column(String, index=True)
    organization_id = Column(String, ForeignKey('organizations.id'))
    
    organization = relationship("Organization", back_populates="teams")