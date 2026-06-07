from sqlalchemy import Column, Integer, String, Float
from database import Base

class Record(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    request_url = Column(String, nullable=False)
    user_agent = Column(String, nullable=False)
    method = Column(String, nullable=False)
    payload = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    timestamp = Column(String, default=None)