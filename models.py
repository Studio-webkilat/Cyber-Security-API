from sqlalchemy import Column, Integer, String, DateTime
from database import Base
import datetime

class HackingLog(Base):
    __tablename__ = "hacking_logs"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String)
    endpoint = Column(String)
    status_code = Column(Integer)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    user_agent = Column(String)