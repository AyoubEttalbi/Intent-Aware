from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()

class Job(Base):
    __tablename__ = 'jobs'
    id = Column(String, primary_key=True)
    spec_url = Column(String)
    base_url = Column(String)
    description = Column(Text)
    status = Column(String, default='pending')
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    results = Column(JSON)
    error = Column(Text)

class Bug(Base):
    __tablename__ = 'bugs'
    id = Column(Integer, primary_key=True)
    job_id = Column(String, ForeignKey('jobs.id'))
    severity = Column(String)
    reason = Column(Text)
    scenario_name = Column(String)
    endpoint = Column(String)
    method = Column(String)
    reproduction_json = Column(JSON)
    response_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

# Database Setup
DATABASE_URL = "sqlite:///./qa_agent.db" # Can be changed to postgresql://...
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
