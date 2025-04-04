from sqlalchemy import Column, Integer, String, Text, Float, Boolean, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from db import Base  # <-- import shared base from db.py

class Repository(Base):
    __tablename__ = 'repositories'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    clone_url = Column(String)
    last_commit = Column(String)
    last_updated = Column(DateTime, default=datetime.utcnow)

class GrypeVulnerability(Base):
    __tablename__ = 'grype_vulnerabilities'
    __table_args__ = (UniqueConstraint('repository_name', 'vulnerability_id'),)
    id = Column(Integer, primary_key=True)
    repository_name = Column(String, nullable=False)
    vulnerability_id = Column(String, nullable=False)
    actual_severity = Column(String)
    predicted_severity = Column(String)
    predicted_score = Column(Float)
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    detailed_description = Column(Text)
    vulnerable_package = Column(Text)
    mitigation = Column(Text)
    explanation = Column(Text)
    false_positive = Column(Boolean, default=False)
    notified = Column(Boolean, default=False)
    query_date = Column(DateTime, default=datetime.utcnow)

class NvdVulnerability(Base):
    __tablename__ = 'nvd_vulnerabilities'
    __table_args__ = (UniqueConstraint('repository_name', 'vulnerability_id'),)
    id = Column(Integer, primary_key=True)
    repository_name = Column(String, nullable=False)
    vulnerability_id = Column(String, nullable=False)
    actual_severity = Column(String)
    predicted_severity = Column(String)
    predicted_score = Column(Float)
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    detailed_description = Column(Text)
    vulnerable_package = Column(Text)
    mitigation = Column(Text)
    explanation = Column(Text)
    false_positive = Column(Boolean, default=False)
    notified = Column(Boolean, default=False)
    query_date = Column(DateTime, default=datetime.utcnow)

class RepositoryCpe(Base):
    __tablename__ = 'repository_cpes'
    __table_args__ = (UniqueConstraint('repository_id', 'cpe'),)
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey('repositories.id'), nullable=False)
    cpe = Column(String, nullable=False)
    vendor = Column(String)
    product = Column(String)
    version = Column(String)
    repository = relationship("Repository")
