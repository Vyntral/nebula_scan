"""
Database Models for Orizon Enterprise
SQLAlchemy ORM models for all entities
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text, JSON,
    ForeignKey, Float, Enum as SQLEnum, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
import uuid
import enum


Base = declarative_base()


class ScanStatus(str, enum.Enum):
    """Scan status enumeration"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class ScanType(str, enum.Enum):
    """Scan type enumeration"""
    SUBDOMAIN = "subdomain"
    FULL = "full"
    QUICK = "quick"
    DEEP = "deep"
    CUSTOM = "custom"


class VulnerabilitySeverity(str, enum.Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class UserRole(str, enum.Enum):
    """User roles"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    API = "api"


# ===================== Core Models =====================

class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    api_key = Column(String(255), unique=True, index=True)
    metadata = Column(JSONB, default={})

    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    api_tokens = relationship("APIToken", back_populates="user", cascade="all, delete-orphan")
    webhooks = relationship("Webhook", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(username='{self.username}', role='{self.role}')>"


class APIToken(Base):
    """API Token for programmatic access"""
    __tablename__ = "api_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used = Column(DateTime)
    scopes = Column(ARRAY(String), default=["read", "write"])

    # Relationships
    user = relationship("User", back_populates="api_tokens")

    def __repr__(self):
        return f"<APIToken(name='{self.name}', user_id='{self.user_id}')>"


class Scan(Base):
    """Main scan entity"""
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    target_domain = Column(String(255), nullable=False, index=True)
    scan_type = Column(SQLEnum(ScanType), default=ScanType.FULL, nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False, index=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Progress tracking
    progress = Column(Float, default=0.0)
    total_subdomains = Column(Integer, default=0)
    active_subdomains = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)

    # Configuration
    config = Column(JSONB, default={})
    wordlist_used = Column(String(255))

    # Results summary
    summary = Column(JSONB, default={})
    error_message = Column(Text)

    # Performance metrics
    duration_seconds = Column(Float)

    # Task tracking
    celery_task_id = Column(String(255), index=True)

    # Relationships
    user = relationship("User", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_status_created", "status", "created_at"),
    )

    def __repr__(self):
        return f"<Scan(domain='{self.target_domain}', status='{self.status}')>"


class Subdomain(Base):
    """Subdomain entity with enriched information"""
    __tablename__ = "subdomains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    subdomain = Column(String(255), nullable=False, index=True)

    # DNS Information
    ip_addresses = Column(ARRAY(String), default=[])
    cname = Column(String(255))
    is_active = Column(Boolean, default=False)
    is_internal_ip = Column(Boolean, default=False)

    # HTTP Information
    http_status = Column(Integer)
    https_status = Column(Integer)
    http_title = Column(String(500))
    http_server = Column(String(255))
    response_time_ms = Column(Float)
    content_length = Column(Integer)

    # SSL/TLS Information
    ssl_info = Column(JSONB, default={})
    ssl_valid = Column(Boolean)
    ssl_issuer = Column(String(255))
    ssl_expiry = Column(DateTime)

    # Technology Stack
    technologies = Column(JSONB, default=[])

    # Security Information
    waf_detected = Column(Boolean, default=False)
    waf_name = Column(String(100))
    security_headers = Column(JSONB, default={})

    # Port Information
    open_ports = Column(ARRAY(Integer), default=[])

    # Geolocation
    country = Column(String(100))
    city = Column(String(255))
    latitude = Column(Float)
    longitude = Column(Float)
    asn = Column(String(100))
    organization = Column(String(255))

    # Screenshots
    screenshot_path = Column(String(500))

    # Metadata
    discovered_via = Column(String(100))  # passive, bruteforce, etc.
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime, default=datetime.utcnow)
    metadata = Column(JSONB, default={})

    # Relationships
    scan = relationship("Scan", back_populates="subdomains")
    emails = relationship("Email", back_populates="subdomain", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="subdomain", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_subdomains_scan_subdomain", "scan_id", "subdomain"),
        Index("ix_subdomains_active", "is_active"),
    )

    def __repr__(self):
        return f"<Subdomain(name='{self.subdomain}', active={self.is_active})>"


class Email(Base):
    """Email addresses discovered"""
    __tablename__ = "emails"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    source_url = Column(String(500))
    verified = Column(Boolean, default=False)
    metadata = Column(JSONB, default={})

    # Relationships
    subdomain = relationship("Subdomain", back_populates="emails")

    __table_args__ = (
        UniqueConstraint("subdomain_id", "email", name="uix_subdomain_email"),
    )

    def __repr__(self):
        return f"<Email(email='{self.email}')>"


class Port(Base):
    """Port scan results"""
    __tablename__ = "ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20))  # open, closed, filtered
    service = Column(String(100))
    version = Column(String(255))
    banner = Column(Text)
    scanned_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    subdomain = relationship("Subdomain", back_populates="ports")

    __table_args__ = (
        Index("ix_ports_subdomain_port", "subdomain_id", "port"),
    )

    def __repr__(self):
        return f"<Port(port={self.port}, state='{self.state}')>"


class Vulnerability(Base):
    """Vulnerabilities and security issues detected"""
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id"), index=True)

    # Vulnerability details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(VulnerabilitySeverity), nullable=False, index=True)
    cvss_score = Column(Float)
    cve_id = Column(String(50), index=True)
    cwe_id = Column(String(50))

    # Location
    url = Column(String(1000))
    parameter = Column(String(255))
    evidence = Column(Text)

    # Remediation
    remediation = Column(Text)
    references = Column(ARRAY(String), default=[])

    # Status
    is_confirmed = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)

    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    metadata = Column(JSONB, default={})

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vulnerabilities_severity", "severity"),
        Index("ix_vulnerabilities_scan_severity", "scan_id", "severity"),
    )

    def __repr__(self):
        return f"<Vulnerability(title='{self.title}', severity='{self.severity}')>"


class Webhook(Base):
    """Webhook configuration for notifications"""
    __tablename__ = "webhooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    url = Column(String(500), nullable=False)
    is_active = Column(Boolean, default=True)

    # Events to trigger on
    events = Column(ARRAY(String), default=["scan.completed", "scan.failed"])

    # Authentication
    auth_type = Column(String(50))  # none, basic, bearer, custom
    auth_header = Column(String(255))
    auth_value = Column(String(500))

    # Retry configuration
    max_retries = Column(Integer, default=3)
    retry_delay = Column(Integer, default=60)

    # Statistics
    total_calls = Column(Integer, default=0)
    failed_calls = Column(Integer, default=0)
    last_called = Column(DateTime)
    last_error = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="webhooks")

    def __repr__(self):
        return f"<Webhook(name='{self.name}', url='{self.url}')>"


class Notification(Base):
    """Notification log"""
    __tablename__ = "notifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    webhook_id = Column(UUID(as_uuid=True), ForeignKey("webhooks.id"), index=True)

    event_type = Column(String(100), nullable=False)
    status = Column(String(50))  # sent, failed, pending
    payload = Column(JSONB)
    response_code = Column(Integer)
    response_body = Column(Text)
    error_message = Column(Text)

    sent_at = Column(DateTime, default=datetime.utcnow)
    retry_count = Column(Integer, default=0)

    # Relationships
    scan = relationship("Scan", back_populates="notifications")

    def __repr__(self):
        return f"<Notification(event='{self.event_type}', status='{self.status}')>"


class ScheduledScan(Base):
    """Scheduled recurring scans"""
    __tablename__ = "scheduled_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    target_domain = Column(String(255), nullable=False)
    scan_type = Column(SQLEnum(ScanType), default=ScanType.FULL)

    # Schedule configuration (cron-like)
    schedule = Column(String(100), nullable=False)  # e.g., "0 0 * * *" for daily at midnight
    timezone = Column(String(50), default="UTC")

    # Configuration
    config = Column(JSONB, default={})

    # Status
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ScheduledScan(name='{self.name}', schedule='{self.schedule}')>"


class Plugin(Base):
    """Plugin registry"""
    __tablename__ = "plugins"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False, index=True)
    version = Column(String(20), nullable=False)
    description = Column(Text)
    author = Column(String(255))
    is_enabled = Column(Boolean, default=False)
    is_official = Column(Boolean, default=False)

    # Plugin configuration
    config_schema = Column(JSONB)
    config = Column(JSONB, default={})

    # Plugin file path
    module_path = Column(String(500))

    installed_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Plugin(name='{self.name}', version='{self.version}')>"


class AuditLog(Base):
    """Audit log for security and compliance"""
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))
    resource_id = Column(UUID(as_uuid=True))
    details = Column(JSONB)
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_audit_logs_user_timestamp", "user_id", "timestamp"),
        Index("ix_audit_logs_action_timestamp", "action", "timestamp"),
    )

    def __repr__(self):
        return f"<AuditLog(action='{self.action}', timestamp='{self.timestamp}')>"
