"""
Enterprise Configuration Settings for Orizon
Supports multiple environments and comprehensive configuration
"""
from typing import Optional, List
from pydantic import Field, validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import os


class DatabaseSettings(BaseSettings):
    """Database configuration"""
    postgres_host: str = Field(default="localhost", env="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, env="POSTGRES_PORT")
    postgres_user: str = Field(default="orizon", env="POSTGRES_USER")
    postgres_password: str = Field(default="orizon_secure", env="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="orizon_enterprise", env="POSTGRES_DB")
    pool_size: int = Field(default=20, env="DB_POOL_SIZE")
    max_overflow: int = Field(default=40, env="DB_MAX_OVERFLOW")
    pool_recycle: int = Field(default=3600, env="DB_POOL_RECYCLE")

    @property
    def database_url(self) -> str:
        return f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def sync_database_url(self) -> str:
        return f"postgresql://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"


class RedisSettings(BaseSettings):
    """Redis configuration for caching and task queue"""
    redis_host: str = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_db: int = Field(default=0, env="REDIS_DB")
    redis_cache_db: int = Field(default=1, env="REDIS_CACHE_DB")
    redis_ttl: int = Field(default=3600, env="REDIS_TTL")

    @property
    def redis_url(self) -> str:
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def cache_url(self) -> str:
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_cache_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_cache_db}"


class CelerySettings(BaseSettings):
    """Celery distributed task queue configuration"""
    celery_broker_url: Optional[str] = Field(default=None, env="CELERY_BROKER_URL")
    celery_result_backend: Optional[str] = Field(default=None, env="CELERY_RESULT_BACKEND")
    celery_task_track_started: bool = Field(default=True, env="CELERY_TASK_TRACK_STARTED")
    celery_task_time_limit: int = Field(default=3600, env="CELERY_TASK_TIME_LIMIT")
    celery_task_soft_time_limit: int = Field(default=3000, env="CELERY_TASK_SOFT_TIME_LIMIT")
    celery_worker_concurrency: int = Field(default=10, env="CELERY_WORKER_CONCURRENCY")
    celery_worker_prefetch_multiplier: int = Field(default=4, env="CELERY_WORKER_PREFETCH_MULTIPLIER")


class SecuritySettings(BaseSettings):
    """Security and authentication configuration"""
    secret_key: str = Field(default="change-me-in-production-super-secret-key-12345", env="SECRET_KEY")
    algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=60, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    api_key_header_name: str = Field(default="X-API-Key", env="API_KEY_HEADER_NAME")
    cors_origins: List[str] = Field(default=["*"], env="CORS_ORIGINS")

    @validator("cors_origins", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


class ScanningSettings(BaseSettings):
    """Advanced scanning configuration"""
    max_concurrent_scans: int = Field(default=100, env="MAX_CONCURRENT_SCANS")
    dns_timeout: int = Field(default=5, env="DNS_TIMEOUT")
    http_timeout: int = Field(default=10, env="HTTP_TIMEOUT")
    port_scan_timeout: int = Field(default=5, env="PORT_SCAN_TIMEOUT")
    max_retries: int = Field(default=3, env="MAX_RETRIES")
    retry_delay: float = Field(default=1.0, env="RETRY_DELAY")
    user_agent: str = Field(
        default="Orizon-Enterprise/2.0 (Security Scanner; +https://orizon.one)",
        env="USER_AGENT"
    )

    # Rate limiting
    requests_per_second: int = Field(default=50, env="REQUESTS_PER_SECOND")
    burst_size: int = Field(default=100, env="BURST_SIZE")

    # Ports to scan
    common_ports: List[int] = Field(
        default=[21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888],
        env="COMMON_PORTS"
    )

    # Advanced features
    enable_screenshots: bool = Field(default=True, env="ENABLE_SCREENSHOTS")
    enable_vulnerability_scan: bool = Field(default=True, env="ENABLE_VULNERABILITY_SCAN")
    enable_tech_detection: bool = Field(default=True, env="ENABLE_TECH_DETECTION")
    enable_waf_detection: bool = Field(default=True, env="ENABLE_WAF_DETECTION")
    enable_ssl_analysis: bool = Field(default=True, env="ENABLE_SSL_ANALYSIS")


class APISettings(BaseSettings):
    """External API keys and credentials"""
    virustotal_api_key: Optional[str] = Field(default=None, env="VIRUSTOTAL_API_KEY")
    securitytrails_api_key: Optional[str] = Field(default=None, env="SECURITYTRAILS_API_KEY")
    censys_id: Optional[str] = Field(default=None, env="CENSYS_ID")
    censys_secret: Optional[str] = Field(default=None, env="CENSYS_SECRET")
    shodan_api_key: Optional[str] = Field(default=None, env="SHODAN_API_KEY")
    hunter_io_api_key: Optional[str] = Field(default=None, env="HUNTER_IO_API_KEY")
    geoip_license_key: Optional[str] = Field(default=None, env="GEOIP_LICENSE_KEY")
    whoisxml_api_key: Optional[str] = Field(default=None, env="WHOISXML_API_KEY")


class MonitoringSettings(BaseSettings):
    """Monitoring and observability configuration"""
    enable_prometheus: bool = Field(default=True, env="ENABLE_PROMETHEUS")
    enable_sentry: bool = Field(default=False, env="ENABLE_SENTRY")
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")


class StorageSettings(BaseSettings):
    """File storage configuration"""
    storage_backend: str = Field(default="local", env="STORAGE_BACKEND")  # local, s3, minio
    local_storage_path: str = Field(default="./storage", env="LOCAL_STORAGE_PATH")
    s3_bucket: Optional[str] = Field(default=None, env="S3_BUCKET")
    s3_region: Optional[str] = Field(default=None, env="S3_REGION")
    s3_access_key: Optional[str] = Field(default=None, env="S3_ACCESS_KEY")
    s3_secret_key: Optional[str] = Field(default=None, env="S3_SECRET_KEY")


class NotificationSettings(BaseSettings):
    """Notification and webhook configuration"""
    enable_webhooks: bool = Field(default=True, env="ENABLE_WEBHOOKS")
    enable_email_notifications: bool = Field(default=False, env="ENABLE_EMAIL_NOTIFICATIONS")
    smtp_host: Optional[str] = Field(default=None, env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_user: Optional[str] = Field(default=None, env="SMTP_USER")
    smtp_password: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    smtp_from_email: Optional[str] = Field(default=None, env="SMTP_FROM_EMAIL")
    slack_webhook_url: Optional[str] = Field(default=None, env="SLACK_WEBHOOK_URL")
    discord_webhook_url: Optional[str] = Field(default=None, env="DISCORD_WEBHOOK_URL")


class Settings(BaseSettings):
    """Main application settings"""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow"
    )

    # Application
    app_name: str = Field(default="Orizon Enterprise", env="APP_NAME")
    app_version: str = Field(default="2.0.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    workers: int = Field(default=4, env="WORKERS")

    # Sub-configurations
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    celery: CelerySettings = Field(default_factory=CelerySettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    scanning: ScanningSettings = Field(default_factory=ScanningSettings)
    api_keys: APISettings = Field(default_factory=APISettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def is_development(self) -> bool:
        return self.environment.lower() == "development"


# Singleton instance
settings = Settings()


# Celery broker configuration
def get_celery_config():
    """Get Celery configuration"""
    redis_settings = settings.redis

    broker_url = settings.celery.celery_broker_url or redis_settings.redis_url
    result_backend = settings.celery.celery_result_backend or redis_settings.cache_url

    return {
        'broker_url': broker_url,
        'result_backend': result_backend,
        'task_serializer': 'json',
        'result_serializer': 'json',
        'accept_content': ['json'],
        'timezone': 'UTC',
        'enable_utc': True,
        'task_track_started': settings.celery.celery_task_track_started,
        'task_time_limit': settings.celery.celery_task_time_limit,
        'task_soft_time_limit': settings.celery.celery_task_soft_time_limit,
        'worker_prefetch_multiplier': settings.celery.celery_worker_prefetch_multiplier,
        'worker_max_tasks_per_child': 1000,
        'broker_connection_retry_on_startup': True,
    }
