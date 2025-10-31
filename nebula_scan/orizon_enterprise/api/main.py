"""
FastAPI Main Application
Enterprise REST API for Orizon
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
import logging
import time

from config.settings import settings
from db.database import init_db, close_db
from api.routes import (
    auth,
    scans,
    subdomains,
    users,
    webhooks,
    scheduled_scans,
    reports,
    health
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events for startup and shutdown"""
    # Startup
    logger.info("Starting Orizon Enterprise API")

    # Initialize database
    await init_db()
    logger.info("Database initialized")

    # Initialize monitoring
    if settings.monitoring.enable_prometheus:
        from monitoring.metrics import setup_metrics
        setup_metrics(app)
        logger.info("Prometheus metrics enabled")

    # Initialize Sentry
    if settings.monitoring.enable_sentry and settings.monitoring.sentry_dsn:
        import sentry_sdk
        sentry_sdk.init(
            dsn=settings.monitoring.sentry_dsn,
            environment=settings.environment,
            traces_sample_rate=0.1,
        )
        logger.info("Sentry monitoring enabled")

    yield

    # Shutdown
    logger.info("Shutting down Orizon Enterprise API")
    await close_db()


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Enterprise-grade subdomain enumeration and security reconnaissance platform",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.security.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compression Middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = time.time()

    # Process request
    response = await call_next(request)

    # Calculate duration
    duration = time.time() - start_time

    # Log request
    logger.info(
        f"{request.method} {request.url.path} - {response.status_code} - {duration:.3f}s",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration": duration,
            "client_ip": request.client.host if request.client else None,
        }
    )

    # Add custom headers
    response.headers["X-Process-Time"] = str(duration)
    response.headers["X-API-Version"] = settings.app_version

    return response


# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": exc.errors(),
            "body": exc.body
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": str(exc) if settings.debug else "An unexpected error occurred"
        }
    )


# Include routers
app.include_router(health.router, prefix="/api/health", tags=["Health"])
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(subdomains.router, prefix="/api/subdomains", tags=["Subdomains"])
app.include_router(webhooks.router, prefix="/api/webhooks", tags=["Webhooks"])
app.include_router(scheduled_scans.router, prefix="/api/scheduled-scans", tags=["Scheduled Scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint"""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "docs": "/api/docs",
        "health": "/api/health"
    }


@app.get("/api", tags=["Root"])
async def api_info():
    """API information"""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "features": {
            "subdomain_enumeration": True,
            "vulnerability_scanning": settings.scanning.enable_vulnerability_scan,
            "technology_detection": settings.scanning.enable_tech_detection,
            "waf_detection": settings.scanning.enable_waf_detection,
            "ssl_analysis": settings.scanning.enable_ssl_analysis,
            "screenshots": settings.scanning.enable_screenshots,
            "scheduled_scans": True,
            "webhooks": settings.notifications.enable_webhooks,
            "distributed_scanning": True,
        },
        "endpoints": {
            "docs": "/api/docs",
            "health": "/api/health",
            "auth": "/api/auth",
            "scans": "/api/scans",
            "subdomains": "/api/subdomains",
            "webhooks": "/api/webhooks",
            "scheduled_scans": "/api/scheduled-scans",
            "reports": "/api/reports",
        }
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        workers=settings.workers if settings.is_production else 1,
        reload=settings.debug,
        log_level=settings.monitoring.log_level.lower(),
    )
