"""
Scans API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from db.database import get_async_session
from db.models import Scan, User, ScanStatus, ScanType
from api.schemas.scans import (
    ScanCreate, ScanResponse, ScanListResponse,
    ScanUpdate, ScanStatistics
)
from api.dependencies.auth import get_current_user
from workers.tasks import run_scan

router = APIRouter()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new scan

    - **target_domain**: Domain to scan (required)
    - **scan_type**: Type of scan (subdomain, full, quick, deep, custom)
    - **config**: Scan configuration options
    """
    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        target_domain=scan_data.target_domain,
        scan_type=scan_data.scan_type,
        status=ScanStatus.QUEUED,
        config=scan_data.config or {},
        wordlist_used=scan_data.wordlist_path
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Queue scan task
    background_tasks.add_task(
        run_scan.delay,
        str(scan.id),
        str(current_user.id),
        scan_data.config
    )

    return scan


@router.get("", response_model=ScanListResponse)
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[ScanStatus] = None,
    domain: Optional[str] = None,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    List all scans for current user

    - **skip**: Number of records to skip (pagination)
    - **limit**: Maximum number of records to return
    - **status**: Filter by scan status
    - **domain**: Filter by domain name
    """
    # Build query
    query = select(Scan).where(Scan.user_id == current_user.id)

    if status:
        query = query.where(Scan.status == status)

    if domain:
        query = query.where(Scan.target_domain.ilike(f"%{domain}%"))

    # Order by creation date
    query = query.order_by(Scan.created_at.desc())

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)

    # Get paginated results
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()

    return {
        "scans": scans,
        "total": total,
        "skip": skip,
        "limit": limit
    }


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    Get scan details by ID
    """
    query = select(Scan).where(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    )
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return scan


@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: UUID,
    scan_update: ScanUpdate,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    Update scan (e.g., cancel, pause)
    """
    query = select(Scan).where(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    )
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    # Update fields
    if scan_update.status:
        scan.status = scan_update.status

    scan.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(scan)

    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    Delete a scan and all associated data
    """
    query = select(Scan).where(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    )
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}/statistics", response_model=ScanStatistics)
async def get_scan_statistics(
    scan_id: UUID,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed statistics for a scan
    """
    query = select(Scan).where(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    )
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    # Calculate additional statistics
    from db.models import Subdomain, Vulnerability, Email

    # Count active subdomains
    active_count = await db.scalar(
        select(func.count()).where(
            Subdomain.scan_id == scan_id,
            Subdomain.is_active == True
        )
    )

    # Count vulnerabilities by severity
    vuln_query = select(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).where(
        Vulnerability.scan_id == scan_id
    ).group_by(Vulnerability.severity)

    vuln_result = await db.execute(vuln_query)
    vuln_by_severity = dict(vuln_result.all())

    # Count emails
    email_count = await db.scalar(
        select(func.count()).select_from(Email).join(Subdomain).where(
            Subdomain.scan_id == scan_id
        )
    )

    return {
        "scan_id": scan_id,
        "total_subdomains": scan.total_subdomains or 0,
        "active_subdomains": active_count or 0,
        "total_vulnerabilities": scan.total_vulnerabilities or 0,
        "vulnerabilities_by_severity": vuln_by_severity,
        "emails_found": email_count or 0,
        "duration_seconds": scan.duration_seconds,
        "scan_date": scan.created_at,
        "status": scan.status
    }


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    Cancel a running scan
    """
    query = select(Scan).where(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    )
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    if scan.status not in [ScanStatus.QUEUED, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only cancel queued or running scans"
        )

    # Cancel Celery task
    if scan.celery_task_id:
        from workers.celery_app import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    # Update scan status
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    await db.commit()

    return {"message": "Scan cancelled successfully"}


@router.post("/{scan_id}/export")
async def export_scan(
    scan_id: UUID,
    format: str = Query("json", regex="^(json|csv|pdf|html)$"),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    """
    Export scan results in various formats

    - **format**: Export format (json, csv, pdf, html)
    """
    query = select(Scan).where(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    )
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only export completed scans"
        )

    # Queue export task
    from workers.tasks import export_scan_results
    task = export_scan_results.delay(str(scan_id), format)

    return {
        "message": "Export started",
        "task_id": task.id,
        "format": format
    }
