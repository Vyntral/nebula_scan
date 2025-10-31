"""
Celery Tasks for Distributed Scanning
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any
from uuid import UUID

from celery import Task
from sqlalchemy import select, update

from workers.celery_app import celery_app
from core.scanner import EnterpriseScanner
from db.database import get_sync_session
from db.models import Scan, Subdomain, Email, Port, Vulnerability, ScanStatus
from services.notifications import NotificationService
from utils.cache import cache_manager

logger = logging.getLogger(__name__)


class ScanTask(Task):
    """Base task class with error handling"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(f"Task {task_id} failed: {exc}")
        scan_id = kwargs.get('scan_id') or (args[0] if args else None)

        if scan_id:
            try:
                with next(get_sync_session()) as session:
                    scan = session.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(exc)
                        scan.completed_at = datetime.utcnow()
                        session.commit()
            except Exception as e:
                logger.error(f"Failed to update scan status: {e}")

    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success"""
        logger.info(f"Task {task_id} completed successfully")


@celery_app.task(
    base=ScanTask,
    bind=True,
    name='workers.tasks.run_scan',
    max_retries=3,
    default_retry_delay=60
)
def run_scan(self, scan_id: str, user_id: str, config: Dict[str, Any] = None):
    """
    Execute a full domain scan

    Args:
        scan_id: UUID of the scan
        user_id: UUID of the user
        config: Scan configuration

    Returns:
        Dict with scan results
    """
    logger.info(f"Starting scan task for scan_id={scan_id}")

    try:
        with next(get_sync_session()) as session:
            # Get scan from database
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            # Update scan status
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.celery_task_id = self.request.id
            session.commit()

            # Get scan configuration
            domain = scan.target_domain
            scan_config = config or scan.config or {}

            # Run async scanner
            scanner = EnterpriseScanner(domain, config=scan_config)

            # Create new event loop for async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # Run scan with progress callback
                def progress_callback(progress: float):
                    """Update scan progress"""
                    scan.progress = progress
                    session.commit()

                results = loop.run_until_complete(scanner.run(callback=progress_callback))

            finally:
                loop.close()

            # Store results in database
            _store_scan_results(session, scan, results)

            # Update scan status
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.duration_seconds = results['duration_seconds']
            scan.summary = results['statistics']
            scan.total_subdomains = results['statistics']['total_subdomains']
            scan.active_subdomains = results['statistics']['active_subdomains']
            scan.progress = 100.0
            session.commit()

            # Cache results
            cache_manager.set_scan_results(scan_id, results)

            # Send notifications
            try:
                notification_service = NotificationService()
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    notification_service.notify_scan_completed(scan_id, user_id, results)
                )
                loop.close()
            except Exception as e:
                logger.error(f"Failed to send notifications: {e}")

            logger.info(f"Scan {scan_id} completed successfully")
            return {
                'scan_id': str(scan_id),
                'status': 'completed',
                'statistics': results['statistics']
            }

    except Exception as e:
        logger.error(f"Scan task failed: {e}", exc_info=True)
        raise


def _store_scan_results(session, scan, results: Dict[str, Any]):
    """Store scan results in database"""
    logger.info(f"Storing results for scan {scan.id}")

    subdomains_data = results.get('subdomains', {})

    for subdomain_name, data in subdomains_data.items():
        # Create subdomain record
        subdomain = Subdomain(
            scan_id=scan.id,
            subdomain=subdomain_name,
            ip_addresses=data.get('ips', []),
            is_active=data.get('is_active', False),
            is_internal_ip=data.get('is_internal', False),
            http_status=data.get('http_status'),
            https_status=data.get('https_status'),
            http_title=data.get('title'),
            http_server=data.get('server'),
            response_time_ms=data.get('response_time_ms'),
            ssl_info=data.get('ssl_info', {}),
            technologies=data.get('technologies', []),
            waf_detected=bool(data.get('waf')),
            waf_name=data.get('waf'),
            open_ports=data.get('open_ports', []),
            discovered_via=data.get('discovered_via', 'unknown'),
            metadata=data
        )
        session.add(subdomain)
        session.flush()  # Get subdomain ID

        # Store emails
        emails = data.get('emails', [])
        for email_addr in emails:
            email = Email(
                subdomain_id=subdomain.id,
                email=email_addr,
                discovered_at=datetime.utcnow()
            )
            session.add(email)

        # Store open ports details
        open_ports = data.get('open_ports', [])
        for port_num in open_ports:
            port = Port(
                subdomain_id=subdomain.id,
                port=port_num,
                state='open',
                protocol='tcp',
                scanned_at=datetime.utcnow()
            )
            session.add(port)

        # Store vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        for vuln_data in vulnerabilities:
            vulnerability = Vulnerability(
                scan_id=scan.id,
                subdomain_id=subdomain.id,
                title=vuln_data.get('type', 'Unknown'),
                description=vuln_data.get('description', ''),
                severity=vuln_data.get('severity', 'info'),
                discovered_at=datetime.utcnow(),
                metadata=vuln_data
            )
            session.add(vulnerability)

    session.commit()
    logger.info(f"Stored {len(subdomains_data)} subdomains for scan {scan.id}")


@celery_app.task(name='workers.tasks.scheduled_scan')
def scheduled_scan(scheduled_scan_id: str):
    """
    Execute a scheduled scan

    Args:
        scheduled_scan_id: UUID of the scheduled scan
    """
    logger.info(f"Running scheduled scan {scheduled_scan_id}")

    try:
        with next(get_sync_session()) as session:
            from db.models import ScheduledScan

            scheduled = session.query(ScheduledScan).filter(
                ScheduledScan.id == scheduled_scan_id
            ).first()

            if not scheduled or not scheduled.is_active:
                logger.warning(f"Scheduled scan {scheduled_scan_id} not found or inactive")
                return

            # Create new scan
            scan = Scan(
                user_id=scheduled.user_id,
                target_domain=scheduled.target_domain,
                scan_type=scheduled.scan_type,
                status=ScanStatus.QUEUED,
                config=scheduled.config
            )
            session.add(scan)
            session.commit()

            # Update scheduled scan
            scheduled.last_run = datetime.utcnow()
            session.commit()

            # Queue the scan
            run_scan.delay(str(scan.id), str(scheduled.user_id), scheduled.config)

            logger.info(f"Scheduled scan {scheduled_scan_id} queued as scan {scan.id}")

    except Exception as e:
        logger.error(f"Scheduled scan task failed: {e}", exc_info=True)
        raise


@celery_app.task(name='workers.tasks.rescan_subdomain')
def rescan_subdomain(subdomain_id: str):
    """
    Rescan a specific subdomain for updates

    Args:
        subdomain_id: UUID of the subdomain
    """
    logger.info(f"Rescanning subdomain {subdomain_id}")

    try:
        with next(get_sync_session()) as session:
            subdomain = session.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
            if not subdomain:
                logger.warning(f"Subdomain {subdomain_id} not found")
                return

            # Create scanner for single subdomain
            scanner = EnterpriseScanner(subdomain.subdomain.split('.')[-2:])

            # Run async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # Re-check subdomain
                loop.run_until_complete(scanner._resolve_subdomain(subdomain.subdomain))
                loop.run_until_complete(scanner._check_http(subdomain.subdomain))

                # Update database
                if subdomain.subdomain in scanner.subdomains:
                    data = scanner.subdomains[subdomain.subdomain]
                    subdomain.ip_addresses = data.get('ips', [])
                    subdomain.is_active = data.get('is_active', False)
                    subdomain.http_status = data.get('http_status')
                    subdomain.https_status = data.get('https_status')
                    subdomain.last_checked = datetime.utcnow()
                    session.commit()

            finally:
                loop.close()

            logger.info(f"Subdomain {subdomain_id} rescanned successfully")

    except Exception as e:
        logger.error(f"Rescan subdomain task failed: {e}", exc_info=True)
        raise


@celery_app.task(name='workers.tasks.cleanup_old_scans')
def cleanup_old_scans(days: int = 30):
    """
    Cleanup old scan data

    Args:
        days: Delete scans older than this many days
    """
    logger.info(f"Cleaning up scans older than {days} days")

    try:
        from datetime import timedelta

        with next(get_sync_session()) as session:
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            # Delete old scans
            deleted = session.query(Scan).filter(
                Scan.created_at < cutoff_date
            ).delete()

            session.commit()

            logger.info(f"Deleted {deleted} old scans")
            return {'deleted_scans': deleted}

    except Exception as e:
        logger.error(f"Cleanup task failed: {e}", exc_info=True)
        raise


@celery_app.task(name='workers.tasks.export_scan_results')
def export_scan_results(scan_id: str, format: str = 'json'):
    """
    Export scan results to various formats

    Args:
        scan_id: UUID of the scan
        format: Export format (json, csv, xml, pdf)

    Returns:
        Path to exported file
    """
    logger.info(f"Exporting scan {scan_id} to {format}")

    try:
        from services.exporter import ExportService

        with next(get_sync_session()) as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            exporter = ExportService()
            file_path = exporter.export_scan(scan, format)

            logger.info(f"Scan {scan_id} exported to {file_path}")
            return {'file_path': file_path}

    except Exception as e:
        logger.error(f"Export task failed: {e}", exc_info=True)
        raise


# Periodic tasks
@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Setup periodic tasks"""

    # Cleanup old scans daily at 2 AM
    sender.add_periodic_task(
        crontab(hour=2, minute=0),
        cleanup_old_scans.s(),
        name='cleanup-old-scans-daily'
    )

    # Check scheduled scans every 5 minutes
    sender.add_periodic_task(
        300.0,  # 5 minutes
        check_scheduled_scans.s(),
        name='check-scheduled-scans'
    )


@celery_app.task(name='workers.tasks.check_scheduled_scans')
def check_scheduled_scans():
    """Check and execute due scheduled scans"""
    logger.info("Checking for due scheduled scans")

    try:
        with next(get_sync_session()) as session:
            from db.models import ScheduledScan

            # Find due scans
            now = datetime.utcnow()
            due_scans = session.query(ScheduledScan).filter(
                ScheduledScan.is_active == True,
                ScheduledScan.next_run <= now
            ).all()

            for scheduled in due_scans:
                scheduled_scan.delay(str(scheduled.id))

            logger.info(f"Queued {len(due_scans)} scheduled scans")

    except Exception as e:
        logger.error(f"Check scheduled scans failed: {e}", exc_info=True)
