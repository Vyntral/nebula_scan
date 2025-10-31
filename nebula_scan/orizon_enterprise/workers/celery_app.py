"""
Celery Application for Distributed Task Processing
"""
from celery import Celery
from celery.signals import task_prerun, task_postrun, task_failure
import logging

from config.settings import settings, get_celery_config

logger = logging.getLogger(__name__)

# Initialize Celery app
celery_app = Celery('orizon_enterprise')
celery_app.config_from_object(get_celery_config())

# Auto-discover tasks from all modules
celery_app.autodiscover_tasks([
    'workers.tasks',
])


@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **extra):
    """Handler called before task execution"""
    logger.info(f"Task {task.name} [{task_id}] starting")


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, **extra):
    """Handler called after task execution"""
    logger.info(f"Task {task.name} [{task_id}] completed")


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, args=None, kwargs=None, traceback=None, **extra):
    """Handler called when task fails"""
    logger.error(f"Task {sender.name} [{task_id}] failed: {exception}")


if __name__ == '__main__':
    celery_app.start()
