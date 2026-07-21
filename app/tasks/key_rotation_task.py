from celery import shared_task
from app.utils.key_rotation import key_manager
from app.core.logging import logger

@shared_task(name="app.tasks.key_rotation_task.rotate_jwt_keys_periodic")
def rotate_jwt_keys_periodic():
    """Periodic task to check and rotate JWT keys if they are older than 30 days."""
    try:
        # 30 days = 30 * 24 * 3600 seconds
        rotated = key_manager.check_and_rotate_key(max_age_seconds=30 * 24 * 3600)
        if rotated:
            logger.info("JWT keys rotated successfully.")
        else:
            logger.debug("JWT keys check completed: no rotation needed.")
        return rotated
    except Exception as exc:
        logger.exception("Failed to check and rotate JWT keys")
        raise
