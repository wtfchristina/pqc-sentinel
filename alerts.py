import httpx
import logging

logger = logging.getLogger(__name__)

async def send_drift_alert(webhook_url: str, alert_payload: dict):
    if not webhook_url:
        return

    try:
        async with httpx.AsyncClient() as client:
            # We can format the payload generically, or assume it's suitable for Slack/Discord (e.g., using "content" or "text")
            # For simplicity, we just send standard JSON which many generic webhooks support.
            response = await client.post(webhook_url, json=alert_payload)
            response.raise_for_status()
            logger.info(f"Drift alert sent successfully to {webhook_url}")
    except httpx.HTTPError as e:
        logger.error(f"Failed to send drift alert to {webhook_url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error when sending drift alert: {e}")
