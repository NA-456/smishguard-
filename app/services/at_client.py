"""
AfricasTalking SMS client — thin async wrapper around the AT REST API.
Used for sending auto-reply warnings when a danger-level message is received.

Docs: https://developers.africastalking.com/docs/sms/sending
"""

import httpx
import logging
from app.config import settings

logger = logging.getLogger("smishguard.at_client")

AT_SMS_URL = "https://api.africastalking.com/version1/messaging"
AT_SANDBOX_URL = "https://api.sandbox.africastalking.com/version1/messaging"


def _sms_url() -> str:
    return AT_SANDBOX_URL if settings.environment == "development" else AT_SMS_URL


async def send_sms(to: str, message: str) -> dict:
    """
    Send an SMS via AfricasTalking.

    Parameters
    ----------
    to      : Recipient phone number in international format, e.g. +233541234567
    message : SMS body (max 160 chars for single SMS, AT handles concatenation)

    Returns the AT API response dict on success; raises on HTTP error.
    """
    if not settings.at_api_key:
        logger.warning("AT_API_KEY not set — skipping SMS send (sandbox mode)")
        return {"status": "skipped", "reason": "no api key"}

    payload = {
        "username": settings.at_username,
        "to":       to,
        "message":  message,
    }
    if settings.at_shortcode:
        payload["from"] = settings.at_shortcode

    headers = {
        "apiKey":       settings.at_api_key,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept":       "application/json",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(_sms_url(), data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"AT send_sms response: {data}")
        return data
