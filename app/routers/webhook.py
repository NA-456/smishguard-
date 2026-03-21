"""
AfricasTalking SMS webhook receiver.

AfricasTalking POSTs incoming SMS to this endpoint as application/x-www-form-urlencoded.
Docs: https://developers.africastalking.com/docs/sms/receiving

Endpoint: POST /webhook/sms/incoming
"""

import logging
import hmac
import hashlib
from datetime import datetime

from fastapi import APIRouter, Request, Form, HTTPException, Header
from fastapi.responses import PlainTextResponse
from typing import Optional

from app.engine import analyze_message
from app.config import settings
from app.services.at_client import send_sms  # optional auto-reply

logger = logging.getLogger("smishguard.webhook")

router = APIRouter()


def _verify_at_signature(body: bytes, signature: str, secret: str) -> bool:
    """
    Verify the optional HMAC-SHA256 signature AfricasTalking attaches
    when a webhook signing secret is configured in the AT dashboard.
    """
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post(
    "/sms/incoming",
    response_class=PlainTextResponse,
    summary="AfricasTalking incoming SMS webhook",
    description=(
        "AfricasTalking calls this endpoint for every incoming SMS. "
        "The message is analyzed in real time; if auto-reply is enabled "
        "and the message is flagged as danger, a warning SMS is sent back."
    ),
)
async def incoming_sms(
    request: Request,
    linkId: Optional[str]  = Form(None),
    text: str              = Form(...),
    to: str                = Form(...),
    messageId: str         = Form(...),
    date: str              = Form(...),
    # AfricasTalking sends the sender as "from" — FastAPI alias handles this
    **kwargs,
):
    # Extract 'from' field manually (reserved Python keyword)
    form_data   = await request.form()
    sender      = form_data.get("from", "unknown")
    raw_body    = await request.body()

    # ── Optional webhook signature verification ────────────────────
    if settings.at_webhook_secret:
        sig = request.headers.get("X-AT-Signature", "")
        if not sig or not _verify_at_signature(raw_body, sig, settings.at_webhook_secret):
            logger.warning(f"Webhook signature mismatch for message {messageId}")
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    logger.info(f"Incoming SMS | id={messageId} | from={sender} | to={to}")

    # ── Analyze ────────────────────────────────────────────────────
    result = analyze_message(text=text, sender=sender)

    logger.info(
        f"Analysis result | id={messageId} | level={result['level']} "
        f"score={result['score']} gh_hits={result['gh_hits']}"
    )

    if result["level"] == "danger":
        logger.warning(
            f"SMISHING DETECTED | id={messageId} | from={sender} | "
            f"triggers={[t['id'] for t in result['triggered_rules']]}"
        )

    # ── Optional auto-reply ────────────────────────────────────────
    auto_replied = False
    if settings.enable_auto_reply and result["level"] == "danger" and sender != "unknown":
        try:
            await send_sms(
                to=sender,
                message=settings.auto_reply_danger_msg,
            )
            auto_replied = True
            logger.info(f"Auto-reply sent to {sender}")
        except Exception as exc:
            logger.error(f"Auto-reply failed for {sender}: {exc}")

    # AfricasTalking expects a 200 OK with no specific body
    return PlainTextResponse("OK", status_code=200)


@router.post(
    "/sms/delivery",
    response_class=PlainTextResponse,
    summary="AfricasTalking delivery report webhook",
)
async def delivery_report(request: Request):
    """Acknowledge delivery reports (AT requires a 200 response)."""
    form = await request.form()
    logger.info(f"Delivery report: {dict(form)}")
    return PlainTextResponse("OK", status_code=200)
