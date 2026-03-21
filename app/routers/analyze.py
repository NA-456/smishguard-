"""
/api/v1/analyze  — single and batch message analysis endpoints
"""

from fastapi import APIRouter, HTTPException
from datetime import datetime

from app.models.schemas import (
    AnalyzeRequest, AnalyzeResponse, TriggeredRule,
    BatchAnalyzeRequest, BatchAnalyzeResponse, BatchResult,
)
from app.engine import analyze_message, analyze_batch

router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a single SMS message",
    description=(
        "Score one SMS against all active global and Ghana-specific rules. "
        "Returns a risk level (safe / suspicious / danger), score 0–100, "
        "triggered rule details, and a recommended action."
    ),
)
async def analyze_single(req: AnalyzeRequest) -> AnalyzeResponse:
    result = analyze_message(
        text=req.text,
        sender=req.sender or "",
        sender_type=req.sender_type or "unknown",
    )
    return AnalyzeResponse(
        score=result["score"],
        level=result["level"],
        triggered_rules=[TriggeredRule(**t) for t in result["triggered_rules"]],
        gh_hits=result["gh_hits"],
        summary=result["summary"],
        recommendation=result["recommendation"],
        analyzed_at=datetime.utcnow(),
    )


@router.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    summary="Analyze a batch of SMS messages (max 100)",
    description=(
        "Submit up to 100 messages in one call. "
        "Useful for bulk scanning an inbox export or historical data."
    ),
)
async def analyze_batch_endpoint(req: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    messages = [m.model_dump() for m in req.messages]
    results  = analyze_batch(messages)

    danger_count     = sum(1 for r in results if r["level"] == "danger")
    suspicious_count = sum(1 for r in results if r["level"] == "suspicious")
    safe_count       = sum(1 for r in results if r["level"] == "safe")

    return BatchAnalyzeResponse(
        total=len(results),
        danger_count=danger_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        results=[BatchResult(**r) for r in results],
        analyzed_at=datetime.utcnow(),
    )
