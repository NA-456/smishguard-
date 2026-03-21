"""
/api/v1/admin — runtime rule management endpoints.

In production, protect these with an API key or OAuth scope.
For now, a simple Bearer token check is used.
"""

import os
from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.schemas import (
    RulesListResponse, RuleSummary,
    RuleToggleRequest, RuleWeightRequest,
)
from app.engine import get_rules_summary, toggle_rule, set_rule_weight, ALL_RULES

router  = APIRouter()
_bearer = HTTPBearer(auto_error=False)

ADMIN_TOKEN = os.getenv("SMISHGUARD_ADMIN_TOKEN", "changeme")


def require_admin(creds: HTTPAuthorizationCredentials = Security(_bearer)):
    if not creds or creds.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid or missing admin token")
    return creds


@router.get(
    "/rules",
    response_model=RulesListResponse,
    summary="List all detection rules with current state",
    dependencies=[Depends(require_admin)],
)
async def list_rules():
    rules = get_rules_summary()
    return RulesListResponse(
        total=len(rules),
        gh_rules=sum(1 for r in rules if r["region"] == "gh"),
        global_rules=sum(1 for r in rules if r["region"] == "global"),
        rules=[RuleSummary(**r) for r in rules],
    )


@router.patch(
    "/rules/toggle",
    summary="Enable or disable a rule at runtime",
    dependencies=[Depends(require_admin)],
)
async def toggle(req: RuleToggleRequest):
    if not toggle_rule(req.rule_id, req.enabled):
        raise HTTPException(status_code=404, detail=f"Rule '{req.rule_id}' not found")
    return {"rule_id": req.rule_id, "enabled": req.enabled}


@router.patch(
    "/rules/weight",
    summary="Override a rule's weight at runtime",
    dependencies=[Depends(require_admin)],
)
async def update_weight(req: RuleWeightRequest):
    if not set_rule_weight(req.rule_id, req.weight):
        raise HTTPException(status_code=404, detail=f"Rule '{req.rule_id}' not found")
    return {"rule_id": req.rule_id, "weight": req.weight}
