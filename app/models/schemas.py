"""
Pydantic schemas — request bodies, response models, webhook payloads.
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Literal
from datetime import datetime


# ── Analysis ────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000,
                      description="SMS message text to analyze")
    sender: Optional[str] = Field(None, description="Sender ID or phone number")
    sender_type: Optional[Literal["shortcode", "alphanumeric", "random_number", "unknown"]] = "unknown"

    @field_validator("text")
    @classmethod
    def strip_text(cls, v: str) -> str:
        return v.strip()


class TriggeredRule(BaseModel):
    id: str
    name: str
    weight: int
    severity: Literal["high", "med", "low"]
    region: Literal["global", "gh"]
    category: Optional[str] = None


class AnalyzeResponse(BaseModel):
    score: int = Field(..., ge=0, le=100)
    level: Literal["safe", "suspicious", "danger"]
    triggered_rules: List[TriggeredRule]
    gh_hits: int = Field(0, description="Number of Ghana-specific rules triggered")
    summary: str
    recommendation: str
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


# ── Batch analysis ───────────────────────────────────────────────────

class BatchMessage(BaseModel):
    id: str
    text: str = Field(..., min_length=1, max_length=2000)
    sender: Optional[str] = None
    sender_type: Optional[str] = "unknown"


class BatchAnalyzeRequest(BaseModel):
    messages: List[BatchMessage] = Field(..., min_length=1, max_length=100)


class BatchResult(BaseModel):
    id: str
    score: int
    level: Literal["safe", "suspicious", "danger"]
    gh_hits: int
    top_triggers: List[str]


class BatchAnalyzeResponse(BaseModel):
    total: int
    danger_count: int
    suspicious_count: int
    safe_count: int
    results: List[BatchResult]
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


# ── AfricasTalking webhook ───────────────────────────────────────────

class ATIncomingSMS(BaseModel):
    """
    AfricasTalking incoming SMS webhook payload.
    Docs: https://developers.africastalking.com/docs/sms/receiving
    """
    linkId: Optional[str] = None
    text: str
    to: str                          # Your shortcode
    messageId: str
    date: str
    from_: str = Field(alias="from") # Sender's phone number

    class Config:
        populate_by_name = True


class ATWebhookResponse(BaseModel):
    received: bool = True
    message_id: str
    analysis: AnalyzeResponse
    auto_reply_sent: bool = False


# ── Admin ────────────────────────────────────────────────────────────

class RuleToggleRequest(BaseModel):
    rule_id: str
    enabled: bool


class RuleWeightRequest(BaseModel):
    rule_id: str
    weight: int = Field(..., ge=1, le=100)


class RuleSummary(BaseModel):
    id: str
    name: str
    weight: int
    enabled: bool
    severity: str
    region: str
    category: Optional[str] = None


class RulesListResponse(BaseModel):
    total: int
    gh_rules: int
    global_rules: int
    rules: List[RuleSummary]


# ── System ───────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    rules_loaded: int
    gh_rules: int
