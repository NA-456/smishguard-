"""
SmishGuard Detection Engine

Compiles all rules into cached regex patterns and scores incoming SMS messages.
Designed to be fast enough for real-time webhook processing (<5 ms per message).
"""

import re
import logging
from functools import lru_cache
from typing import List, Tuple, Dict, Any

from app.rules.global_rules import GLOBAL_RULES
from app.rules.gh_rules import GH_RULES
from app.config import settings

logger = logging.getLogger("smishguard.engine")

# ── Merge all rules ─────────────────────────────────────────────────
ALL_RULES: List[Dict[str, Any]] = GLOBAL_RULES + GH_RULES

# Patch settings with live rule counts
settings.total_rules = len(ALL_RULES)
settings.gh_rules    = len(GH_RULES)

# Runtime toggle / weight overrides (mutated by admin endpoints)
_rule_overrides: Dict[str, Dict[str, Any]] = {}


@lru_cache(maxsize=None)
def _compiled_pattern(rule_id: str, pattern: str) -> re.Pattern:
    """Compile and cache regex patterns (case-insensitive, dotall)."""
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


def _get_rule_state(rule: Dict[str, Any]) -> Tuple[bool, int]:
    """Return (enabled, weight) for a rule, accounting for any runtime overrides."""
    ov = _rule_overrides.get(rule["id"], {})
    enabled = ov.get("enabled", True)
    weight  = ov.get("weight", rule["weight"])
    return enabled, weight


# ── Public API ──────────────────────────────────────────────────────

def analyze_message(text: str, sender: str = "", sender_type: str = "unknown") -> Dict[str, Any]:
    """
    Score a single SMS message against all active rules.

    Returns a dict compatible with AnalyzeResponse schema.
    """
    triggered = []
    score = 0

    for rule in ALL_RULES:
        enabled, weight = _get_rule_state(rule)
        if not enabled:
            continue

        pattern = _compiled_pattern(rule["id"], rule["pattern"])
        if pattern.search(text):
            score += weight
            triggered.append({
                "id":       rule["id"],
                "name":     rule["name"],
                "weight":   weight,
                "severity": rule["severity"],
                "region":   rule["region"],
                "category": rule.get("category"),
            })

    score   = min(100, score)
    level   = _score_to_level(score)
    gh_hits = sum(1 for t in triggered if t["region"] == "gh")

    return {
        "score":          score,
        "level":          level,
        "triggered_rules": triggered,
        "gh_hits":        gh_hits,
        "summary":        _build_summary(score, level, triggered, gh_hits),
        "recommendation": _build_recommendation(level, triggered),
    }


def analyze_batch(messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Score a list of messages. Each item must have 'id' and 'text'."""
    results = []
    for msg in messages:
        result = analyze_message(
            text=msg.get("text", ""),
            sender=msg.get("sender", ""),
            sender_type=msg.get("sender_type", "unknown"),
        )
        results.append({
            "id":           msg["id"],
            "score":        result["score"],
            "level":        result["level"],
            "gh_hits":      result["gh_hits"],
            "top_triggers": [t["name"] for t in result["triggered_rules"][:3]],
        })
    return results


def get_rules_summary() -> List[Dict[str, Any]]:
    """Return current state of all rules (with any runtime overrides applied)."""
    summary = []
    for rule in ALL_RULES:
        enabled, weight = _get_rule_state(rule)
        summary.append({
            "id":       rule["id"],
            "name":     rule["name"],
            "weight":   weight,
            "enabled":  enabled,
            "severity": rule["severity"],
            "region":   rule["region"],
            "category": rule.get("category"),
        })
    return summary


def toggle_rule(rule_id: str, enabled: bool) -> bool:
    """Enable or disable a rule at runtime."""
    if not any(r["id"] == rule_id for r in ALL_RULES):
        return False
    _rule_overrides.setdefault(rule_id, {})["enabled"] = enabled
    logger.info(f"Rule '{rule_id}' {'enabled' if enabled else 'disabled'}")
    return True


def set_rule_weight(rule_id: str, weight: int) -> bool:
    """Override a rule's weight at runtime."""
    if not any(r["id"] == rule_id for r in ALL_RULES):
        return False
    _rule_overrides.setdefault(rule_id, {})["weight"] = weight
    logger.info(f"Rule '{rule_id}' weight set to {weight}")
    return True


# ── Helpers ─────────────────────────────────────────────────────────

def _score_to_level(score: int) -> str:
    if score >= settings.danger_threshold:
        return "danger"
    if score >= settings.suspicious_threshold:
        return "suspicious"
    return "safe"


def _build_summary(score: int, level: str, triggered: List, gh_hits: int) -> str:
    if level == "danger":
        cats = list({t["category"] for t in triggered if t["category"]})
        cats_str = ", ".join(cats[:3]) if cats else "multiple signals"
        return f"High-risk message (score {score}/100). Threats detected: {cats_str}."
    if level == "suspicious":
        return f"Suspicious message (score {score}/100). {len(triggered)} rule(s) triggered."
    return f"No significant threats detected (score {score}/100)."


def _build_recommendation(level: str, triggered: List) -> str:
    categories = {t.get("category", "") for t in triggered}

    if level == "danger":
        if "MoMo fraud" in categories:
            return (
                "Do NOT share your MoMo PIN or send money. "
                "Report to your network operator and call 18111 (Ghana Cybersecurity Authority)."
            )
        if "Govt impersonation" in categories:
            return (
                "Verify directly with the official agency website or hotline. "
                "Do not click links or call numbers in this message."
            )
        if "Carrier impersonation" in categories:
            return (
                "Contact your carrier's official customer care line. "
                "MTN: 100 · Telecel: 200 · AirtelTigo: 200."
            )
        return (
            "Do not click any links or respond with personal information. "
            "Report to Ghana Cybersecurity Authority: 292 (toll-free)."
        )

    if level == "suspicious":
        return (
            "Treat this message with caution. "
            "Verify the sender through official channels before taking any action."
        )

    return "Message appears safe. Always stay cautious about unsolicited messages."
