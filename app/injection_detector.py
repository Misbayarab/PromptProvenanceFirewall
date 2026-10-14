
import re


# Patterns that may indicate an attempt to control an AI agent.
INJECTION_PATTERNS = [
    (
        "ignore previous instructions",
        re.compile(
            r"\bignore\s+(?:all\s+)?(?:previous|prior|preceding)"
            r"\s+instructions\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ignore system instructions",
        re.compile(
            r"\bignore\s+(?:the\s+)?system\s+instructions\b",
            re.IGNORECASE,
        ),
    ),
    (
        "reveal hidden instructions",
        re.compile(
            r"\b(?:reveal|show|print|disclose)\s+"
            r"(?:the\s+)?(?:hidden\s+)?"
            r"(?:system\s+prompt|system\s+instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "send the password",
        re.compile(
            r"\b(?:send|share|email|transmit|exfiltrate)\b"
            r".{0,100}\b(?:passwords?|credentials?|secret keys?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "send sensitive data externally",
        re.compile(
            r"\b(?:send|email|upload|forward|transmit)\b"
            r".{0,100}\b(?:private data|personal data|confidential data)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "override safety rules",
        re.compile(
            r"\b(?:bypass|disable|override)\b"
            r".{0,60}\b(?:safety|security|restrictions|guardrails)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "unauthorized tool instruction",
        re.compile(
            r"\b(?:call|execute|invoke)\s+"
            r"(?:the\s+)?(?:send_email|purchase_item)\b",
            re.IGNORECASE,
        ),
    ),
]


def detect_prompt_injection(content: str) -> dict:
    """
    Inspect untrusted text for common prompt-injection indicators.

    Returns:
        is_injection: whether any known pattern matched
        risk: low, medium, or high
        risk_score: numeric score from 0 to 100
        patterns: descriptions of the matched patterns
    """
    if not isinstance(content, str):
        content = str(content) if content is not None else ""

    matches = [
        description
        for description, pattern in INJECTION_PATTERNS
        if pattern.search(content)
    ]

    count = len(matches)

    if count == 0:
        risk = "low"
        risk_score = 0
    elif count == 1:
        risk = "high"
        risk_score = 80
    else:
        risk = "high"
        risk_score = 100

    return {
        "is_injection": count > 0,
        "risk": risk,
        "risk_score": risk_score,
        "patterns": matches,
    }
