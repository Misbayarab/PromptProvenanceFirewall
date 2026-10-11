import re


# Common prompt injection patterns
INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all previous instructions",
    r"ignore the previous instructions",
    r"disregard previous instructions",
    r"disregard all previous instructions",
    r"forget previous instructions",
    r"you are now",
    r"system prompt",
    r"reveal confidential information",
    r"reveal secret",
    r"send the password",
    r"provide the password",
    r"bypass security",
    r"override security",
]


def detect_prompt_injection(text: str) -> dict:

    detected_patterns = []

    text_lower = text.lower()

    for pattern in INJECTION_PATTERNS:

        if re.search(pattern, text_lower):
            detected_patterns.append(pattern)

    if detected_patterns:

        return {
            "is_injection": True,
            "risk": "high",
            "detected_patterns": detected_patterns
        }

    return {
        "is_injection": False,
        "risk": "low",
        "detected_patterns": []
    }