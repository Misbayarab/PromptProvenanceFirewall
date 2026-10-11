from datetime import datetime

from .database import save_security_event


def log_security_event(
    source_name: str,
    trust_level,
    action,
    allowed: bool,
    reason: str,
    risk: str = "low",
    risk_score: int = 0
):

    timestamp = datetime.now().isoformat()

    # Convert Enum values to normal strings
    trust_value = getattr(
        trust_level,
        "value",
        str(trust_level)
    )

    action_value = getattr(
        action,
        "value",
        str(action)
    )

    event = {
        "timestamp": timestamp,
        "source_name": source_name,
        "trust_level": trust_value,
        "action": action_value,
        "allowed": allowed,
        "reason": reason,
        "risk": risk,
        "risk_score": risk_score
    }

    print("\n--- SECURITY EVENT ---")
    print(event)

    save_security_event(
        timestamp=timestamp,
        source_name=source_name,
        trust_level=trust_value,
        action=action_value,
        allowed=allowed,
        reason=reason,
        risk=risk,
        risk_score=risk_score
    )

    return event