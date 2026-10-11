from .models import DataItem
from .policy import Action


def calculate_risk(
    data: DataItem,
    action: Action,
    injection_detected: bool
) -> int:

    risk_score = 0

    # Untrusted external data
    if data.provenance.trust_level.value == "untrusted":
        risk_score += 20

    # Sensitive actions
    if action in {
        Action.SEND_EMAIL,
        Action.PURCHASE,
        Action.DELETE,
        Action.MODIFY_DATABASE
    }:
        risk_score += 40

    # Prompt injection detected
    if injection_detected:
        risk_score += 40

    # Maximum risk score = 100
    return min(risk_score, 100)