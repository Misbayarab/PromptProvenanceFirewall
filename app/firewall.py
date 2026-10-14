
from .models import DataItem
from .policy import Action, check_policy
from .security_log import log_security_event
from .injection_detector import detect_prompt_injection
from .risk_analyzer import calculate_risk


class FirewallResult:
    def __init__(
        self,
        allowed: bool,
        reason: str,
        risk: str = "low",
        risk_score: int = 0,
        injection_detected: bool = False,
    ):
        self.allowed = allowed
        self.reason = reason
        self.risk = risk
        self.risk_score = risk_score
        self.injection_detected = injection_detected


def inspect_action(data: DataItem, action: Action) -> FirewallResult:
    # Step 1: Detect prompt injection.
    detection = detect_prompt_injection(data.content)
    injection_detected = bool(detection["is_injection"])

    # Step 2: Calculate numerical risk.
    risk_score = calculate_risk(
        data,
        action,
        injection_detected,
    )

    # Step 3: Check provenance policy.
    allowed_by_policy = check_policy(data, action)

    # Step 4: Block detected prompt injection.
    if injection_detected:
        reason = (
            "Action blocked because prompt injection was detected "
            "in untrusted data."
        )

        log_security_event(
            source_name=data.provenance.source_name,
            trust_level=data.provenance.trust_level,
            action=action,
            allowed=False,
            reason=reason,
            risk="high",
            risk_score=risk_score,
            injection_detected=True,
        )

        return FirewallResult(
            allowed=False,
            reason=reason,
            risk="high",
            risk_score=risk_score,
            injection_detected=True,
        )

    # Step 5: Block sensitive actions disallowed by policy.
    if not allowed_by_policy:
        reason = (
            "Action blocked because untrusted data attempted to "
            "control a sensitive action."
        )

        log_security_event(
            source_name=data.provenance.source_name,
            trust_level=data.provenance.trust_level,
            action=action,
            allowed=False,
            reason=reason,
            risk="medium",
            risk_score=risk_score,
            injection_detected=False,
        )

        return FirewallResult(
            allowed=False,
            reason=reason,
            risk="medium",
            risk_score=risk_score,
            injection_detected=False,
        )

    # Step 6: Allow the action.
    reason = "Action allowed by provenance and injection policy."

    log_security_event(
        source_name=data.provenance.source_name,
        trust_level=data.provenance.trust_level,
        action=action,
        allowed=True,
        reason=reason,
        risk="low",
        risk_score=risk_score,
        injection_detected=False,
    )

    return FirewallResult(
        allowed=True,
        reason=reason,
        risk="low",
        risk_score=risk_score,
        injection_detected=False,
    )
