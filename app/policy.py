from enum import Enum

from .models import DataItem, TrustLevel


class Action(str, Enum):
    READ = "read"
    ANSWER = "answer"
    SEARCH = "search"
    SEND_EMAIL = "send_email"
    PURCHASE = "purchase"
    DELETE = "delete"
    MODIFY_DATABASE = "modify_database"


def check_policy(
    data: DataItem,
    action: Action
) -> bool:

    trust = data.provenance.trust_level

    # -----------------------------------------
    # LOW-RISK ACTIONS
    # -----------------------------------------

    # Untrusted information can be read
    # and used to help formulate an answer.
    if action in {
        Action.READ,
        Action.ANSWER,
        Action.SEARCH
    }:
        return True

    # -----------------------------------------
    # HIGH-RISK ACTIONS
    # -----------------------------------------

    # Sensitive actions should not be
    # controlled by untrusted external data.
    if action in {
        Action.SEND_EMAIL,
        Action.PURCHASE,
        Action.DELETE,
        Action.MODIFY_DATABASE
    }:

        if trust == TrustLevel.UNTRUSTED:
            return False

    return True