from .models import DataItem
from .policy import Action
from .firewall import inspect_action


def search_web(query: str) -> DataItem:
    """
    Simulate a web search.

    In the real system, this would connect to a
    search engine or website.
    """

    return DataItem(
        content=f"Search result for: {query}",
        provenance={
            "source_type": "website",
            "source_name": "search-engine",
            "trust_level": "untrusted"
        }
    )


def read_document(document_name: str) -> DataItem:
    """
    Simulate reading a document.
    """

    return DataItem(
        content=f"Content extracted from {document_name}",
        provenance={
            "source_type": "document",
            "source_name": document_name,
            "trust_level": "untrusted"
        }
    )


def send_email(data: DataItem, recipient: str) -> str:
    """
    Simulate sending an email.

    The firewall checks the provenance before
    allowing the sensitive action.
    """

    result = inspect_action(
        data,
        Action.SEND_EMAIL
    )

    if not result.allowed:
        return f"BLOCKED: {result.reason}"

    return f"EMAIL SENT to {recipient}"


def purchase_item(data: DataItem, item: str) -> str:
    """
    Simulate purchasing an item.

    The firewall checks the provenance before
    allowing the purchase.
    """

    result = inspect_action(
        data,
        Action.PURCHASE
    )

    if not result.allowed:
        return f"BLOCKED: {result.reason}"

    return f"PURCHASE APPROVED: {item}"