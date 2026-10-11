from .provenance import create_user_data
from .tools import search_web, send_email
from .provenance_chain import ProvenanceChain


def run_agent(user_request: str):

    # Create provenance chain
    chain = ProvenanceChain()

    # Step 1: Store user's request
    user_data = create_user_data(
        user_request
    )

    chain.add(user_data)

    print("USER REQUEST:")
    print(user_data)

    # Step 2: Simulate web search
    web_data = search_web(
        user_request
    )

    chain.add(web_data)

    print("\nWEB DATA:")
    print(web_data)

    # Step 3: Display provenance chain
    print("\nPROVENANCE CHAIN:")
    print(chain.describe())

    # Step 4: Try to send email
    result = send_email(
        web_data,
        "user@example.com"
    )

    print("\nTOOL RESULT:")
    print(result)

    return result