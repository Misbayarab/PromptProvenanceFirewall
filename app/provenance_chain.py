from .models import DataItem


class ProvenanceChain:

    def __init__(self):
        self.items = []

    def add(self, data: DataItem):
        self.items.append(data)

    def get_chain(self):
        return self.items

    def describe(self):

        if not self.items:
            return "No provenance information."

        chain = []

        for data in self.items:
            source = data.provenance.source_name
            trust = data.provenance.trust_level.value

            chain.append(
                f"{source} ({trust})"
            )

        return " -> ".join(chain)