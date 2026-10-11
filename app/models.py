from enum import Enum
from pydantic import BaseModel


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    INTERNAL = "internal"
    UNTRUSTED = "untrusted"


class SourceType(str, Enum):
    USER = "user"
    SYSTEM = "system"
    APPLICATION = "application"
    WEBSITE = "website"
    DOCUMENT = "document"
    DATABASE = "database"
    TOOL = "tool"


class Provenance(BaseModel):
    source_type: SourceType
    source_name: str
    trust_level: TrustLevel


class DataItem(BaseModel):
    content: str
    provenance: Provenance
