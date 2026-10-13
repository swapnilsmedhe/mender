from dataclasses import dataclass
from enum import Enum


class RemediationType(Enum):
    VERSION_UPGRADE = "VERSION_UPGRADE"
    NO_AUTOMATIC_REMEDIATION = "NO_AUTOMATIC_REMEDIATION"


class Confidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class FindingAnalysis:
    finding_id: str
    root_cause: str
    recommended_action: RemediationType
    target_version: str | None
    confidence: Confidence