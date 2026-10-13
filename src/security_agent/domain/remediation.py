from dataclasses import dataclass, field

from security_agent.domain.analysis import (
    Confidence,
    RemediationType,
)


@dataclass(frozen=True)
class FileChange:
    file: str
    dependency: str
    current_version: str
    target_version: str


@dataclass(frozen=True)
class RemediationPlan:
    finding_id: str
    remediation_type: RemediationType
    reason: str
    confidence: Confidence
    changes: list[FileChange] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)