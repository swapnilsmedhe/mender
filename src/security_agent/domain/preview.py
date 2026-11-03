
from dataclasses import dataclass
from enum import Enum


class PreviewStatus(Enum):
    READY = "READY"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    DEPENDENCY_NOT_FOUND = "DEPENDENCY_NOT_FOUND"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    AMBIGUOUS = "AMBIGUOUS"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class ChangePreview:
    finding_id: str
    file: str
    dependency: str
    current_version: str
    target_version: str
    status: PreviewStatus
    diff: str = ""
    message: str = ""
