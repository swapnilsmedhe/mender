from dataclasses import dataclass
from enum import Enum


class Scanner(Enum):
    BLACK_DUCK = "BLACK_DUCK"


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SecurityFinding:
    id: str
    scanner: Scanner
    severity: Severity
    cve: str
    component: str
    current_version: str
    fixed_versions: list[str]
    repository: str
    file: str