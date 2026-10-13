from dataclasses import dataclass

from security_agent.domain.finding import SecurityFinding
from security_agent.tools.repository import RepositoryTools


@dataclass(frozen=True)
class RepositoryInspection:
    finding_id: str
    inspected_file: str
    component_matches: list[dict[str, str | int]]
    version_matches: list[dict[str, str | int]]

    @property
    def is_consistent(self) -> bool:
        return bool(self.component_matches and self.version_matches)


class RepositoryInspector:
    def __init__(self, tools: RepositoryTools) -> None:
        self.tools = tools

    def inspect(self, finding: SecurityFinding) -> RepositoryInspection:
        # Confirm that the file supplied by the scanner exists and is readable.
        self.tools.read_file(finding.file)

        component_matches = self.tools.search_code(
            finding.component,
        )
        version_matches = self.tools.search_code(
            finding.current_version,
        )

        return RepositoryInspection(
            finding_id=finding.id,
            inspected_file=finding.file,
            component_matches=component_matches,
            version_matches=version_matches,
        )
