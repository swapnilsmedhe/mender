import re
from dataclasses import dataclass

from security_agent.domain.finding import SecurityFinding
from security_agent.tools.repository import RepositoryTools


@dataclass(frozen=True)
class VersionSourceEvidence:
    dependency: str
    declaration: str
    source_type: str
    source_file: str | None
    property_name: str | None
    value: str | None
    resolved: bool
    lookup_scope: str | None = None


class GradleVersionSourceResolver:
    """
    Identifies how a directly declared Gradle dependency gets its version.

    This is source-level evidence, not a replacement for Gradle's
    resolved dependency graph.
    """

    COORDINATE_PATTERN = re.compile(r"""['"]([^'"]+)['"]""")

    PROPERTY_VARIABLE_PATTERNS = (
        (
            re.compile(
                r"""
                \b(?:val|var)\s+
                (?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*
                (?::\s*String\s*)?
                \bby\s+project\b
                """,
                re.VERBOSE,
            ),
            "CURRENT_PROJECT",
        ),
        (
            re.compile(
                r"""
                \b(?:val|var)\s+
                (?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*
                =
                \s*rootProject\.findProperty\(
                \s*['"](?P<property>[^'"]+)['"]\s*
                \)
                (?:\s*as\s+String)?
                """,
                re.VERBOSE,
            ),
            "ROOT_PROJECT",
        ),
        (
            re.compile(
                r"""
                \b(?:val|var)\s+
                (?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*
                =
                \s*project\.findProperty\(
                \s*['"](?P<property>[^'"]+)['"]\s*
                \)
                (?:\s*as\s+String)?
                """,
                re.VERBOSE,
            ),
            "CURRENT_PROJECT",
        ),
    )

    FIND_PROPERTY_PATTERN = re.compile(
        r"""
        \b(?:rootProject|project)\.findProperty\(
        \s*['"](?P<property>[^'"]+)['"]\s*
        \)
        """,
        re.VERBOSE,
    )

    INTERPOLATION_PATTERN = re.compile(
        r"^\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|"
        r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))$"
    )

    def __init__(self, tools: RepositoryTools) -> None:
        self.tools = tools

    def resolve(
        self,
        build_file: str,
        content: str,
        finding: SecurityFinding,
    ) -> VersionSourceEvidence | None:
        variables = self._find_property_variables(content)

        for match in self.COORDINATE_PATTERN.finditer(content):
            coordinate = match.group(1).strip()
            parts = coordinate.split(":")

            if len(parts) != 3:
                continue

            group, artifact, version = parts

            if not self._matches_dependency(group, artifact, finding):
                continue

            declaration = self._declaration_at(content, match.start())
            interpolation = self.INTERPOLATION_PATTERN.fullmatch(version)

            if interpolation is None:
                return VersionSourceEvidence(
                    dependency=f"{group}:{artifact}",
                    declaration=declaration,
                    source_type="INLINE",
                    source_file=build_file,
                    property_name=None,
                    value=version,
                    resolved=True,
                )

            variable = interpolation.group("braced") or interpolation.group("plain")
            property_info = variables.get(variable)

            if property_info is not None:
                property_name, lookup_scope = property_info
                return VersionSourceEvidence(
                    dependency=f"{group}:{artifact}",
                    declaration=declaration,
                    source_type="GRADLE_PROJECT_PROPERTY",
                    source_file=None,
                    property_name=property_name,
                    value=None,
                    resolved=False,
                    lookup_scope=lookup_scope,
                )

            return VersionSourceEvidence(
                dependency=f"{group}:{artifact}",
                declaration=declaration,
                source_type="UNKNOWN",
                source_file=None,
                property_name=None,
                value=None,
                resolved=False,
            )

        return None

    @classmethod
    def _find_property_variables(
        cls,
        content: str,
    ) -> dict[str, tuple[str, str]]:
        variables = {}

        for pattern, lookup_scope in cls.PROPERTY_VARIABLE_PATTERNS:
            for match in pattern.finditer(content):
                variable = match.group("variable")
                property_name = match.groupdict().get("property") or variable
                variables[variable] = (property_name, lookup_scope)

        return variables

    @staticmethod
    def _matches_dependency(
        group: str,
        artifact: str,
        finding: SecurityFinding,
    ) -> bool:
        parts = finding.component.split(":")

        if len(parts) >= 2:
            return (
                group.casefold() == parts[-2].casefold()
                and artifact.casefold() == parts[-1].casefold()
            )

        return artifact.casefold() == finding.component.casefold()

    @staticmethod
    def _declaration_at(content: str, offset: int) -> str:
        lines = content.splitlines()
        current_offset = 0

        for line in lines:
            next_offset = current_offset + len(line) + 1

            if current_offset <= offset < next_offset:
                return line.strip()

            current_offset = next_offset

        return ""
