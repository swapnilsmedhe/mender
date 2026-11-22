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
    candidate_source_file: str | None = None
    candidate_value: str | None = None


class GradleVersionSourceResolver:
    """
    Identifies how a directly declared Gradle dependency gets its version.

    This is source-level evidence, not a replacement for Gradle's
    resolved dependency graph. Property values discovered in repository
    files are candidates, not proof of Gradle's effective property value.
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

    INTERPOLATION_PATTERN = re.compile(
        r"^\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|"
        r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))$"
    )

    PROPERTY_LINE_PATTERN = re.compile(
        r"^\s*(?P<key>[^#!\s:=]+)\s*(?:=|:|\s)\s*(?P<value>.*?)\s*$"
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
                candidate_file, candidate_value = (
                    self._find_repository_property_candidate(property_name)
                )

                return VersionSourceEvidence(
                    dependency=f"{group}:{artifact}",
                    declaration=declaration,
                    source_type="GRADLE_PROJECT_PROPERTY",
                    source_file=None,
                    property_name=property_name,
                    value=None,
                    resolved=False,
                    lookup_scope=lookup_scope,
                    candidate_source_file=candidate_file,
                    candidate_value=candidate_value,
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

    def _find_repository_property_candidate(
        self,
        property_name: str,
    ) -> tuple[str | None, str | None]:
        """
        Look for a candidate in the repository-root gradle.properties.

        This deliberately does not claim to reproduce Gradle's complete
        property precedence or effective runtime property resolution.
        """
        if self.tools is None:
            return None, None

        property_file = "gradle.properties"

        try:
            content = self.tools.read_file(property_file)
        except (
            FileNotFoundError,
            OSError,
            UnicodeError,
            ValueError,
        ):
            return None, None

        # RepositoryTools.read_file returns str. This guard also makes
        # the resolver safe when a test double or alternate adapter
        # returns an unconfigured or invalid value.
        if not isinstance(content, str):
            return None, None

        candidate_value = None

        for line in content.splitlines():
            stripped = line.lstrip()

            if not stripped or stripped.startswith(("#", "!")):
                continue

            match = self.PROPERTY_LINE_PATTERN.match(line)

            if match is None:
                continue

            if match.group("key") == property_name:
                candidate_value = match.group("value").strip()

        if candidate_value is None:
            return None, None

        return property_file, candidate_value

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
