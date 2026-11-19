
import re
from dataclasses import dataclass
from pathlib import Path

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


class GradleVersionSourceResolver:
    """
    Identifies the source of a directly declared Gradle dependency version.

    Supported:
    - Inline versions in Maven coordinate notation.
    - Kotlin DSL variables populated through
      rootProject.findProperty("propertyName") as String.
    - Properties defined in the repository-root gradle.properties.

    Gradle remains authoritative for the resolved dependency version.
    """

    COORDINATE_PATTERN = re.compile(
        r"""['"]([^'"]+)['"]"""
    )

    PROPERTY_VARIABLE_PATTERN = re.compile(
        r"""
        \b(?:val|var)\s+
        (?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*
        =
        \s*rootProject\.findProperty\(
        \s*['"](?P<property>[^'"]+)['"]\s*
        \)
        \s*as\s+String
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
        variable_properties = self._find_property_variables(content)

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

            variable = (
                interpolation.group("braced")
                or interpolation.group("plain")
            )

            property_name = variable_properties.get(variable)

            if property_name is None:
                return VersionSourceEvidence(
                    dependency=f"{group}:{artifact}",
                    declaration=declaration,
                    source_type="UNKNOWN",
                    source_file=None,
                    property_name=None,
                    value=None,
                    resolved=False,
                )

            property_value = self._read_root_property(property_name)

            return VersionSourceEvidence(
                dependency=f"{group}:{artifact}",
                declaration=declaration,
                source_type="GRADLE_PROPERTY",
                source_file="gradle.properties",
                property_name=property_name,
                value=property_value,
                resolved=property_value is not None,
            )

        return None

    @classmethod
    def _find_property_variables(
        cls,
        content: str,
    ) -> dict[str, str]:
        return {
            match.group("variable"): match.group("property")
            for match in cls.PROPERTY_VARIABLE_PATTERN.finditer(content)
        }

    def _read_root_property(self, property_name: str) -> str | None:
        try:
            content = self.tools.read_file("gradle.properties")
        except (FileNotFoundError, ValueError):
            return None

        for line in content.splitlines():
            stripped = line.strip()

            if not stripped or stripped.startswith(("#", "!")):
                continue

            separator = re.search(r"[=:]", stripped)

            if separator is None:
                continue

            key = stripped[:separator.start()].strip()
            value = stripped[separator.end():].strip()

            if key == property_name:
                return value

        return None

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
