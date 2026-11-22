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
    declaration_kind: str = "DEPENDENCY"


class GradleVersionSourceResolver:
    """
    Identifies source-level Gradle dependency and platform declarations.

    This is supplementary evidence. Gradle's resolved dependency graph
    remains authoritative for the selected dependency version.

    Property values found in repository files are candidates, not proof
    of Gradle's effective property value.
    """

    COORDINATE_PATTERN = re.compile(r"""['"]([^'"]+)['"]""")

    CONFIGURATIONS = (
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testRuntimeOnly",
        "testCompileOnly",
        "testFixturesApi",
        "testFixturesImplementation",
        "annotationProcessor",
        "kapt",
    )

    CONFIGURATION_PATTERN = "|".join(re.escape(item) for item in CONFIGURATIONS)

    DECLARATION_PATTERN = re.compile(
        rf"""
        (?P<configuration>\b(?:{CONFIGURATION_PATTERN})\b)
        \s*
        (?:\(\s*)?
        (?P<quote>['"])
        (?P<coordinate>[^'"]+)
        (?P=quote)
        """,
        re.VERBOSE | re.DOTALL,
    )

    PLATFORM_PATTERN = re.compile(
        r"""
        \b(?P<platform>platform|enforcedPlatform)
        \s*\(\s*
        (?P<quote>['"])
        (?P<coordinate>[^'"]+)
        (?P=quote)
        \s*\)
        """,
        re.VERBOSE | re.DOTALL,
    )

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

    CONFIGURATION_LINE_PATTERN = re.compile(rf"^\s*(?:{CONFIGURATION_PATTERN})\s*\(")

    def __init__(self, tools: RepositoryTools) -> None:
        self.tools = tools

    def resolve(
        self,
        build_file: str,
        content: str,
        finding: SecurityFinding,
    ) -> VersionSourceEvidence | None:
        """
        Preserve the existing API for resolving a vulnerable dependency.

        Only dependency declarations are considered here. Platform
        declarations are available through find_declarations().
        """
        for evidence in self.find_declarations(
            build_file=build_file,
            content=content,
            finding=finding,
        ):
            if evidence.declaration_kind != "DEPENDENCY":
                continue

            if self._matches_dependency_name(
                evidence.dependency,
                finding,
            ):
                return evidence

        return None

    def find_declarations(
        self,
        build_file: str,
        content: str,
        finding: SecurityFinding,
    ) -> tuple[VersionSourceEvidence, ...]:
        """
        Find declarations relevant to the vulnerable component and
        all platform/BOM declarations in the same build file.

        A platform declaration is evidence of a possible version
        authority, not proof that it controls the vulnerable component.
        """
        variables = self._find_property_variables(content)
        evidence = []
        seen = set()

        for match in self.PLATFORM_PATTERN.finditer(content):
            coordinate = match.group("coordinate").strip()

            item = self._create_evidence(
                coordinate=coordinate,
                declaration=self._declaration_at(
                    content,
                    match.start(),
                ),
                build_file=build_file,
                variables=variables,
                declaration_kind="PLATFORM",
            )

            if item is not None:
                self._append_unique(evidence, seen, item)

        for match in self.DECLARATION_PATTERN.finditer(content):
            coordinate = match.group("coordinate").strip()

            prefix = content[max(0, match.start() - 40) : match.start()]

            if re.search(
                r"\b(?:platform|enforcedPlatform)\s*\(\s*$",
                prefix,
            ):
                continue

            parts = coordinate.split(":")

            if len(parts) < 2:
                continue

            dependency_name = ":".join(parts[:2])

            if not self._matches_dependency_name(
                dependency_name,
                finding,
            ):
                continue

            item = self._create_evidence(
                coordinate=coordinate,
                declaration=self._declaration_at(
                    content,
                    match.start(),
                ),
                build_file=build_file,
                variables=variables,
                declaration_kind="DEPENDENCY",
            )

            if item is not None:
                self._append_unique(evidence, seen, item)

        return tuple(evidence)

    def _create_evidence(
        self,
        coordinate: str,
        declaration: str,
        build_file: str,
        variables: dict[str, tuple[str, str]],
        declaration_kind: str,
    ) -> VersionSourceEvidence | None:
        parts = coordinate.split(":")

        if len(parts) < 2:
            return None

        group, artifact = parts[:2]
        dependency = f"{group}:{artifact}"

        if len(parts) == 2:
            return VersionSourceEvidence(
                dependency=dependency,
                declaration=declaration,
                source_type="VERSIONLESS",
                source_file=build_file,
                property_name=None,
                value=None,
                resolved=False,
                declaration_kind=declaration_kind,
            )

        version = parts[2]

        if not version:
            return VersionSourceEvidence(
                dependency=dependency,
                declaration=declaration,
                source_type="UNKNOWN",
                source_file=build_file,
                property_name=None,
                value=None,
                resolved=False,
                declaration_kind=declaration_kind,
            )

        interpolation = self.INTERPOLATION_PATTERN.fullmatch(version)

        if interpolation is None:
            return VersionSourceEvidence(
                dependency=dependency,
                declaration=declaration,
                source_type="INLINE",
                source_file=build_file,
                property_name=None,
                value=version,
                resolved=True,
                declaration_kind=declaration_kind,
            )

        variable = interpolation.group("braced") or interpolation.group("plain")

        property_info = variables.get(variable)

        if property_info is None:
            return VersionSourceEvidence(
                dependency=dependency,
                declaration=declaration,
                source_type="UNKNOWN",
                source_file=None,
                property_name=None,
                value=None,
                resolved=False,
                declaration_kind=declaration_kind,
            )

        property_name, lookup_scope = property_info

        candidate_file, candidate_value = self._find_repository_property_candidate(
            property_name
        )

        return VersionSourceEvidence(
            dependency=dependency,
            declaration=declaration,
            source_type="GRADLE_PROJECT_PROPERTY",
            source_file=None,
            property_name=property_name,
            value=None,
            resolved=False,
            lookup_scope=lookup_scope,
            candidate_source_file=candidate_file,
            candidate_value=candidate_value,
            declaration_kind=declaration_kind,
        )

    def _find_repository_property_candidate(
        self,
        property_name: str,
    ) -> tuple[str | None, str | None]:
        """
        Look for a candidate in the repository-root gradle.properties.

        This does not reproduce Gradle's complete property precedence
        or effective runtime property resolution.
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
                variables[variable] = (
                    property_name,
                    lookup_scope,
                )

        return variables

    @staticmethod
    def _matches_dependency_name(
        dependency: str,
        finding: SecurityFinding,
    ) -> bool:
        parts = finding.component.split(":")

        if len(parts) >= 2:
            expected = ":".join(parts[-2:])
            return dependency.casefold() == expected.casefold()

        return dependency.split(":")[-1].casefold() == finding.component.casefold()

    @staticmethod
    def _append_unique(
        evidence: list[VersionSourceEvidence],
        seen: set[tuple],
        item: VersionSourceEvidence,
    ) -> None:
        key = (
            item.dependency,
            item.declaration,
            item.declaration_kind,
            item.source_type,
            item.value,
            item.property_name,
        )

        if key not in seen:
            seen.add(key)
            evidence.append(item)

    @classmethod
    def _declaration_at(
        cls,
        content: str,
        offset: int,
    ) -> str:
        """
        Return the complete Gradle configuration expression.

        Handles multi-line Kotlin DSL declarations and nested calls such
        as implementation(platform("group:artifact:version")).
        Parentheses inside quoted strings are ignored.
        """
        lines = content.splitlines(keepends=True)

        line_offsets = []
        current_offset = 0

        for line in lines:
            line_offsets.append((current_offset, line))
            current_offset += len(line)

        coordinate_line_index = None

        for index, (line_offset, line) in enumerate(line_offsets):
            if line_offset <= offset < line_offset + len(line):
                coordinate_line_index = index
                break

        if coordinate_line_index is None:
            return ""

        start_index = coordinate_line_index

        # Locate the configuration call immediately preceding the
        # coordinate. Permit intervening whitespace/newlines.
        for index in range(coordinate_line_index, -1, -1):
            line = line_offsets[index][1]

            if cls.CONFIGURATION_LINE_PATTERN.match(line):
                start_index = index
                break

            if line.strip() and index != coordinate_line_index:
                # Do not cross another non-empty statement.
                break

        start_offset = line_offsets[start_index][0]
        candidate = content[start_offset:]

        opening_paren = candidate.find("(")

        if opening_paren == -1:
            # Groovy shorthand, e.g. implementation 'group:artifact:1.0'
            line_end = content.find("\n", offset)
            if line_end == -1:
                line_end = len(content)
            return " ".join(content[start_offset:line_end].strip().split())

        depth = 0
        quote = None
        escaped = False
        end_offset = len(candidate)

        for index, char in enumerate(candidate):
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue

            if char in ("'", '"'):
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1

                if depth == 0:
                    end_offset = index + 1
                    break

        return " ".join(candidate[:end_offset].strip().split())
