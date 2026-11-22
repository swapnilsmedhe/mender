import os
import re
import subprocess
from dataclasses import dataclass

from security_agent.application.module_discovery import (
    GradleModule,
    GradleModuleDiscovery,
)
from security_agent.domain.finding import SecurityFinding
from security_agent.tools.repository import RepositoryTools
from security_agent.application.gradle_dependency_report import (
    GradleDependencyGraph,
    GradleDependencyReportCollector,
)

@dataclass(frozen=True)
class ModuleMatch:
    project_path: str
    build_file: str
    command_output: str
    resolved_version: str | None = None
    dependency_paths: tuple[tuple[str, ...], ...] = ()

    @property
    def dependency_path(self) -> tuple[str, ...]:
        """Return the first known path, if Gradle reported one."""
        if not self.dependency_paths:
            return ()
        return self.dependency_paths[0]

    @property
    def introducing_dependency(self) -> str | None:
        """Return the direct dependency introducing the transitive finding."""
        path = self.dependency_path
        if len(path) < 2:
            return None
        return path[0]


@dataclass(frozen=True)
class RepositoryInspection:
    finding_id: str
    configuration: str
    command_output: str
    is_consistent: bool
    matches: tuple[ModuleMatch, ...] = ()
    errors: tuple[str, ...] = ()
    transitive_matches: tuple[ModuleMatch, ...] = ()


@dataclass(frozen=True)
class _DependencyCoordinate:
    group: str
    artifact: str
    requested_version: str
    resolved_version: str

    @property
    def notation(self) -> str:
        return (
            f"{self.group}:{self.artifact}:"
            f"{self.resolved_version}"
        )


@dataclass(frozen=True)
class _DependencyTreeNode:
    depth: int
    coordinate: _DependencyCoordinate


class RepositoryInspector:
    SUPPORTED_CONFIGURATIONS = (
        "implementation",
        "api",
        "runtimeOnly",
        "compileOnly",
        "testImplementation",
        "testRuntimeOnly",
        "testCompileOnly",
        "annotationProcessor",
        "kapt",
    )

    COORDINATE_PATTERN = re.compile(
        r"(?P<group>[A-Za-z0-9_.-]+):"
        r"(?P<artifact>[A-Za-z0-9_.-]+):"
        r"(?P<requested>[^\s()]+)"
        r"(?:\s+->\s+(?P<selected>[^\s()]+))?"
    )

    TREE_MARKER_PATTERN = re.compile(
        r"(?:\+---|\\---)\s+"
    )

    def __init__(
        self,
        tools: RepositoryTools,
        configuration: str = "runtimeClasspath",
        timeout_seconds: int = 120,
    ) -> None:
        self.tools = tools
        self.configuration = configuration
        self.timeout_seconds = timeout_seconds

        self.discovery = GradleModuleDiscovery(
            tools,
            timeout_seconds=timeout_seconds,
        )

        self.report_collector = GradleDependencyReportCollector(
            tools,
            timeout_seconds=timeout_seconds,
        )
    
    def inspect(
        self,
        finding: SecurityFinding,
    ) -> RepositoryInspection:
        modules = self.discovery.discover()

        modules_with_build_files = [
            module for module in modules
            if module.build_file is not None
        ]

        if not modules_with_build_files:
            return RepositoryInspection(
                finding_id=finding.id,
                configuration=self.configuration,
                command_output="",
                is_consistent=False,
                errors=("No Gradle projects with existing build files.",),
            )

        eligible_modules = []
        outputs = []

        for module in modules_with_build_files:
            # Older discovery results may not contain configuration data.
            if (
                module.configurations is not None
                and self.configuration not in module.configurations
            ):
                outputs.append(
                    f"Module {module.project_path} skipped: "
                    f"configuration '{self.configuration}' "
                    "is not available."
                )
                continue

            eligible_modules.append(module)

        if not eligible_modules:
            return RepositoryInspection(
                finding_id=finding.id,
                configuration=self.configuration,
                command_output="\n".join(outputs),
                is_consistent=False,
                errors=(
                    f"No Gradle projects expose the requested "
                    f"configuration '{self.configuration}'.",
                ),
            )

        try:
            report = self.report_collector.collect(
                self.configuration,
            )
        except (RuntimeError, FileNotFoundError, ValueError) as exc:
            return RepositoryInspection(
                finding_id=finding.id,
                configuration=self.configuration,
                command_output="\n".join(outputs),
                is_consistent=False,
                errors=(str(exc),),
            )

        graph = GradleDependencyGraph(report)

        direct_matches = []
        transitive_matches = []
        errors = list(report.errors)

        for module in eligible_modules:
            paths = graph.find_paths(
                project_path=module.project_path,
                target_component=finding.component,
            )

            # A path is relevant only when Gradle actually resolved
            # the vulnerable version reported by the scanner.
            vulnerable_paths = tuple(
                path
                for path in paths
                if path
                and self._path_resolved_version(path)
                == finding.current_version
            )

            if not vulnerable_paths:
                continue

            direct_paths = tuple(
                path for path in vulnerable_paths
                if len(path) == 1
            )

            transitive_paths = tuple(
                path for path in vulnerable_paths
                if len(path) > 1
            )

            def create_match(
                dependency_paths: tuple[tuple[str, ...], ...],
            ) -> ModuleMatch:
                return ModuleMatch(
                    project_path=module.project_path,
                    build_file=module.build_file,
                    command_output="\n".join(
                        " -> ".join(path)
                        for path in dependency_paths
                    ),
                    resolved_version=finding.current_version,
                    dependency_paths=dependency_paths,
                )

            # A module can have both direct and transitive paths.
            # Keep those relationships separate.
            if direct_paths:
                direct_matches.append(
                    create_match(direct_paths)
                )

            if transitive_paths:
                transitive_matches.append(
                    create_match(transitive_paths)
                )

            outputs.append(
                f"Module {module.project_path}:\n"
                + "\n".join(
                    "  " + " -> ".join(path)
                    for path in vulnerable_paths
                )
            )

        has_dependency_evidence = bool(
            direct_matches or transitive_matches
        )

        return RepositoryInspection(
            finding_id=finding.id,
            configuration=self.configuration,
            command_output="\n\n".join(outputs),
            is_consistent=(
                has_dependency_evidence and not errors
            ),
            matches=tuple(direct_matches),
            errors=tuple(errors),
            transitive_matches=tuple(transitive_matches),
        )


    @staticmethod
    def _path_resolved_version(
            dependency_path: tuple[str, ...],
    ) -> str | None:
        if not dependency_path:
            return None

        target = dependency_path[-1]
        parts = target.split(":")

        if len(parts) < 3:
            return None

        return parts[-1]

    def _inspect_module(
            self,
            module: GradleModule,
            finding: SecurityFinding,
    ) -> str:
        root = self.tools.root

        wrapper_name = (
            "gradlew.bat" if os.name == "nt" else "gradlew"
        )
        wrapper = root / wrapper_name

        task = (
            f"{module.project_path}:dependencyInsight"
            if module.project_path != ":"
            else ":dependencyInsight"
        )

        command = [
            str(wrapper),
            task,
            "--dependency",
            finding.component,
            "--configuration",
            self.configuration,
            "--console=plain",
        ]

        try:
            result = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Gradle dependency inspection timed out."
            ) from exc

        output = (
            f"{result.stdout}\n{result.stderr}"
        ).strip()

        if result.returncode != 0:
            raise RuntimeError(
                "Gradle dependency inspection failed.\n"
                f"{output}"
            )

        return output

    @classmethod
    def _parse_coordinates(
            cls,
            output: str,
    ) -> list[_DependencyCoordinate]:
        coordinates = []

        for line in output.splitlines():
            for match in cls.COORDINATE_PATTERN.finditer(line):
                requested = match.group("requested")
                selected = match.group("selected")

                coordinates.append(
                    _DependencyCoordinate(
                        group=match.group("group"),
                        artifact=match.group("artifact"),
                        requested_version=requested,
                        resolved_version=selected or requested,
                    )
                )

        return coordinates

    @staticmethod
    def _matches_component(
            coordinate: _DependencyCoordinate,
            finding: SecurityFinding,
    ) -> bool:
        parts = finding.component.split(":")

        if len(parts) >= 2:
            expected_group = parts[-2]
            expected_artifact = parts[-1]

            return (
                    coordinate.group.casefold()
                    == expected_group.casefold()
                    and coordinate.artifact.casefold()
                    == expected_artifact.casefold()
            )

        return (
                coordinate.artifact.casefold()
                == finding.component.casefold()
        )

    @classmethod
    def _contains_finding(
            cls,
            output: str,
            finding: SecurityFinding,
    ) -> bool:
        coordinates = [
            coordinate
            for coordinate in cls._parse_coordinates(output)
            if cls._matches_component(coordinate, finding)
        ]

        if coordinates:
            return any(
                coordinate.resolved_version
                == finding.current_version
                for coordinate in coordinates
            )

        # Compatibility with simplified output that contains the
        # component and version but no complete Maven coordinates.
        return (
                finding.component.casefold() in output.casefold()
                and finding.current_version in output
        )

    @classmethod
    def _extract_resolved_version(
            cls,
            output: str,
            finding: SecurityFinding,
    ) -> str | None:
        coordinates = [
            coordinate
            for coordinate in cls._parse_coordinates(output)
            if cls._matches_component(coordinate, finding)
        ]

        for coordinate in coordinates:
            if coordinate.resolved_version == finding.current_version:
                return coordinate.resolved_version

        if coordinates:
            return coordinates[0].resolved_version

        if (
                finding.component.casefold() in output.casefold()
                and finding.current_version in output
        ):
            return finding.current_version

        return None

    @classmethod
    def _iter_dependency_tree_nodes(
            cls,
            output: str,
    ) -> list[_DependencyTreeNode]:
        nodes = []

        for line in output.splitlines():
            marker = cls.TREE_MARKER_PATTERN.search(line)

            if marker:
                coordinate_match = cls.COORDINATE_PATTERN.search(
                    line,
                    marker.end(),
                )

                if not coordinate_match:
                    continue

                requested = coordinate_match.group("requested")
                selected = coordinate_match.group("selected")

                coordinate = _DependencyCoordinate(
                    group=coordinate_match.group("group"),
                    artifact=coordinate_match.group("artifact"),
                    requested_version=requested,
                    resolved_version=selected or requested,
                )

                # Gradle dependencyInsight uses five-character
                # indentation levels in its ASCII dependency tree.
                depth = marker.start() // 5 + 1

                nodes.append(
                    _DependencyTreeNode(
                        depth=depth,
                        coordinate=coordinate,
                    )
                )
                continue

            # The selected dependency normally appears as an
            # unindented root coordinate.
            if line and not line[0].isspace():
                coordinate_match = cls.COORDINATE_PATTERN.match(line)

                if not coordinate_match:
                    continue

                requested = coordinate_match.group("requested")
                selected = coordinate_match.group("selected")

                coordinate = _DependencyCoordinate(
                    group=coordinate_match.group("group"),
                    artifact=coordinate_match.group("artifact"),
                    requested_version=requested,
                    resolved_version=selected or requested,
                )

                nodes.append(
                    _DependencyTreeNode(
                        depth=0,
                        coordinate=coordinate,
                    )
                )

        return nodes

    @classmethod
    def _extract_dependency_paths(
            cls,
            output: str,
            finding: SecurityFinding,
    ) -> tuple[tuple[str, ...], ...]:
        nodes = cls._iter_dependency_tree_nodes(output)

        # Split the report into trees. Each unindented coordinate
        # starts a new dependencyInsight result tree.
        trees: list[list[_DependencyTreeNode]] = []

        for node in nodes:
            if node.depth == 0:
                trees.append([node])
            elif trees:
                trees[-1].append(node)

        paths = []

        for tree in trees:
            root = tree[0].coordinate

            if not cls._matches_component(root, finding):
                continue

            if root.resolved_version != finding.current_version:
                continue

            stack = [root.notation]

            for index, node in enumerate(tree[1:], start=1):
                depth = node.depth

                while len(stack) > depth:
                    stack.pop()

                # Ignore malformed or incomplete indentation rather
                # than guessing the missing dependency relationship.
                if len(stack) != depth:
                    continue

                stack.append(node.coordinate.notation)

                next_depth = (
                    tree[index + 1].depth
                    if index + 1 < len(tree)
                    else -1
                )

                # A leaf represents a direct dependency path back
                # to the selected vulnerable component.
                if next_depth <= depth:
                    path = tuple(reversed(stack))

                    if path not in paths:
                        paths.append(path)

        return tuple(paths)

    @classmethod
    def _contains_direct_dependency(
            cls,
            content: str,
            finding: SecurityFinding,
    ) -> bool:
        configurations = "|".join(
            re.escape(item)
            for item in cls.SUPPORTED_CONFIGURATIONS
        )

        configuration_pattern = re.compile(
            rf"^\s*(?:{configurations})\b(.*)$"
        )

        lines = content.splitlines()
        index = 0

        while index < len(lines):
            match = configuration_pattern.match(lines[index])

            if not match:
                index += 1
                continue

            declaration_lines = [match.group(1)]
            index += 1

            while index < len(lines):
                line = lines[index]
                stripped = line.strip()

                if not stripped or stripped.startswith("//"):
                    index += 1
                    continue

                if stripped.startswith("}"):
                    break

                if configuration_pattern.match(line):
                    break

                declaration_lines.append(line)
                index += 1

            declaration = " ".join(declaration_lines)
            declaration = re.sub(r"//.*", "", declaration)

            if cls._matches_string_notation(declaration, finding):
                return True

            if cls._matches_map_notation(declaration, finding):
                return True

            index += 1

        return False

    @staticmethod
    def _version_matches(
            version: str,
            finding: SecurityFinding,
    ) -> bool:
        if version == finding.current_version:
            return True

        # A variable reference is accepted because Gradle's
        # dependencyInsight output confirms the resolved version.
        return bool(
            re.fullmatch(
                r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?",
                version,
            )
        )

    @classmethod
    def _matches_string_notation(
            cls,
            declaration: str,
            finding: SecurityFinding,
    ) -> bool:
        coordinates = re.findall(
            r"""['"]([^'"]+)['"]""",
            declaration,
        )

        for coordinate in coordinates:
            parts = coordinate.split(":")

            if len(parts) != 3:
                continue

            group, artifact, version = parts

            if not cls._matches_component(
                    _DependencyCoordinate(
                        group=group,
                        artifact=artifact,
                        requested_version=version,
                        resolved_version=version,
                    ),
                    finding,
            ):
                continue

            if cls._version_matches(version, finding):
                return True

        return False

    @classmethod
    def _matches_map_notation(
            cls,
            declaration: str,
            finding: SecurityFinding,
    ) -> bool:
        group_match = re.search(
            r"""group\s*:\s*['"]([^'"]+)['"]""",
            declaration,
        )
        name_match = re.search(
            r"""name\s*:\s*['"]([^'"]+)['"]""",
            declaration,
        )
        version_match = re.search(
            r"""version\s*:\s*['"]([^'"]+)['"]""",
            declaration,
        )

        if not group_match or not name_match or not version_match:
            return False

        group = group_match.group(1)
        artifact = name_match.group(1)
        version = version_match.group(1)

        coordinate = _DependencyCoordinate(
            group=group,
            artifact=artifact,
            requested_version=version,
            resolved_version=version,
        )

        if not cls._matches_component(coordinate, finding):
            return False

        return cls._version_matches(version, finding)
