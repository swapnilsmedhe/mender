import base64
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from security_agent.tools.repository import RepositoryTools


@dataclass(frozen=True)
class GradleDependencyEdge:
    project_path: str
    configuration: str
    from_component: str
    requested: str
    selected: str | None
    is_constraint: bool
    status: str
    selection_reason: str = ""


@dataclass(frozen=True)
class GradleDependencyReport:
    configuration: str
    edges: tuple[GradleDependencyEdge, ...] = ()
    errors: tuple[str, ...] = ()


class GradleDependencyGraph:
    """Find dependency paths and relevant constraints in a Gradle project."""

    def __init__(self, report: GradleDependencyReport) -> None:
        self.report = report
        self._adjacency: dict[tuple[str, str], list[str]] = {}

        for edge in report.edges:
            if edge.status != "RESOLVED" or edge.is_constraint or edge.selected is None:
                continue

            key = (edge.project_path, edge.from_component)
            children = self._adjacency.setdefault(key, [])

            if edge.selected not in children:
                children.append(edge.selected)

    def find_paths(
        self,
        project_path: str,
        target_component: str,
        max_paths: int = 100,
    ) -> tuple[tuple[str, ...], ...]:
        """Return ordinary dependency paths from a project root."""
        if not project_path.strip():
            raise ValueError("Project path cannot be empty.")

        if not target_component.strip():
            raise ValueError("Target component cannot be empty.")

        if max_paths < 1:
            raise ValueError("max_paths must be at least 1.")

        root = f"project {project_path}"
        paths: list[tuple[str, ...]] = []

        def visit(
            current: str,
            path: tuple[str, ...],
            visited: frozenset[str],
        ) -> None:
            if len(paths) >= max_paths:
                return

            for child in self._adjacency.get(
                (project_path, current),
                (),
            ):
                if child in visited:
                    continue

                next_path = (*path, child)

                if self._matches_component(child, target_component):
                    paths.append(next_path)
                    if len(paths) >= max_paths:
                        return
                    continue

                visit(
                    child,
                    next_path,
                    visited | {child},
                )

                if len(paths) >= max_paths:
                    return

        visit(root, (), frozenset({root}))
        return tuple(paths)

    def find_constraints(
        self,
        project_path: str,
        target_component: str,
    ) -> tuple[GradleDependencyEdge, ...]:
        """Return resolved constraints selecting the target component."""
        if not project_path.strip():
            raise ValueError("Project path cannot be empty.")

        if not target_component.strip():
            raise ValueError("Target component cannot be empty.")

        return tuple(
            edge
            for edge in self.report.edges
            if (
                edge.project_path == project_path
                and edge.status == "RESOLVED"
                and edge.is_constraint
                and edge.selected is not None
                and self._matches_component(
                    edge.selected,
                    target_component,
                )
            )
        )

    @staticmethod
    def _matches_component(
        resolved_component: str,
        target_component: str,
    ) -> bool:
        resolved_parts = resolved_component.split(":")
        target_parts = target_component.split(":")

        if len(target_parts) >= 2:
            if len(resolved_parts) < 2:
                return False

            return (
                resolved_parts[0].casefold() == target_parts[-2].casefold()
                and resolved_parts[1].casefold() == target_parts[-1].casefold()
            )

        return resolved_parts[-1].casefold() == target_component.casefold()


class GradleDependencyReportCollector:
    EDGE_MARKER = "SECURITY_AGENT_EDGE"
    ERROR_MARKER = "SECURITY_AGENT_REPORT_ERROR"

    def __init__(
        self,
        tools: RepositoryTools,
        timeout_seconds: int = 120,
    ) -> None:
        self.tools = tools
        self.timeout_seconds = timeout_seconds

    def collect(
        self,
        configuration: str = "runtimeClasspath",
    ) -> GradleDependencyReport:
        root = self.tools.root.resolve()
        wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
        wrapper = root / wrapper_name

        if not wrapper.is_file():
            raise FileNotFoundError(f"Gradle wrapper not found: {wrapper}")

        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "dependency-report.init.gradle"
            script_path.write_text(
                self._create_init_script(),
                encoding="utf-8",
            )

            command = [
                str(wrapper),
                "--init-script",
                str(script_path),
                f"-Pmender.configuration={configuration}",
                "help",
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
                raise RuntimeError("Gradle dependency report timed out.") from exc

        output = f"{result.stdout}\n{result.stderr}"
        report = self.parse_output(output, configuration)

        if result.returncode != 0:
            raise RuntimeError(
                f"Gradle dependency report execution failed.\n{output.strip()}"
            )

        return report

    @classmethod
    def parse_output(
        cls,
        output: str,
        configuration: str,
    ) -> GradleDependencyReport:
        edges = []
        errors = []

        for line in output.splitlines():
            if line.startswith(cls.EDGE_MARKER + "\t"):
                parts = line.split("\t")

                # Eight fields preserve compatibility with reports
                # generated before selection reasons were added.
                if len(parts) not in (8, 9):
                    continue

                try:
                    project_path = cls._decode(parts[1])
                    edge_configuration = cls._decode(parts[2])
                    from_component = cls._decode(parts[3])
                    requested = cls._decode(parts[4])
                    selected_value = cls._decode(parts[5])
                    constraint_value = cls._decode(parts[6])
                    status = cls._decode(parts[7])
                    selection_reason = cls._decode(parts[8]) if len(parts) == 9 else ""
                except (ValueError, UnicodeDecodeError):
                    continue

                if constraint_value not in ("true", "false"):
                    continue

                edges.append(
                    GradleDependencyEdge(
                        project_path=project_path,
                        configuration=edge_configuration,
                        from_component=from_component,
                        requested=requested,
                        selected=selected_value or None,
                        is_constraint=constraint_value == "true",
                        status=status,
                        selection_reason=selection_reason,
                    )
                )

            elif line.startswith(cls.ERROR_MARKER + "\t"):
                parts = line.split("\t")

                if len(parts) != 4:
                    continue

                try:
                    project_path = cls._decode(parts[1])
                    edge_configuration = cls._decode(parts[2])
                    message = cls._decode(parts[3])
                except (ValueError, UnicodeDecodeError):
                    continue

                errors.append(f"{project_path} ({edge_configuration}): {message}")

        return GradleDependencyReport(
            configuration=configuration,
            edges=tuple(edges),
            errors=tuple(errors),
        )

    @staticmethod
    def _decode(value: str) -> str:
        return base64.b64decode(
            value,
            validate=True,
        ).decode("utf-8")

    @staticmethod
    def _create_init_script() -> str:
        return r"""
import java.util.Base64
import org.gradle.api.artifacts.result.ResolvedDependencyResult

def encodeValue = { value ->
    Base64.encoder.encodeToString(
        value.toString().getBytes("UTF-8")
    )
}

def emitEdge = { projectPath, configuration, from, requested,
                 selected, isConstraint, status, selectionReason ->
    println(
        "SECURITY_AGENT_EDGE\t" +
        encodeValue(projectPath) + "\t" +
        encodeValue(configuration) + "\t" +
        encodeValue(from) + "\t" +
        encodeValue(requested) + "\t" +
        encodeValue(selected ?: "") + "\t" +
        encodeValue(isConstraint.toString()) + "\t" +
        encodeValue(status) + "\t" +
        encodeValue(selectionReason ?: "")
    )
}

def emitError = { projectPath, configuration, message ->
    println(
        "SECURITY_AGENT_REPORT_ERROR\t" +
        encodeValue(projectPath) + "\t" +
        encodeValue(configuration) + "\t" +
        encodeValue(message)
    )
}

gradle.projectsEvaluated {
    def configurationName =
        gradle.startParameter.projectProperties[
            "mender.configuration"
        ] ?: "runtimeClasspath"

    gradle.rootProject.allprojects.each { project ->
        def configuration =
            project.configurations.findByName(configurationName)

        if (configuration == null) {
            return
        }

        try {
            def resolutionResult =
                configuration.incoming.resolutionResult

            def root = resolutionResult.root
            def queue = new ArrayList()
            def visitedEdges = new LinkedHashSet()

            root.dependencies.each { dependency ->
                queue.add([root, dependency])
            }

            while (!queue.isEmpty()) {
                def item = queue.remove(0)
                def from = item[0]
                def dependency = item[1]

                if (dependency instanceof ResolvedDependencyResult) {
                    def selected = dependency.selected
                    def fromId = from.id.displayName
                    def selectedId = selected.id.displayName

                    def selectionReason =
                        selected.selectionReason.descriptions
                            .collect { descriptor -> descriptor.description }
                            .findAll { description -> description }
                            .unique()
                            .join("; ")

                    emitEdge(
                        project.path,
                        configurationName,
                        fromId,
                        dependency.requested.displayName,
                        selectedId,
                        dependency.isConstraint(),
                        "RESOLVED",
                        selectionReason
                    )

                    def edgeKey = [
                        fromId,
                        selectedId,
                        dependency.requested.displayName,
                        dependency.isConstraint()
                    ].join("|")

                    if (visitedEdges.add(edgeKey)) {
                        selected.dependencies.each { child ->
                            queue.add([selected, child])
                        }
                    }
                } else {
                    emitEdge(
                        project.path,
                        configurationName,
                        from.id.displayName,
                        dependency.requested.displayName,
                        "",
                        dependency.isConstraint(),
                        "UNRESOLVED",
                        ""
                    )
                }
            }
        } catch (Exception exception) {
            emitError(
                project.path,
                configurationName,
                exception.class.simpleName + ": " +
                    (exception.message ?: "Unknown resolution error")
            )
        }
    }
}
"""


# Temporary compatibility with the existing RepositoryInspector import.
GradleDependencyReportParser = GradleDependencyReportCollector
