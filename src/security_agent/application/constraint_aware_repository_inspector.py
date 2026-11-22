from dataclasses import dataclass, replace

from security_agent.application.gradle_constraint_collector import (
    GradleConstraintCollector,
)
from security_agent.application.gradle_dependency_report import (
    GradleDependencyGraph,
    GradleDependencyReport,
)
from security_agent.application.gradle_version_source_resolver import (
    GradleVersionSourceResolver,
    VersionSourceEvidence,
)
from security_agent.application.repository_inspector import (
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyConstraint,
    DependencyRelationship,
)
from security_agent.domain.finding import SecurityFinding


@dataclass(frozen=True)
class SourceDeclaration:
    module_path: str
    manifest_file: str
    dependency: str
    declaration: str
    declaration_kind: str
    relationship: DependencyRelationship
    dependency_path: tuple[str, ...] = ()
    source_type: str | None = None
    property_name: str | None = None
    lookup_scope: str | None = None
    source_file: str | None = None
    declared_version: str | None = None
    source_resolved: bool | None = None
    candidate_source_file: str | None = None
    candidate_value: str | None = None


@dataclass(frozen=True)
class ConstraintAwareRepositoryInspection(RepositoryInspection):
    constraints: tuple[DependencyConstraint, ...] = ()
    source_declarations: tuple[SourceDeclaration, ...] = ()


class _CapturingReportCollector:
    """Capture the report produced by the existing inspector."""

    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.last_report: GradleDependencyReport | None = None

    @property
    def calls(self) -> int:
        return getattr(self.delegate, "calls", 0)

    def collect(
        self,
        configuration: str = "runtimeClasspath",
    ) -> GradleDependencyReport:
        report = self.delegate.collect(configuration)
        self.last_report = report
        return report


class ConstraintAwareRepositoryInspector:
    """
    Decorate RepositoryInspector with finding-specific Gradle evidence.

    The Gradle report is collected once by the wrapped inspector and
    reused for constraint and source declaration analysis.
    """

    MAX_SOURCE_DECLARATIONS = 30

    def __init__(
        self,
        inspector,
        constraint_collector: GradleConstraintCollector | None = None,
    ) -> None:
        self.inspector = inspector
        self.constraint_collector = constraint_collector or GradleConstraintCollector()
        self._capturing_report_collector = _CapturingReportCollector(
            inspector.report_collector
        )
        self.inspector.report_collector = self._capturing_report_collector

    def inspect(
        self,
        finding: SecurityFinding,
    ) -> ConstraintAwareRepositoryInspection:
        self._capturing_report_collector.last_report = None

        inspection = self.inspector.inspect(finding)
        report = self._capturing_report_collector.last_report

        if report is None:
            return self._to_constraint_aware(inspection, (), ())

        graph = GradleDependencyGraph(report)

        affected_matches = (
            *inspection.matches,
            *inspection.transitive_matches,
        )

        affected_module_build_files = {
            match.project_path: match.build_file for match in affected_matches
        }

        constraints = self.constraint_collector.collect(
            finding=finding,
            inspection=inspection,
            graph=graph,
            module_build_files=affected_module_build_files,
        )

        source_declarations = self._collect_source_declarations(
            finding,
            inspection,
            constraints,
        )

        return self._to_constraint_aware(
            inspection,
            constraints,
            source_declarations,
        )

    def _collect_source_declarations(
        self,
        finding: SecurityFinding,
        inspection: RepositoryInspection,
        constraints: tuple[DependencyConstraint, ...],
    ) -> tuple[SourceDeclaration, ...]:
        tools = getattr(self.inspector, "tools", None)

        if tools is None:
            return ()

        module_build_files = {
            match.project_path: match.build_file
            for match in (
                *inspection.matches,
                *inspection.transitive_matches,
            )
        }

        discovery = getattr(self.inspector, "discovery", None)

        if discovery is not None:
            try:
                for module in discovery.discover():
                    if module.build_file is not None:
                        module_build_files[module.project_path] = module.build_file
            except (RuntimeError, OSError, ValueError):
                # Existing inspection evidence remains usable if module
                # discovery cannot be repeated.
                pass

        # Each request identifies a component declaration to locate
        # in a particular module build file.
        requests: dict[
            str, list[tuple[str, DependencyRelationship, tuple[str, ...]]]
        ] = {}

        for match in inspection.matches:
            self._add_request(
                requests,
                match.project_path,
                finding.component,
                DependencyRelationship.DIRECT,
                (finding.component,),
            )

        for match in inspection.transitive_matches:
            for path in match.dependency_paths:
                if not path:
                    continue

                # A path may begin with an external dependency declared
                # by the affected module.
                first_component = self._component_key(path[0])

                if first_component is not None:
                    self._add_request(
                        requests,
                        match.project_path,
                        first_component,
                        DependencyRelationship.TRANSITIVE,
                        path,
                    )

                # It may also cross one or more Gradle project boundaries.
                # The declaration after "project :module" belongs to
                # that module's build file, not necessarily the consumer.
                for index, component in enumerate(path[:-1]):
                    module_path = self._project_path(component)

                    if module_path is None:
                        continue

                    next_component = self._component_key(path[index + 1])

                    if next_component is None:
                        continue

                    if module_path not in module_build_files:
                        continue

                    self._add_request(
                        requests,
                        module_path,
                        next_component,
                        DependencyRelationship.TRANSITIVE,
                        path[index + 1 :],
                    )

        resolver = GradleVersionSourceResolver(tools)
        declarations: list[SourceDeclaration] = []
        seen: set[tuple] = set()

        # IMPORTANT:
        # A constraint source is scoped to the project whose Gradle
        # configuration produced that constraint. Matching only by
        # component coordinates incorrectly associates a BOM declaration
        # in one module with constraints from other modules.
        constraints_by_source: dict[tuple[str, str], list[DependencyConstraint]] = {}

        for constraint in constraints:
            key = self._component_key(constraint.source_component)

            if key is not None:
                scoped_key = (constraint.module_path, key)
                constraints_by_source.setdefault(scoped_key, []).append(constraint)

        for module_path, module_requests in requests.items():
            manifest_file = module_build_files.get(module_path)

            if not manifest_file:
                continue

            try:
                content = tools.read_file(manifest_file)
            except (
                FileNotFoundError,
                OSError,
                UnicodeError,
                ValueError,
            ):
                continue

            if not isinstance(content, str):
                continue

            for component, relationship, dependency_path in module_requests:
                requested_finding = replace(
                    finding,
                    component=component,
                )

                try:
                    evidence_items = resolver.find_declarations(
                        manifest_file,
                        content,
                        requested_finding,
                    )
                except (ValueError, TypeError):
                    continue

                for evidence in evidence_items:
                    if evidence.declaration_kind == "PLATFORM":
                        # Only constraints from the same module can
                        # establish the provenance of this declaration.
                        related_constraints = constraints_by_source.get(
                            (module_path, evidence.dependency),
                            (),
                        )

                        if related_constraints:
                            for constraint in related_constraints:
                                self._append_evidence(
                                    declarations,
                                    seen,
                                    self._to_source_declaration(
                                        module_path,
                                        manifest_file,
                                        evidence,
                                        constraint.source_relationship,
                                        constraint.provenance_path,
                                    ),
                                )
                        else:
                            self._append_evidence(
                                declarations,
                                seen,
                                self._to_source_declaration(
                                    module_path,
                                    manifest_file,
                                    evidence,
                                    DependencyRelationship.UNKNOWN,
                                    (),
                                ),
                            )
                        continue

                    self._append_evidence(
                        declarations,
                        seen,
                        self._to_source_declaration(
                            module_path,
                            manifest_file,
                            evidence,
                            relationship,
                            dependency_path,
                        ),
                    )

                    if len(declarations) >= self.MAX_SOURCE_DECLARATIONS:
                        return tuple(declarations[: self.MAX_SOURCE_DECLARATIONS])

        return tuple(declarations)

    @staticmethod
    def _add_request(
        requests,
        module_path: str,
        component: str,
        relationship: DependencyRelationship,
        dependency_path: tuple[str, ...],
    ) -> None:
        entries = requests.setdefault(module_path, [])
        request = (component, relationship, dependency_path)

        if request not in entries:
            entries.append(request)

    @staticmethod
    def _component_key(component: str) -> str | None:
        parts = component.split(":")

        if len(parts) < 2:
            return None

        if parts[0].startswith("project "):
            return None

        return f"{parts[0]}:{parts[1]}"

    @staticmethod
    def _project_path(component: str) -> str | None:
        prefix = "project "

        if not component.startswith(prefix):
            return None

        project_path = component[len(prefix) :].strip()

        if not project_path.startswith(":"):
            return None

        return project_path

    @staticmethod
    def _to_source_declaration(
        module_path: str,
        manifest_file: str,
        evidence: VersionSourceEvidence,
        relationship: DependencyRelationship,
        dependency_path: tuple[str, ...],
    ) -> SourceDeclaration:
        return SourceDeclaration(
            module_path=module_path,
            manifest_file=manifest_file,
            dependency=evidence.dependency,
            declaration=evidence.declaration,
            declaration_kind=evidence.declaration_kind,
            relationship=relationship,
            dependency_path=dependency_path,
            source_type=evidence.source_type,
            property_name=evidence.property_name,
            lookup_scope=evidence.lookup_scope,
            source_file=evidence.source_file,
            declared_version=evidence.value,
            source_resolved=evidence.resolved,
            candidate_source_file=evidence.candidate_source_file,
            candidate_value=evidence.candidate_value,
        )

    @staticmethod
    def _append_evidence(
        declarations: list[SourceDeclaration],
        seen: set[tuple],
        evidence: SourceDeclaration,
    ) -> None:
        key = (
            evidence.module_path,
            evidence.manifest_file,
            evidence.dependency,
            evidence.declaration_kind,
            evidence.declaration,
            evidence.relationship,
            evidence.dependency_path,
        )

        if key not in seen:
            seen.add(key)
            declarations.append(evidence)

    @staticmethod
    def _to_constraint_aware(
        inspection: RepositoryInspection,
        constraints: tuple[DependencyConstraint, ...],
        source_declarations: tuple[SourceDeclaration, ...],
    ) -> ConstraintAwareRepositoryInspection:
        return ConstraintAwareRepositoryInspection(
            finding_id=inspection.finding_id,
            configuration=inspection.configuration,
            command_output=inspection.command_output,
            is_consistent=inspection.is_consistent,
            matches=inspection.matches,
            errors=inspection.errors,
            transitive_matches=inspection.transitive_matches,
            constraints=constraints,
            source_declarations=source_declarations,
        )
