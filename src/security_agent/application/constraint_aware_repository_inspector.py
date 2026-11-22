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
class ConstraintSourceProvenance:
    """Resolution evidence linking a declared platform to a selected constraint."""

    source_relationship: DependencyRelationship
    provenance_path: tuple[str, ...]
    requested_component: str
    selected_component: str
    selection_reason: str | None = None


@dataclass(frozen=True)
class SourceDeclaration:
    """
    One unique dependency or platform declaration in a Gradle module.

    Declaration relationship describes how the declaration appears in this
    module's build file. Vulnerable dependency relationship describes how the
    vulnerable component is reached from the declaration. These are distinct
    facts and must not be conflated.
    """

    module_path: str
    manifest_file: str
    dependency: str
    declaration: str
    declaration_kind: str
    declaration_relationship: DependencyRelationship
    vulnerable_dependency_relationship: DependencyRelationship
    dependency_paths: tuple[tuple[str, ...], ...] = ()
    constraint_provenance: tuple[ConstraintSourceProvenance, ...] = ()
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

    The Gradle report is collected once by the wrapped inspector and reused
    for constraint and source declaration analysis.
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

        # Requests are grouped by module and component. Multiple dependency
        # paths to the same component are retained on the same request.
        requests: dict[
            str, dict[str, list[tuple[str, ...]]]
        ] = {}

        for match in inspection.matches:
            self._add_request(
                requests,
                match.project_path,
                self._component_key(finding.component) or finding.component,
                (finding.component,),
            )

        for match in inspection.transitive_matches:
            for path in match.dependency_paths:
                if not path:
                    continue

                # The first external component is the declaration candidate
                # in the affected consumer module.
                first_component = self._component_key(path[0])

                if first_component is not None:
                    self._add_request(
                        requests,
                        match.project_path,
                        first_component,
                        path,
                    )

                # A project boundary changes the source module. The
                # declaration following "project :module" belongs to that
                # module's build file.
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
                        path[index + 1 :],
                    )

        resolver = GradleVersionSourceResolver(tools)
        declarations: list[SourceDeclaration] = []
        declaration_indexes: dict[tuple, int] = {}

        # Constraint provenance is deliberately scoped to the module whose
        # Gradle configuration produced the constraint.
        constraints_by_source: dict[
            tuple[str, str], list[DependencyConstraint]
        ] = {}

        for constraint in constraints:
            source_key = self._component_key(constraint.source_component)

            if source_key is not None:
                constraints_by_source.setdefault(
                    (constraint.module_path, source_key),
                    [],
                ).append(constraint)

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

            for component, dependency_paths in module_requests.items():
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
                        related_constraints = constraints_by_source.get(
                            (module_path, evidence.dependency),
                            (),
                        )

                        provenance = tuple(
                            self._to_constraint_provenance(item)
                            for item in related_constraints
                        )

                        self._append_evidence(
                            declarations,
                            declaration_indexes,
                            self._to_source_declaration(
                                module_path=module_path,
                                manifest_file=manifest_file,
                                evidence=evidence,
                                finding=finding,
                                dependency_paths=(),
                                constraint_provenance=provenance,
                            ),
                        )
                        continue

                    self._append_evidence(
                        declarations,
                        declaration_indexes,
                        self._to_source_declaration(
                            module_path=module_path,
                            manifest_file=manifest_file,
                            evidence=evidence,
                            finding=finding,
                            dependency_paths=tuple(dependency_paths),
                        ),
                    )

                    if len(declarations) >= self.MAX_SOURCE_DECLARATIONS:
                        return tuple(declarations[: self.MAX_SOURCE_DECLARATIONS])

        return tuple(declarations)

    @staticmethod
    def _add_request(
        requests: dict[str, dict[str, list[tuple[str, ...]]]],
        module_path: str,
        component: str,
        dependency_path: tuple[str, ...],
    ) -> None:
        module_requests = requests.setdefault(module_path, {})
        paths = module_requests.setdefault(component, [])

        if dependency_path and dependency_path not in paths:
            paths.append(dependency_path)

    @staticmethod
    def _component_key(component: str) -> str | None:
        parts = component.split(":")

        if len(parts) < 2 or parts[0].startswith("project "):
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
    def _to_constraint_provenance(
        constraint: DependencyConstraint,
    ) -> ConstraintSourceProvenance:
        return ConstraintSourceProvenance(
            source_relationship=constraint.source_relationship,
            provenance_path=constraint.provenance_path,
            requested_component=constraint.requested,
            selected_component=constraint.selected,
            selection_reason=constraint.selection_reason,
        )

    @staticmethod
    def _to_source_declaration(
        module_path: str,
        manifest_file: str,
        evidence: VersionSourceEvidence,
        finding: SecurityFinding,
        dependency_paths: tuple[tuple[str, ...], ...],
        constraint_provenance: tuple[ConstraintSourceProvenance, ...] = (),
    ) -> SourceDeclaration:
        vulnerable_component_key = (
            ConstraintAwareRepositoryInspector._component_key(finding.component)
            or finding.component
        )

        vulnerable_relationship = DependencyRelationship.UNKNOWN

        if evidence.declaration_kind == "DEPENDENCY":
            if evidence.dependency == vulnerable_component_key:
                vulnerable_relationship = DependencyRelationship.DIRECT
            elif dependency_paths:
                vulnerable_relationship = DependencyRelationship.TRANSITIVE

        return SourceDeclaration(
            module_path=module_path,
            manifest_file=manifest_file,
            dependency=evidence.dependency,
            declaration=evidence.declaration,
            declaration_kind=evidence.declaration_kind,
            declaration_relationship=DependencyRelationship.DIRECT,
            vulnerable_dependency_relationship=vulnerable_relationship,
            dependency_paths=dependency_paths,
            constraint_provenance=constraint_provenance,
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
        indexes: dict[tuple, int],
        evidence: SourceDeclaration,
    ) -> None:
        # Declaration identity is independent of the paths through which
        # the declaration participates in the resolved graph.
        key = (
            evidence.module_path,
            evidence.manifest_file,
            evidence.dependency,
            evidence.declaration_kind,
            evidence.declaration,
        )

        existing_index = indexes.get(key)

        if existing_index is None:
            indexes[key] = len(declarations)
            declarations.append(evidence)
            return

        existing = declarations[existing_index]
        merged_paths = tuple(
            dict.fromkeys((*existing.dependency_paths, *evidence.dependency_paths))
        )
        merged_provenance = tuple(
            dict.fromkeys(
                (*existing.constraint_provenance, *evidence.constraint_provenance)
            )
        )

        declarations[existing_index] = replace(
            existing,
            dependency_paths=merged_paths,
            constraint_provenance=merged_provenance,
        )

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
