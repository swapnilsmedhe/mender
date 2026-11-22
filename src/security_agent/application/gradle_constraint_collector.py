from security_agent.application.gradle_dependency_report import (
    GradleDependencyGraph,
)
from security_agent.application.repository_inspector import (
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyConstraint,
    DependencyRelationship,
)
from security_agent.domain.finding import SecurityFinding


class GradleConstraintCollector:
    """Collect finding-specific constraints and their provenance paths."""

    def collect(
        self,
        finding: SecurityFinding,
        inspection: RepositoryInspection,
        graph: GradleDependencyGraph,
        module_build_files: dict[str, str],
    ) -> tuple[DependencyConstraint, ...]:
        if inspection.finding_id != finding.id:
            raise ValueError("Finding and repository inspection IDs do not match.")

        affected_modules = {
            match.project_path
            for match in (
                *inspection.matches,
                *inspection.transitive_matches,
            )
        }

        constraints = []
        seen = set()

        for module_path in sorted(affected_modules):
            module_manifest = module_build_files.get(module_path)

            if not module_manifest:
                continue

            for edge in graph.find_constraints(
                project_path=module_path,
                target_component=finding.component,
            ):
                if self._selected_version(edge.selected) != finding.current_version:
                    continue

                source_paths = graph.find_paths(
                    project_path=module_path,
                    target_component=self._component_selector(edge.from_component),
                )

                provenance_path = self._select_provenance_path(source_paths)
                source_relationship = self._classify_path(provenance_path)

                try:
                    constraint = DependencyConstraint(
                        module_path=module_path,
                        manifest_file=module_manifest,
                        source_component=edge.from_component,
                        requested=edge.requested,
                        selected=edge.selected,
                        provenance_path=provenance_path,
                        source_relationship=source_relationship,
                        selection_reason=edge.selection_reason or None,
                    )
                except ValueError:
                    continue

                key = (
                    constraint.module_path,
                    constraint.source_component,
                    constraint.requested,
                    constraint.selected,
                    constraint.provenance_path,
                )

                if key in seen:
                    continue

                seen.add(key)
                constraints.append(constraint)

        return tuple(constraints)

    @staticmethod
    def _component_selector(component: str) -> str:
        parts = component.split(":")

        if len(parts) >= 2:
            return ":".join(parts[:2])

        return component

    @staticmethod
    def _select_provenance_path(
        paths: tuple[tuple[str, ...], ...],
    ) -> tuple[str, ...]:
        if not paths:
            return ()

        # Prefer the shortest known path. It is the least speculative
        # explanation of how the constraint source entered the module.
        return min(paths, key=lambda path: (len(path), path))

    @staticmethod
    def _classify_path(
        path: tuple[str, ...],
    ) -> DependencyRelationship:
        if not path:
            return DependencyRelationship.UNKNOWN

        if len(path) == 1:
            return DependencyRelationship.DIRECT

        return DependencyRelationship.TRANSITIVE

    @staticmethod
    def _selected_version(component: str | None) -> str | None:
        if not component:
            return None

        parts = component.split(":")

        if len(parts) < 3:
            return None

        return parts[-1]
