from security_agent.application.gradle_dependency_report import (
    GradleDependencyGraph,
)
from security_agent.application.repository_inspector import (
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyConstraint,
)
from security_agent.domain.finding import SecurityFinding


class GradleConstraintCollector:
    """Collect finding-specific Gradle constraints from an inspection."""

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
            build_file = module_build_files.get(module_path)

            if not build_file:
                continue

            for edge in graph.find_constraints(
                project_path=module_path,
                target_component=finding.component,
            ):
                if self._selected_version(edge.selected) != finding.current_version:
                    continue

                try:
                    constraint = DependencyConstraint(
                        module_path=module_path,
                        manifest_file=build_file,
                        source_component=edge.from_component,
                        requested=edge.requested,
                        selected=edge.selected,
                    )
                except ValueError:
                    continue

                key = (
                    constraint.module_path,
                    constraint.manifest_file,
                    constraint.source_component,
                    constraint.requested,
                    constraint.selected,
                )

                if key in seen:
                    continue

                seen.add(key)
                constraints.append(constraint)

        return tuple(constraints)

    @staticmethod
    def _selected_version(component: str | None) -> str | None:
        if not component:
            return None

        parts = component.split(":")

        if len(parts) < 3:
            return None

        return parts[-1]
