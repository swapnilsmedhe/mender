from dataclasses import dataclass

from security_agent.application.gradle_constraint_collector import (
    GradleConstraintCollector,
)
from security_agent.application.gradle_dependency_report import (
    GradleDependencyGraph,
    GradleDependencyReport,
)
from security_agent.application.repository_inspector import (
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyConstraint,
)
from security_agent.domain.finding import SecurityFinding


@dataclass(frozen=True)
class ConstraintAwareRepositoryInspection(RepositoryInspection):
    constraints: tuple[DependencyConstraint, ...] = ()


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
    Decorate RepositoryInspector with finding-specific constraint evidence.

    The existing inspector performs the Gradle report collection. This
    decorator reuses that report rather than invoking Gradle a second time.
    """

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
            return self._to_constraint_aware(inspection, ())

        graph = GradleDependencyGraph(report)

        affected_matches = (
            *inspection.matches,
            *inspection.transitive_matches,
        )

        module_build_files = {
            match.project_path: match.build_file for match in affected_matches
        }

        constraints = self.constraint_collector.collect(
            finding=finding,
            inspection=inspection,
            graph=graph,
            module_build_files=module_build_files,
        )

        return self._to_constraint_aware(
            inspection,
            constraints,
        )

    @staticmethod
    def _to_constraint_aware(
        inspection: RepositoryInspection,
        constraints: tuple[DependencyConstraint, ...],
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
        )
