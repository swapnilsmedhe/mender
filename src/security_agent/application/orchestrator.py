from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.planner import RemediationPlanner
from security_agent.application.repository_inspector import (
    RepositoryInspector,
)
from security_agent.domain.finding import SecurityFinding
from security_agent.domain.remediation import RemediationPlan


class SecurityRemediationOrchestrator:
    def __init__(
        self,
        analyzer: FindingAnalyzer,
        planner: RemediationPlanner,
        inspector: RepositoryInspector,
    ) -> None:
        self.analyzer = analyzer
        self.planner = planner
        self.inspector = inspector

    def run(self, finding: SecurityFinding) -> RemediationPlan:
        inspection = self.inspector.inspect(finding)

        if not inspection.is_consistent:
            raise ValueError(
                f"Repository evidence does not match finding "
                f"{finding.id}. "
                f"Component matches: {len(inspection.component_matches)}, "
                f"version matches: {len(inspection.version_matches)}. "
                "No remediation plan was generated."
            )

        analysis = self.analyzer.analyze(finding)

        return self.planner.create_plan(
            finding=finding,
            analysis=analysis,
        )
