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
        # Step 1: Inspect the resolved dependency using Gradle.
        inspection = self.inspector.inspect(finding)

        # Step 2: Stop if the finding cannot be verified.
        if not inspection.is_consistent:
            raise ValueError(
                f"Repository evidence does not match finding "
                f"{finding.id}.\n"
                f"Gradle configuration: {inspection.configuration}\n"
                f"Dependency: {finding.component}\n"
                f"Reported version: {finding.current_version}\n"
                "No remediation plan was generated."
            )

        # Step 3: Analyze the verified finding.
        analysis = self.analyzer.analyze(finding)

        # Step 4: Generate the remediation plan.
        return self.planner.create_plan(
            finding=finding,
            analysis=analysis,
        )
