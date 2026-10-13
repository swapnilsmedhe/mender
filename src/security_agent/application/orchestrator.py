from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.planner import RemediationPlanner
from security_agent.domain.finding import SecurityFinding
from security_agent.domain.remediation import RemediationPlan


class SecurityRemediationOrchestrator:
    def __init__(
        self,
        analyzer: FindingAnalyzer,
        planner: RemediationPlanner,
    ) -> None:
        self.analyzer = analyzer
        self.planner = planner

    def run(self, finding: SecurityFinding) -> RemediationPlan:
        analysis = self.analyzer.analyze(finding)

        plan = self.planner.create_plan(
            finding=finding,
            analysis=analysis,
        )

        return plan