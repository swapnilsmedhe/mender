
from dataclasses import replace

from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.planner import RemediationPlanner
from security_agent.application.repository_inspector import RepositoryInspector
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
            matching_modules = [
                match.project_path for match in inspection.matches
            ]

            details = (
                f"Matching modules: {', '.join(matching_modules)}"
                if matching_modules
                else "No matching module was identified."
            )

            errors = (
                "\nInspection errors:\n" + "\n".join(inspection.errors)
                if inspection.errors
                else ""
            )

            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                f"{details}\n"
                f"{errors}\n"
                "No remediation plan was generated."
            )

        if len(inspection.matches) != 1:
            raise ValueError(
                f"Expected exactly one matching Gradle module for "
                f"finding {finding.id}, but found "
                f"{len(inspection.matches)}.\n"
                "No remediation plan was generated."
            )

        matched_module = inspection.matches[0]

        # Use the actual build file discovered by Gradle.
        updated_finding = replace(
            finding,
            file=matched_module.build_file,
        )

        analysis = self.analyzer.analyze(updated_finding)

        return self.planner.create_plan(
            finding=updated_finding,
            analysis=analysis,
        )
