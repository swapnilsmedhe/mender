from security_agent.domain.analysis import (
    FindingAnalysis,
    RemediationType,
)
from security_agent.domain.finding import SecurityFinding
from security_agent.domain.remediation import (
    FileChange,
    RemediationPlan,
)


class RemediationPlanner:
    def create_plan(
        self,
        finding: SecurityFinding,
        analysis: FindingAnalysis,
    ) -> RemediationPlan:
        if finding.id != analysis.finding_id:
            raise ValueError(
                "Finding and analysis IDs must match."
            )

        if (
            analysis.recommended_action
            == RemediationType.NO_AUTOMATIC_REMEDIATION
        ):
            return RemediationPlan(
                finding_id=finding.id,
                remediation_type=analysis.recommended_action,
                reason=analysis.root_cause,
                confidence=analysis.confidence,
            )

        if analysis.target_version is None:
            raise ValueError(
                "A version upgrade requires a target version."
            )

        if analysis.target_version not in finding.fixed_versions:
            raise ValueError(
                "Target version must be reported as a fixed version "
                "by the finding."
            )

        change = FileChange(
            file=finding.file,
            dependency=finding.component,
            current_version=finding.current_version,
            target_version=analysis.target_version,
        )

        return RemediationPlan(
            finding_id=finding.id,
            remediation_type=RemediationType.VERSION_UPGRADE,
            reason=analysis.root_cause,
            confidence=analysis.confidence,
            changes=[change],
            validation_steps=[
                "./gradlew test",
                "./gradlew build",
            ],
        )