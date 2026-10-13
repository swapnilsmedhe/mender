from security_agent.domain.analysis import (
    Confidence,
    FindingAnalysis,
    RemediationType,
)
from security_agent.domain.finding import SecurityFinding


class FindingAnalyzer:
    def analyze(self, finding: SecurityFinding) -> FindingAnalysis:
        if not finding.fixed_versions:
            return FindingAnalysis(
                finding_id=finding.id,
                root_cause="No fixed version was reported by the scanner.",
                recommended_action=(
                    RemediationType.NO_AUTOMATIC_REMEDIATION
                ),
                target_version=None,
                confidence=Confidence.HIGH,
            )

        return FindingAnalysis(
            finding_id=finding.id,
            root_cause=(
                f"{finding.component} is reported vulnerable at "
                f"version {finding.current_version}. "
                "The scanner reports at least one fixed version."
            ),
            recommended_action=RemediationType.VERSION_UPGRADE,
            target_version=finding.fixed_versions[0],
            confidence=Confidence.HIGH,
        )