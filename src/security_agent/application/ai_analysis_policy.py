
from dataclasses import dataclass
from enum import Enum

from security_agent.domain.analysis import (
    FindingAnalysis,
    RemediationType,
)
from security_agent.domain.finding import SecurityFinding


class AIAnalysisReason(str, Enum):
    MANUAL_REQUEST = "MANUAL_REQUEST"
    NO_FIXED_VERSION_REPORTED = "NO_FIXED_VERSION_REPORTED"
    MULTIPLE_FIXED_VERSIONS = "MULTIPLE_FIXED_VERSIONS"
    INCONCLUSIVE_ANALYSIS = "INCONCLUSIVE_ANALYSIS"
    INVALID_TARGET_VERSION = "INVALID_TARGET_VERSION"
    DETERMINISTIC_RESULT_AVAILABLE = "DETERMINISTIC_RESULT_AVAILABLE"


@dataclass(frozen=True)
class AIAnalysisDecision:
    finding_id: str
    should_call_ai: bool
    reason: AIAnalysisReason


class AIAnalysisPolicy:
    """
    Decides whether a security finding requires deeper AI analysis.

    This class does not call an AI provider and does not modify
    existing analysis or remediation results.
    """

    def evaluate(
            self,
            finding: SecurityFinding,
            analysis: FindingAnalysis,
            force: bool = False,
    ) -> AIAnalysisDecision:

        if finding.id != analysis.finding_id:
            raise ValueError(
                "Finding ID does not match the analysis finding ID."
            )

        if force:
            return self._decision(
                finding.id,
                True,
                AIAnalysisReason.MANUAL_REQUEST,
            )

        unique_fixed_versions = list(dict.fromkeys(finding.fixed_versions))

        if not unique_fixed_versions:
            return self._decision(
                finding.id,
                True,
                AIAnalysisReason.NO_FIXED_VERSION_REPORTED,
            )

        if len(unique_fixed_versions) > 1:
            return self._decision(
                finding.id,
                True,
                AIAnalysisReason.MULTIPLE_FIXED_VERSIONS,
            )

        if analysis.recommended_action != RemediationType.VERSION_UPGRADE:
            return self._decision(
                finding.id,
                True,
                AIAnalysisReason.INCONCLUSIVE_ANALYSIS,
            )

        if (
                analysis.target_version is None
                or analysis.target_version not in unique_fixed_versions
        ):
            return self._decision(
                finding.id,
                True,
                AIAnalysisReason.INVALID_TARGET_VERSION,
            )

        return self._decision(
            finding.id,
            False,
            AIAnalysisReason.DETERMINISTIC_RESULT_AVAILABLE,
        )

    @staticmethod
    def _decision(
            finding_id: str,
            should_call_ai: bool,
            reason: AIAnalysisReason,
    ) -> AIAnalysisDecision:
        return AIAnalysisDecision(
            finding_id=finding_id,
            should_call_ai=should_call_ai,
            reason=reason,
        )
