from dataclasses import dataclass

from security_agent.application.ai_analysis_policy import (
    AIAnalysisDecision,
    AIAnalysisPolicy,
)
from security_agent.application.ai_recommendation_provider import (
    AIRecommendationProvider,
)
from security_agent.domain.ai_recommendation import (
    AIRecommendationResult,
)
from security_agent.domain.analysis import FindingAnalysis
from security_agent.domain.finding import SecurityFinding


@dataclass(frozen=True)
class AIRecommendationOutcome:
    """
    Outcome of an AI recommendation attempt.

    The original deterministic analysis is never modified.
    """

    decision: AIAnalysisDecision
    result: AIRecommendationResult | None = None
    error: str | None = None


class AIRecommendationService:
    """
    Coordinates policy decisions and AI recommendation providers.

    This service does not modify repository files or apply
    recommendations.
    """

    def __init__(
            self,
            policy: AIAnalysisPolicy,
            provider: AIRecommendationProvider | None,
    ):
        self.policy = policy
        self.provider = provider

    def recommend(
            self,
            finding: SecurityFinding,
            analysis: FindingAnalysis,
            force: bool = False,
    ) -> AIRecommendationOutcome:

        decision = self.policy.evaluate(
            finding=finding,
            analysis=analysis,
            force=force,
        )

        if not decision.should_call_ai:
            return AIRecommendationOutcome(
                decision=decision,
            )

        if self.provider is None:
            return AIRecommendationOutcome(
                decision=decision,
                error="No AI recommendation provider is configured.",
            )

        try:
            result = self.provider.recommend(finding)

        except Exception as exc:
            return AIRecommendationOutcome(
                decision=decision,
                error=(
                    "AI recommendation provider failed "
                    f"({type(exc).__name__})."
                ),
            )

        if not isinstance(result, AIRecommendationResult):
            return AIRecommendationOutcome(
                decision=decision,
                error="AI provider returned an invalid result.",
            )

        if result.finding_id != finding.id:
            return AIRecommendationOutcome(
                decision=decision,
                error=(
                    "AI provider returned recommendations "
                    "for a different finding."
                ),
            )

        return AIRecommendationOutcome(
            decision=decision,
            result=result,
        )