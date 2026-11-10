
from dataclasses import dataclass

from security_agent.application.ai_analysis_policy import (
    AIAnalysisDecision,
    AIAnalysisPolicy,
)
from security_agent.application.ai_recommendation_context_builder import (
    AIRecommendationContextBuilder,
)
from security_agent.application.ai_recommendation_provider import (
    AIRecommendationProvider,
)
from security_agent.application.repository_inspector import (
    RepositoryInspection,
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
    Coordinates policy decisions, context building,
    and AI recommendation providers.

    This service does not modify repository files or apply
    recommendations.
    """

    def __init__(
            self,
            policy: AIAnalysisPolicy,
            provider: AIRecommendationProvider | None,
            context_builder: AIRecommendationContextBuilder | None = None,
    ):
        self.policy = policy
        self.provider = provider
        self.context_builder = (
                context_builder or AIRecommendationContextBuilder()
        )

    def recommend(
            self,
            finding: SecurityFinding,
            analysis: FindingAnalysis,
            force: bool = False,
            inspection: RepositoryInspection | None = None,
    ) -> AIRecommendationOutcome:

        decision = self.policy.evaluate(
            finding=finding,
            analysis=analysis,
            force=force,
        )

        # Do not build context or call AI when policy says it is unnecessary.
        if not decision.should_call_ai:
            return AIRecommendationOutcome(
                decision=decision,
            )

        if self.provider is None:
            return AIRecommendationOutcome(
                decision=decision,
                error="No AI recommendation provider is configured.",
            )

        if inspection is None:
            return AIRecommendationOutcome(
                decision=decision,
                error=(
                    "Repository inspection is required "
                    "for AI recommendations."
                ),
            )

        # Build only the compact context required by the AI provider.
        try:
            context = self.context_builder.build(
                finding=finding,
                inspection=inspection,
            )
        except Exception as exc:
            return AIRecommendationOutcome(
                decision=decision,
                error=(
                    "AI recommendation context building failed "
                    f"({type(exc).__name__})."
                ),
            )

        try:
            result = self.provider.recommend(
                finding=finding,
                context=context,
            )
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
