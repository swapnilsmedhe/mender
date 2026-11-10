
from typing import Protocol, runtime_checkable

from security_agent.domain.ai_recommendation import AIRecommendationResult
from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
)
from security_agent.domain.finding import SecurityFinding


@runtime_checkable
class AIRecommendationProvider(Protocol):
    def recommend(
            self,
            finding: SecurityFinding,
            context: AIRecommendationContext,
    ) -> AIRecommendationResult:
        ...
