from typing import Protocol, runtime_checkable

from security_agent.domain.ai_recommendation import (
    AIRecommendationResult,
)
from security_agent.domain.finding import SecurityFinding


@runtime_checkable
class AIRecommendationProvider(Protocol):
    """
    Contract for AI providers that suggest remediation options.

    Implementations may use GitHub Copilot, an API-key-based provider,
    or another supported AI service.

    Providers must not modify repository files.
    """

    def recommend(
            self,
            finding: SecurityFinding,
    ) -> AIRecommendationResult:
        """
        Generate remediation options for one security finding.

        Returns structured recommendations. It must not modify files,
        apply changes, or perform Git operations.
        """
        ...