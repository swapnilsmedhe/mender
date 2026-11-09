from typing import Protocol, runtime_checkable

from security_agent.domain.analysis import FindingAnalysis
from security_agent.domain.finding import SecurityFinding


@runtime_checkable
class AIAnalysisProvider(Protocol):
    """
    Contract for AI providers used to analyze security findings.

    Implementations may use GitHub Copilot, an API-key-based provider,
    or another supported AI service.
    """

    def analyze(self, finding: SecurityFinding) -> FindingAnalysis:
        """
        Analyze a security finding and return a structured analysis.

        This method must not modify repository files.
        """
        ...