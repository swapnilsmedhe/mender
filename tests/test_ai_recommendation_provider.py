from security_agent.application.ai_recommendation_provider import (
    AIRecommendationProvider,
)
from security_agent.domain.ai_recommendation import (
    AIRecommendationResult,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


class FakeAIRecommendationProvider:
    def recommend(
            self,
            finding: SecurityFinding,
    ) -> AIRecommendationResult:
        return AIRecommendationResult(
            finding_id=finding.id,
            summary="A remediation option was identified.",
            provider="fake",
            recommendations=(),
        )


def create_finding():
    return SecurityFinding(
        id="finding-001",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2025-1234",
        component="org.example:library",
        current_version="1.0.0",
        fixed_versions=["1.1.0"],
        repository="sample-repository",
        file="build.gradle",
    )


def test_fake_provider_implements_recommendation_protocol():
    provider = FakeAIRecommendationProvider()

    assert isinstance(provider, AIRecommendationProvider)


def test_provider_returns_recommendation_result():
    provider = FakeAIRecommendationProvider()
    finding = create_finding()

    result = provider.recommend(finding)

    assert isinstance(result, AIRecommendationResult)
    assert result.finding_id == finding.id
    assert result.provider == "fake"