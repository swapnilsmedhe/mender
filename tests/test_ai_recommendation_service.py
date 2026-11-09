from security_agent.application.ai_analysis_policy import (
    AIAnalysisPolicy,
)
from security_agent.application.ai_recommendation_service import (
    AIRecommendationService,
)
from security_agent.application.analyzer import FindingAnalyzer
from security_agent.domain.ai_recommendation import (
    AIRecommendationResult,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


class FakeAIRecommendationProvider:
    def __init__(self):
        self.call_count = 0

    def recommend(self, finding):
        self.call_count += 1

        return AIRecommendationResult(
            finding_id=finding.id,
            summary="AI identified a remediation option.",
            provider="fake",
            recommendations=(),
        )


class FailingAIRecommendationProvider:
    def recommend(self, finding):
        raise RuntimeError("Simulated provider failure")


class InvalidAIRecommendationProvider:
    def recommend(self, finding):
        return None


class MismatchedAIRecommendationProvider:
    def recommend(self, finding):
        return AIRecommendationResult(
            finding_id="different-finding",
            summary="Incorrect finding result.",
            provider="fake",
            recommendations=(),
        )


def create_finding(fixed_versions=None):
    return SecurityFinding(
        id="finding-001",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2025-1234",
        component="org.example:library",
        current_version="1.0.0",
        fixed_versions=(
            ["1.1.0"]
            if fixed_versions is None
            else fixed_versions
        ),
        repository="sample-repository",
        file="build.gradle",
    )


def create_service(provider):
    return AIRecommendationService(
        policy=AIAnalysisPolicy(),
        provider=provider,
    )


def test_ai_is_not_called_for_deterministic_analysis():
    finding = create_finding()
    analysis = FindingAnalyzer().analyze(finding)
    provider = FakeAIRecommendationProvider()

    service = create_service(provider)

    outcome = service.recommend(finding, analysis)

    assert outcome.result is None
    assert outcome.error is None
    assert outcome.decision.should_call_ai is False
    assert provider.call_count == 0


def test_ai_is_called_when_no_fixed_version_is_available():
    finding = create_finding(fixed_versions=[])
    analysis = FindingAnalyzer().analyze(finding)
    provider = FakeAIRecommendationProvider()

    service = create_service(provider)

    outcome = service.recommend(finding, analysis)

    assert outcome.decision.should_call_ai is True
    assert outcome.result is not None
    assert outcome.result.finding_id == finding.id
    assert provider.call_count == 1


def test_force_calls_ai_even_when_deterministic_result_exists():
    finding = create_finding()
    analysis = FindingAnalyzer().analyze(finding)
    provider = FakeAIRecommendationProvider()

    service = create_service(provider)

    outcome = service.recommend(
        finding,
        analysis,
        force=True,
    )

    assert outcome.decision.should_call_ai is True
    assert outcome.result is not None
    assert provider.call_count == 1


def test_missing_provider_returns_error_without_raising():
    finding = create_finding(fixed_versions=[])
    analysis = FindingAnalyzer().analyze(finding)

    service = create_service(provider=None)

    outcome = service.recommend(finding, analysis)

    assert outcome.result is None
    assert outcome.error == (
        "No AI recommendation provider is configured."
    )


def test_provider_failure_does_not_raise():
    finding = create_finding(fixed_versions=[])
    analysis = FindingAnalyzer().analyze(finding)

    service = create_service(
        FailingAIRecommendationProvider()
    )

    outcome = service.recommend(finding, analysis)

    assert outcome.result is None
    assert outcome.error == (
        "AI recommendation provider failed (RuntimeError)."
    )


def test_invalid_provider_response_is_rejected():
    finding = create_finding(fixed_versions=[])
    analysis = FindingAnalyzer().analyze(finding)

    service = create_service(
        InvalidAIRecommendationProvider()
    )

    outcome = service.recommend(finding, analysis)

    assert outcome.result is None
    assert outcome.error == (
        "AI provider returned an invalid result."
    )


def test_result_for_different_finding_is_rejected():
    finding = create_finding(fixed_versions=[])
    analysis = FindingAnalyzer().analyze(finding)

    service = create_service(
        MismatchedAIRecommendationProvider()
    )

    outcome = service.recommend(finding, analysis)

    assert outcome.result is None
    assert outcome.error == (
        "AI provider returned recommendations "
        "for a different finding."
    )