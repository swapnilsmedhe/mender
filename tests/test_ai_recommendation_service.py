
import pytest

from security_agent.application.ai_analysis_policy import (
    AIAnalysisDecision,
    AIAnalysisReason,
)
from security_agent.application.ai_recommendation_context_builder import (
    AIRecommendationContextBuilder,
)
from security_agent.application.ai_recommendation_provider import (
    AIRecommendationProvider,
)
from security_agent.application.ai_recommendation_service import (
    AIRecommendationService,
)
from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation import (
    AIRecommendationResult,
)
from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
)
from security_agent.domain.analysis import (
    Confidence,
    FindingAnalysis,
    RemediationType,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


@pytest.fixture
def finding():
    return SecurityFinding(
        id="finding-1",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2024-0001",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.15.2",
        fixed_versions=[],
        repository="/repo",
        file="build.gradle",
    )


@pytest.fixture
def analysis():
    return FindingAnalysis(
        finding_id="finding-1",
        root_cause="No fixed version was reported.",
        recommended_action=RemediationType.NO_AUTOMATIC_REMEDIATION,
        target_version=None,
        confidence=Confidence.HIGH,
    )


@pytest.fixture
def inspection():
    return RepositoryInspection(
        finding_id="finding-1",
        configuration="runtimeClasspath",
        command_output="raw gradle output",
        is_consistent=True,
        matches=[
            ModuleMatch(
                project_path=":app",
                build_file="app/build.gradle",
                command_output="dependency output",
            )
        ],
        errors=[],
        transitive_matches=[],
    )


@pytest.fixture
def decision():
    return AIAnalysisDecision(
        finding_id="finding-1",
        should_call_ai=True,
        reason=AIAnalysisReason.NO_FIXED_VERSION_REPORTED,
    )


class FakePolicy:
    def __init__(self, decision):
        self.decision = decision
        self.calls = []

    def evaluate(self, finding, analysis, force=False):
        self.calls.append((finding, analysis, force))
        return self.decision


class FakeProvider:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def recommend(self, finding, context):
        self.calls.append((finding, context))

        if self.error:
            raise self.error

        return self.result


class FakeContextBuilder:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def build(self, finding, inspection):
        self.calls.append((finding, inspection))

        if self.error:
            raise self.error

        return self.result


def create_result(finding_id="finding-1"):
    return AIRecommendationResult(
        finding_id=finding_id,
        summary="AI recommendation summary",
        provider="test-provider",
    )


class TestAIRecommendationService:
    def test_skips_provider_when_policy_does_not_require_ai(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        skip_decision = AIAnalysisDecision(
            finding_id="finding-1",
            should_call_ai=False,
            reason=decision.reason,
        )

        policy = FakePolicy(skip_decision)
        provider = FakeProvider(result=create_result())
        context_builder = FakeContextBuilder()

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
            context_builder=context_builder,
        )

        outcome = service.recommend(
            finding,
            analysis,
            inspection=inspection,
        )

        assert outcome.result is None
        assert outcome.error is None
        assert outcome.decision == skip_decision
        assert provider.calls == []
        assert context_builder.calls == []

    def test_returns_error_when_provider_is_missing(
            self,
            finding,
            analysis,
            decision,
    ):
        policy = FakePolicy(decision)

        service = AIRecommendationService(
            policy=policy,
            provider=None,
        )

        outcome = service.recommend(
            finding,
            analysis,
        )

        assert outcome.result is None
        assert outcome.error == (
            "No AI recommendation provider is configured."
        )

    def test_returns_error_when_inspection_is_missing(
            self,
            finding,
            analysis,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(result=create_result())

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
        )

        outcome = service.recommend(
            finding,
            analysis,
        )

        assert outcome.result is None
        assert outcome.error == (
            "Repository inspection is required "
            "for AI recommendations."
        )
        assert provider.calls == []

    def test_builds_context_and_calls_provider(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(result=create_result())

        context_builder = AIRecommendationContextBuilder()

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
            context_builder=context_builder,
        )

        outcome = service.recommend(
            finding,
            analysis,
            inspection=inspection,
        )

        assert outcome.error is None
        assert outcome.result == create_result()

        assert len(provider.calls) == 1

        called_finding, called_context = provider.calls[0]

        assert called_finding == finding
        assert isinstance(called_context, AIRecommendationContext)
        assert called_context.finding_id == finding.id
        assert called_context.dependency_name == finding.component
        assert len(called_context.locations) == 1

    def test_passes_force_to_policy(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(result=create_result())

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
        )

        service.recommend(
            finding,
            analysis,
            force=True,
            inspection=inspection,
        )

        assert policy.calls[0][2] is True

    def test_handles_context_builder_failure(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(result=create_result())

        context_builder = FakeContextBuilder(
            error=RuntimeError("Context failure"),
        )

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
            context_builder=context_builder,
        )

        outcome = service.recommend(
            finding,
            analysis,
            inspection=inspection,
        )

        assert outcome.result is None
        assert outcome.error == (
            "AI recommendation context building failed "
            "(RuntimeError)."
        )
        assert provider.calls == []

    def test_handles_provider_exception(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(
            error=RuntimeError("Provider failure"),
        )

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
        )

        outcome = service.recommend(
            finding,
            analysis,
            inspection=inspection,
        )

        assert outcome.result is None
        assert outcome.error == (
            "AI recommendation provider failed (RuntimeError)."
        )

    def test_handles_invalid_provider_result(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(result="invalid result")

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
        )

        outcome = service.recommend(
            finding,
            analysis,
            inspection=inspection,
        )

        assert outcome.result is None
        assert outcome.error == (
            "AI provider returned an invalid result."
        )

    def test_rejects_result_for_different_finding(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(
            result=create_result("another-finding"),
        )

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
        )

        outcome = service.recommend(
            finding,
            analysis,
            inspection=inspection,
        )

        assert outcome.result is None
        assert outcome.error == (
            "AI provider returned recommendations "
            "for a different finding."
        )

    def test_preserves_original_analysis(
            self,
            finding,
            analysis,
            inspection,
            decision,
    ):
        policy = FakePolicy(decision)
        provider = FakeProvider(result=create_result())

        service = AIRecommendationService(
            policy=policy,
            provider=provider,
        )

        original_analysis = analysis

        service.recommend(
            finding,
            analysis,
            inspection=inspection,
        )

        assert analysis is original_analysis
        assert analysis.recommended_action == (
            RemediationType.NO_AUTOMATIC_REMEDIATION
        )
        assert analysis.target_version is None
