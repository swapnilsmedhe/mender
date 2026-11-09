
from security_agent.application.ai_provider import AIAnalysisProvider
from security_agent.application.analyzer import FindingAnalyzer
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


def create_finding(fixed_versions=None):
    return SecurityFinding(
        id="FINDING-001",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2025-12345",
        component="jackson-databind",
        current_version="2.15.2",
        fixed_versions=(
            ["2.16.0"] if fixed_versions is None else fixed_versions
        ),
        repository="/tmp/sample-repository",
        file="build.gradle.kts",
    )


class FakeAIProvider:
    def analyze(self, finding: SecurityFinding) -> FindingAnalysis:
        return FindingAnalysis(
            finding_id=finding.id,
            root_cause="Outdated dependency version",
            recommended_action=RemediationType.VERSION_UPGRADE,
            target_version="2.16.0",
            confidence=Confidence.HIGH,
        )


def test_existing_analyzer_implements_ai_provider_contract():
    analyzer = FindingAnalyzer()

    assert isinstance(analyzer, AIAnalysisProvider)


def test_fake_provider_implements_ai_provider_contract():
    provider = FakeAIProvider()

    assert isinstance(provider, AIAnalysisProvider)


def test_existing_analyzer_returns_valid_analysis():
    finding = create_finding()
    analyzer = FindingAnalyzer()

    result = analyzer.analyze(finding)

    assert isinstance(result, FindingAnalysis)
    assert result.finding_id == finding.id
    assert result.recommended_action == RemediationType.VERSION_UPGRADE
    assert result.target_version == "2.16.0"


def test_existing_analyzer_handles_missing_fixed_versions():
    finding = create_finding(fixed_versions=[])
    analyzer = FindingAnalyzer()

    result = analyzer.analyze(finding)

    assert result.recommended_action == (
        RemediationType.NO_AUTOMATIC_REMEDIATION
    )
    assert result.target_version is None
