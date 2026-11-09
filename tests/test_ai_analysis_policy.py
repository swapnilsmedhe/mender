import pytest

from security_agent.application.ai_analysis_policy import (
    AIAnalysisPolicy,
    AIAnalysisReason,
)
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


def analyze(finding):
    return FindingAnalyzer().analyze(finding)


def test_single_fixed_version_does_not_require_ai():
    finding = create_finding(["2.16.0"])
    analysis = analyze(finding)

    decision = AIAnalysisPolicy().evaluate(finding, analysis)

    assert decision.should_call_ai is False
    assert decision.reason == (
        AIAnalysisReason.DETERMINISTIC_RESULT_AVAILABLE
    )


def test_multiple_fixed_versions_require_ai():
    finding = create_finding(["2.16.0", "2.17.0"])
    analysis = analyze(finding)

    decision = AIAnalysisPolicy().evaluate(finding, analysis)

    assert decision.should_call_ai is True
    assert decision.reason == AIAnalysisReason.MULTIPLE_FIXED_VERSIONS


def test_missing_fixed_versions_require_ai():
    finding = create_finding([])
    analysis = analyze(finding)

    decision = AIAnalysisPolicy().evaluate(finding, analysis)

    assert decision.should_call_ai is True
    assert decision.reason == (
        AIAnalysisReason.NO_FIXED_VERSION_REPORTED
    )


def test_duplicate_fixed_versions_do_not_require_ai():
    finding = create_finding(["2.16.0", "2.16.0"])
    analysis = analyze(finding)

    decision = AIAnalysisPolicy().evaluate(finding, analysis)

    assert decision.should_call_ai is False


def test_inconclusive_analysis_requires_ai():
    finding = create_finding(["2.16.0"])

    analysis = FindingAnalysis(
        finding_id=finding.id,
        root_cause="Unable to determine remediation.",
        recommended_action=RemediationType.NO_AUTOMATIC_REMEDIATION,
        target_version=None,
        confidence=Confidence.LOW,
    )

    decision = AIAnalysisPolicy().evaluate(finding, analysis)

    assert decision.should_call_ai is True
    assert decision.reason == AIAnalysisReason.INCONCLUSIVE_ANALYSIS


def test_invalid_target_version_requires_ai():
    finding = create_finding(["2.16.0"])

    analysis = FindingAnalysis(
        finding_id=finding.id,
        root_cause="Upgrade recommended.",
        recommended_action=RemediationType.VERSION_UPGRADE,
        target_version="2.15.9",
        confidence=Confidence.LOW,
    )

    decision = AIAnalysisPolicy().evaluate(finding, analysis)

    assert decision.should_call_ai is True
    assert decision.reason == AIAnalysisReason.INVALID_TARGET_VERSION


def test_manual_request_forces_ai_analysis():
    finding = create_finding(["2.16.0"])
    analysis = analyze(finding)

    decision = AIAnalysisPolicy().evaluate(
        finding,
        analysis,
        force=True,
    )

    assert decision.should_call_ai is True
    assert decision.reason == AIAnalysisReason.MANUAL_REQUEST


def test_finding_and_analysis_ids_must_match():
    finding = create_finding()

    analysis = FindingAnalysis(
        finding_id="DIFFERENT-FINDING",
        root_cause="Test",
        recommended_action=RemediationType.VERSION_UPGRADE,
        target_version="2.16.0",
        confidence=Confidence.HIGH,
    )

    with pytest.raises(ValueError, match="Finding ID"):
        AIAnalysisPolicy().evaluate(finding, analysis)
