import pytest

from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.planner import RemediationPlanner
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


def make_finding() -> SecurityFinding:
    return SecurityFinding(
        id="BD-12345",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2026-12345",
        component="jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="example-service",
        file="gradle/libs.versions.toml",
    )


def test_creates_version_upgrade_plan():
    finding = make_finding()
    analysis = FindingAnalyzer().analyze(finding)

    plan = RemediationPlanner().create_plan(finding, analysis)

    assert plan.finding_id == finding.id
    assert plan.remediation_type == RemediationType.VERSION_UPGRADE
    assert len(plan.changes) == 1

    change = plan.changes[0]
    assert change.file == "gradle/libs.versions.toml"
    assert change.dependency == "jackson-databind"
    assert change.current_version == "2.15.2"
    assert change.target_version == "2.17.3"

    assert "./gradlew test" in plan.validation_steps
    assert "./gradlew build" in plan.validation_steps


def test_rejects_analysis_for_different_finding():
    finding = make_finding()
    analysis = FindingAnalysis(
        finding_id="BD-OTHER",
        root_cause="A fix is available.",
        recommended_action=RemediationType.VERSION_UPGRADE,
        target_version="2.17.3",
        confidence=Confidence.HIGH,
    )

    with pytest.raises(ValueError, match="IDs must match"):
        RemediationPlanner().create_plan(finding, analysis)


def test_rejects_target_version_not_reported_as_fixed():
    finding = make_finding()
    analysis = FindingAnalysis(
        finding_id=finding.id,
        root_cause="Upgrade the dependency.",
        recommended_action=RemediationType.VERSION_UPGRADE,
        target_version="9.9.9",
        confidence=Confidence.HIGH,
    )

    with pytest.raises(ValueError, match="fixed version"):
        RemediationPlanner().create_plan(finding, analysis)