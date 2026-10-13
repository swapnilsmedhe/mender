from security_agent.application.analyzer import FindingAnalyzer
from security_agent.domain.analysis import RemediationType
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


def make_finding(fixed_versions: list[str]) -> SecurityFinding:
    return SecurityFinding(
        id="BD-12345",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2026-12345",
        component="jackson-databind",
        current_version="2.15.2",
        fixed_versions=fixed_versions,
        repository="example-service",
        file="gradle/libs.versions.toml",
    )


def test_recommends_upgrade_when_fixed_version_exists():
    analysis = FindingAnalyzer().analyze(
        make_finding(["2.17.3"])
    )

    assert analysis.finding_id == "BD-12345"
    assert analysis.recommended_action == RemediationType.VERSION_UPGRADE
    assert analysis.target_version == "2.17.3"


def test_does_not_recommend_upgrade_without_fixed_version():
    analysis = FindingAnalyzer().analyze(make_finding([]))

    assert (
        analysis.recommended_action
        == RemediationType.NO_AUTOMATIC_REMEDIATION
    )
    assert analysis.target_version is None