from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


def test_security_finding_can_be_created():
    finding = SecurityFinding(
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

    assert finding.cve == "CVE-2026-12345"
    assert finding.component == "jackson-databind"
    assert finding.current_version == "2.15.2"
    assert "2.17.3" in finding.fixed_versions