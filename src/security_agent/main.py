from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.orchestrator import (
    SecurityRemediationOrchestrator,
)
from security_agent.application.planner import RemediationPlanner
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


def main() -> None:
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

    orchestrator = SecurityRemediationOrchestrator(
        analyzer=FindingAnalyzer(),
        planner=RemediationPlanner(),
    )

    plan = orchestrator.run(finding)

    print("Security Remediation Agent")
    print("=" * 32)

    print("\\nFinding")
    print(f"  Scanner: {finding.scanner.value}")
    print(f"  Severity: {finding.severity.value}")
    print(f"  CVE: {finding.cve}")
    print(f"  Component: {finding.component}")
    print(f"  Current version: {finding.current_version}")
    print(f"  Repository: {finding.repository}")

    print("\\nAnalysis result")
    print(f"  Action: {plan.remediation_type.value}")
    print(f"  Reason: {plan.reason}")
    print(f"  Confidence: {plan.confidence.value}")

    print("\\nRemediation plan")

    if plan.changes:
        for change in plan.changes:
            print(f"  File: {change.file}")
            print(f"  Dependency: {change.dependency}")
            print(
                f"  Version: {change.current_version}"
                f" -> {change.target_version}"
            )
    else:
        print("  No automatic remediation proposed.")

    if plan.validation_steps:
        print("\\nProposed validation steps")
        for step in plan.validation_steps:
            print(f"  - {step}")

    print("\\nExecution status")
    print("  Plan generated; no files were modified.")


if __name__ == "__main__":
    main()