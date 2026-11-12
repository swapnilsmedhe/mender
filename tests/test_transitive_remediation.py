
from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.orchestrator import (
    SecurityRemediationOrchestrator,
)
from security_agent.application.planner import RemediationPlanner
from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspection,
)
from security_agent.domain.analysis import RemediationType
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


def make_finding():
    return SecurityFinding(
        id="BD-12345",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2026-12345",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="example-service",
        file="build.gradle",
    )


def make_transitive_match():
    return ModuleMatch(
        project_path=":app",
        build_file="app/build.gradle",
        command_output="Gradle dependencyInsight output",
        resolved_version="2.15.2",
        dependency_paths=(
            (
                "org.springframework.boot:spring-boot-starter-web:3.2.1",
                "org.springframework.boot:spring-boot-starter-json:3.2.1",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
        ),
    )


class FixedInspector:
    def __init__(self, inspection):
        self.inspection = inspection

    def inspect(self, finding):
        return self.inspection


def test_planner_does_not_upgrade_introducing_dependency():
    finding = make_finding()
    analysis = FindingAnalyzer().analyze(finding)

    match = make_transitive_match()

    plan = RemediationPlanner().create_plan(
        finding=finding,
        analysis=analysis,
        is_transitive=True,
        dependency_paths=match.dependency_paths,
    )

    assert (
            plan.remediation_type
            == RemediationType.NO_AUTOMATIC_REMEDIATION
    )

    assert plan.changes == []

    assert "spring-boot-starter-web:3.2.1" in plan.reason
    assert "jackson-databind:2.15.2" in plan.reason
    assert "does not establish a safe target version" in plan.reason


def test_orchestrator_processes_transitive_only_inspection():
    finding = make_finding()
    match = make_transitive_match()

    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output=match.command_output,
        is_consistent=False,
        matches=(),
        errors=(),
        transitive_matches=(match,),
    )

    orchestrator = SecurityRemediationOrchestrator(
        analyzer=FindingAnalyzer(),
        planner=RemediationPlanner(),
        inspector=FixedInspector(inspection),
    )

    plan = orchestrator.run(finding)

    assert (
            plan.remediation_type
            == RemediationType.NO_AUTOMATIC_REMEDIATION
    )

    assert plan.changes == []
    assert "spring-boot-starter-web:3.2.1" in plan.reason
    assert "jackson-databind:2.15.2" in plan.reason


def test_mixed_direct_and_transitive_matches_do_not_create_partial_upgrade():
    finding = make_finding()

    direct_match = ModuleMatch(
        project_path=":direct",
        build_file="direct/build.gradle",
        command_output="Direct dependency match",
    )

    transitive_match = make_transitive_match()

    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="Gradle dependencyInsight output",
        is_consistent=True,
        matches=(direct_match,),
        errors=(),
        transitive_matches=(transitive_match,),
    )

    orchestrator = SecurityRemediationOrchestrator(
        analyzer=FindingAnalyzer(),
        planner=RemediationPlanner(),
        inspector=FixedInspector(inspection),
    )

    plan = orchestrator.run(finding)

    # The direct match alone could be upgraded, but that would leave
    # the transitive occurrence unresolved.
    assert (
            plan.remediation_type
            == RemediationType.NO_AUTOMATIC_REMEDIATION
    )

    assert plan.changes == []
    assert "spring-boot-starter-web:3.2.1" in plan.reason
