from security_agent.application.constraint_aware_repository_inspector import (
    ConstraintAwareRepositoryInspector,
)
from security_agent.application.gradle_dependency_report import (
    GradleDependencyEdge,
    GradleDependencyReport,
)
from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspection,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


def create_finding():
    return SecurityFinding(
        id="finding-1",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2024-0001",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="/repo",
        file="build.gradle",
    )


def create_edge(project_path, source):
    return GradleDependencyEdge(
        project_path=project_path,
        configuration="runtimeClasspath",
        from_component=source,
        requested="com.fasterxml.jackson.core:jackson-databind:2.15.2",
        selected="com.fasterxml.jackson.core:jackson-databind:2.15.2",
        is_constraint=True,
        status="RESOLVED",
    )


class FakeReportCollector:
    def __init__(self, report):
        self.report = report
        self.calls = 0

    def collect(self, configuration):
        self.calls += 1
        return self.report


class FakeInspector:
    def __init__(self, report, inspection):
        self.report_collector = FakeReportCollector(report)
        self.inspection = inspection

    def inspect(self, finding):
        self.report_collector.collect("runtimeClasspath")
        return self.inspection


def test_reuses_the_existing_gradle_report_and_collects_constraints():
    finding = create_finding()

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":bom-consumer",
                "com.fasterxml.jackson:jackson-bom:2.15.2",
            ),
            create_edge(
                ":unrelated",
                "com.fasterxml.jackson:jackson-bom:2.15.2",
            ),
        ),
    )

    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        matches=(
            ModuleMatch(
                project_path=":bom-consumer",
                build_file="bom-consumer/build.gradle.kts",
                command_output="dependency path",
                resolved_version="2.15.2",
                dependency_paths=(
                    ("com.fasterxml.jackson.core:jackson-databind:2.15.2",),
                ),
            ),
        ),
    )

    base_inspector = FakeInspector(report, inspection)
    inspector = ConstraintAwareRepositoryInspector(base_inspector)

    result = inspector.inspect(finding)

    assert base_inspector.report_collector.calls == 1
    assert len(result.constraints) == 1
    assert result.constraints[0].module_path == ":bom-consumer"
    assert result.constraints[0].manifest_file == ("bom-consumer/build.gradle.kts")


def test_returns_empty_constraints_when_no_gradle_report_was_collected():
    finding = create_finding()

    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=False,
        errors=("Gradle report failed",),
    )

    class NoReportInspector:
        report_collector = FakeReportCollector(
            GradleDependencyReport(configuration="runtimeClasspath")
        )

        def inspect(self, finding):
            return inspection

    result = ConstraintAwareRepositoryInspector(NoReportInspector()).inspect(finding)

    assert result.constraints == ()
    assert result.errors == inspection.errors
