import base64

from security_agent.application.gradle_constraint_collector import (
    GradleConstraintCollector,
)
from security_agent.application.gradle_dependency_report import (
    GradleDependencyEdge,
    GradleDependencyGraph,
    GradleDependencyReport,
    GradleDependencyReportCollector,
)
from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyRelationship,
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
        cve="CVE-2022-42003",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.13.4",
        fixed_versions=["2.13.4.2"],
        repository="/repo",
        file="build.gradle.kts",
    )


def create_edge(
    project,
    source,
    requested,
    selected,
    *,
    constraint=False,
    selection_reason="",
):
    return GradleDependencyEdge(
        project_path=project,
        configuration="runtimeClasspath",
        from_component=source,
        requested=requested,
        selected=selected,
        is_constraint=constraint,
        status="RESOLVED",
        selection_reason=selection_reason,
    )


def create_inspection(module):
    return RepositoryInspection(
        finding_id="finding-1",
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        matches=(
            ModuleMatch(
                project_path=module,
                build_file=f"{module.strip(':')}/build.gradle.kts",
                command_output="",
                resolved_version="2.13.4",
                dependency_paths=(
                    ("com.fasterxml.jackson.core:jackson-databind:2.13.4",),
                ),
            ),
        ),
    )


def test_identifies_transitive_bom_provenance():
    finding = create_finding()

    project = "project :direct-consumer"
    databind = "com.fasterxml.jackson.core:jackson-databind:2.13.4"
    annotations = "com.fasterxml.jackson.core:jackson-annotations:2.13.4"
    bom = "com.fasterxml.jackson:jackson-bom:2.13.4"

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":direct-consumer",
                project,
                databind,
                databind,
            ),
            create_edge(
                ":direct-consumer",
                databind,
                annotations,
                annotations,
            ),
            create_edge(
                ":direct-consumer",
                annotations,
                bom,
                bom,
            ),
            create_edge(
                ":direct-consumer",
                bom,
                databind,
                databind,
                constraint=True,
                selection_reason="By constraint",
            ),
        ),
    )

    inspection = create_inspection(":direct-consumer")
    graph = GradleDependencyGraph(report)

    constraints = GradleConstraintCollector().collect(
        finding,
        inspection,
        graph,
        {
            ":direct-consumer": "direct-consumer/build.gradle.kts",
        },
    )

    assert len(constraints) == 1

    constraint = constraints[0]

    assert constraint.source_component == bom
    assert constraint.source_relationship == DependencyRelationship.TRANSITIVE
    assert constraint.provenance_path == (
        databind,
        annotations,
        bom,
    )
    assert constraint.selection_reason == "By constraint"

    # The manifest belongs to the affected module. It is not
    # asserted to be the source declaration file for the BOM.
    assert constraint.manifest_file == ("direct-consumer/build.gradle.kts")


def test_identifies_direct_bom_provenance():
    finding = create_finding()

    project = "project :bom-consumer"
    bom = "com.fasterxml.jackson:jackson-bom:2.13.4"
    databind = "com.fasterxml.jackson.core:jackson-databind:2.13.4"

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":bom-consumer",
                project,
                bom,
                bom,
            ),
            create_edge(
                ":bom-consumer",
                bom,
                databind,
                databind,
                constraint=True,
                selection_reason="By constraint",
            ),
        ),
    )

    constraints = GradleConstraintCollector().collect(
        finding,
        create_inspection(":bom-consumer"),
        GradleDependencyGraph(report),
        {
            ":bom-consumer": "bom-consumer/build.gradle.kts",
        },
    )

    assert len(constraints) == 1

    constraint = constraints[0]

    assert constraint.source_relationship == DependencyRelationship.DIRECT
    assert constraint.provenance_path == (bom,)
    assert constraint.selection_reason == "By constraint"


def test_constraint_without_provenance_is_unknown():
    finding = create_finding()

    bom = "com.fasterxml.jackson:jackson-bom:2.13.4"
    databind = "com.fasterxml.jackson.core:jackson-databind:2.13.4"

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":bom-consumer",
                bom,
                databind,
                databind,
                constraint=True,
            ),
        ),
    )

    constraints = GradleConstraintCollector().collect(
        finding,
        create_inspection(":bom-consumer"),
        GradleDependencyGraph(report),
        {
            ":bom-consumer": "bom-consumer/build.gradle.kts",
        },
    )

    assert len(constraints) == 1
    assert constraints[0].source_relationship == DependencyRelationship.UNKNOWN
    assert constraints[0].provenance_path == ()


def test_parser_reads_selection_reason():
    encode = lambda value: base64.b64encode(value.encode("utf-8")).decode("ascii")

    values = (
        ":bom-consumer",
        "runtimeClasspath",
        "com.fasterxml.jackson:jackson-bom:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "true",
        "RESOLVED",
        "By constraint",
    )

    output = "SECURITY_AGENT_EDGE\t" + "\t".join(encode(value) for value in values)

    report = GradleDependencyReportCollector.parse_output(
        output,
        "runtimeClasspath",
    )

    assert len(report.edges) == 1
    assert report.edges[0].selection_reason == "By constraint"


def test_parser_supports_legacy_edge_records():
    encode = lambda value: base64.b64encode(value.encode("utf-8")).decode("ascii")

    values = (
        ":service",
        "runtimeClasspath",
        "project :service",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "false",
        "RESOLVED",
    )

    output = "SECURITY_AGENT_EDGE\t" + "\t".join(encode(value) for value in values)

    report = GradleDependencyReportCollector.parse_output(
        output,
        "runtimeClasspath",
    )

    assert len(report.edges) == 1
    assert report.edges[0].selection_reason == ""
