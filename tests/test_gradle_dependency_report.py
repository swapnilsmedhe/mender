
import base64

from security_agent.application.gradle_dependency_report import (
    GradleDependencyReportCollector,
)


def encode(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def edge_line(
    project: str,
    configuration: str,
    source: str,
    requested: str,
    selected: str,
    constraint: str,
    status: str,
) -> str:
    values = (
        project,
        configuration,
        source,
        requested,
        selected,
        constraint,
        status,
    )
    return "SECURITY_AGENT_EDGE\t" + "\t".join(
        encode(value) for value in values
    )


def test_parses_resolved_dependency_edge():
    output = edge_line(
        ":service",
        "runtimeClasspath",
        "project :service",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "false",
        "RESOLVED",
    )

    report = GradleDependencyReportCollector.parse_output(
        output,
        "runtimeClasspath",
    )

    assert report.errors == ()
    assert len(report.edges) == 1

    edge = report.edges[0]
    assert edge.project_path == ":service"
    assert edge.from_component == "project :service"
    assert edge.requested.endswith(":2.13.4")
    assert edge.selected.endswith(":2.13.4")
    assert edge.is_constraint is False
    assert edge.status == "RESOLVED"


def test_parses_constraint_edge():
    output = edge_line(
        ":bom-consumer",
        "runtimeClasspath",
        "com.fasterxml.jackson:jackson-bom:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "true",
        "RESOLVED",
    )

    report = GradleDependencyReportCollector.parse_output(
        output,
        "runtimeClasspath",
    )

    assert len(report.edges) == 1
    assert report.edges[0].is_constraint is True


def test_parses_unresolved_dependency():
    output = edge_line(
        ":service",
        "runtimeClasspath",
        "project :service",
        "com.example:missing:1.0",
        "",
        "false",
        "UNRESOLVED",
    )

    report = GradleDependencyReportCollector.parse_output(
        output,
        "runtimeClasspath",
    )

    assert len(report.edges) == 1
    assert report.edges[0].selected is None
    assert report.edges[0].status == "UNRESOLVED"


def test_parses_project_configuration_error():
    values = (
        ":service",
        "runtimeClasspath",
        "IllegalStateException: resolution failed",
    )
    output = "SECURITY_AGENT_REPORT_ERROR\t" + "\t".join(
        encode(value) for value in values
    )

    report = GradleDependencyReportCollector.parse_output(
        output,
        "runtimeClasspath",
    )

    assert report.edges == ()
    assert report.errors == (
        ":service (runtimeClasspath): "
        "IllegalStateException: resolution failed",
    )


def test_ignores_malformed_records():
    report = GradleDependencyReportCollector.parse_output(
        "SECURITY_AGENT_EDGE\tinvalid",
        "runtimeClasspath",
    )

    assert report.edges == ()
    assert report.errors == ()
