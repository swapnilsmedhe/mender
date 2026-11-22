
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



from security_agent.application.gradle_dependency_report import (
    GradleDependencyEdge,
    GradleDependencyGraph,
    GradleDependencyReport,
)


def create_edge(
    project: str,
    source: str,
    selected: str,
    *,
    constraint: bool = False,
    status: str = "RESOLVED",
) -> GradleDependencyEdge:
    return GradleDependencyEdge(
        project_path=project,
        configuration="runtimeClasspath",
        from_component=source,
        requested=selected,
        selected=selected if status == "RESOLVED" else None,
        is_constraint=constraint,
        status=status,
    )


def test_finds_direct_dependency_path():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":service",
                "project :service",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert graph.find_paths(
        ":service",
        "com.fasterxml.jackson.core:jackson-databind",
    ) == (
        ("com.fasterxml.jackson.core:jackson-databind:2.13.4",),
    )


def test_finds_transitive_dependency_path():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":integration",
                "project :integration",
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            ),
            create_edge(
                ":integration",
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert graph.find_paths(
        ":integration",
        "com.fasterxml.jackson.core:jackson-databind",
    ) == (
        (
            "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        ),
    )


def test_finds_multiple_paths_to_same_dependency():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":app",
                "project :app",
                "project :service",
            ),
            create_edge(
                ":app",
                "project :app",
                "project :integration",
            ),
            create_edge(
                ":app",
                "project :service",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
            create_edge(
                ":app",
                "project :integration",
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            ),
            create_edge(
                ":app",
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    paths = graph.find_paths(
        ":app",
        "com.fasterxml.jackson.core:jackson-databind",
    )

    assert paths == (
        (
            "project :service",
            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        ),
        (
            "project :integration",
            "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        ),
    )


def test_ignores_constraint_edges_when_finding_paths():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":bom-consumer",
                "project :bom-consumer",
                "com.fasterxml.jackson:jackson-bom:2.13.4",
            ),
            create_edge(
                ":bom-consumer",
                "com.fasterxml.jackson:jackson-bom:2.13.4",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
                constraint=True,
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert graph.find_paths(
        ":bom-consumer",
        "com.fasterxml.jackson.core:jackson-databind",
    ) == ()


def test_ignores_unresolved_edges():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":service",
                "project :service",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
                status="UNRESOLVED",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert graph.find_paths(
        ":service",
        "com.fasterxml.jackson.core:jackson-databind",
    ) == ()


def test_does_not_mix_edges_from_different_projects():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":service",
                "project :service",
                "com.example:library:1.0",
            ),
            create_edge(
                ":other",
                "com.example:library:1.0",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert graph.find_paths(
        ":service",
        "com.fasterxml.jackson.core:jackson-databind",
    ) == ()


def test_avoids_cycles():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                ":app",
                "project :app",
                "com.example:a:1.0",
            ),
            create_edge(
                ":app",
                "com.example:a:1.0",
                "com.example:b:1.0",
            ),
            create_edge(
                ":app",
                "com.example:b:1.0",
                "com.example:a:1.0",
            ),
            create_edge(
                ":app",
                "com.example:b:1.0",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert graph.find_paths(
        ":app",
        "com.fasterxml.jackson.core:jackson-databind",
    ) == (
        (
            "com.example:a:1.0",
            "com.example:b:1.0",
            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        ),
    )


def test_respects_maximum_path_count():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(":app", "project :app", "com.example:a:1.0"),
            create_edge(":app", "project :app", "com.example:b:1.0"),
            create_edge(
                ":app",
                "com.example:a:1.0",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
            create_edge(
                ":app",
                "com.example:b:1.0",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    paths = graph.find_paths(
        ":app",
        "com.fasterxml.jackson.core:jackson-databind",
        max_paths=1,
    )

    assert len(paths) == 1
