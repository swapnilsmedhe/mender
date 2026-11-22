import pytest

from security_agent.application.gradle_constraint_collector import (
    GradleConstraintCollector,
)
from security_agent.application.gradle_dependency_report import (
    GradleDependencyEdge,
    GradleDependencyGraph,
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


@pytest.fixture
def finding():
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


def create_edge(
    *,
    project=":bom-consumer",
    source="com.fasterxml.jackson:jackson-bom:2.13.4",
    requested="com.fasterxml.jackson.core:jackson-databind:2.15.2",
    selected="com.fasterxml.jackson.core:jackson-databind:2.15.2",
    is_constraint=True,
    status="RESOLVED",
):
    return GradleDependencyEdge(
        project_path=project,
        configuration="runtimeClasspath",
        from_component=source,
        requested=requested,
        selected=selected,
        is_constraint=is_constraint,
        status=status,
    )


def create_inspection(*, modules=(":bom-consumer",), finding_id="finding-1"):
    matches = tuple(
        ModuleMatch(
            project_path=module,
            build_file=f"{module.strip(':')}/build.gradle.kts",
            command_output="dependency path",
            resolved_version="2.15.2",
            dependency_paths=(("com.fasterxml.jackson.core:jackson-databind:2.15.2",),),
        )
        for module in modules
    )

    return RepositoryInspection(
        finding_id=finding_id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        matches=matches,
    )


def create_graph(*edges):
    return GradleDependencyGraph(
        GradleDependencyReport(
            configuration="runtimeClasspath",
            edges=tuple(edges),
        )
    )


def test_collects_constraint_for_affected_module(finding):
    graph = create_graph(create_edge())
    inspection = create_inspection()

    constraints = GradleConstraintCollector().collect(
        finding,
        inspection,
        graph,
        {":bom-consumer": "bom-consumer/build.gradle.kts"},
    )

    assert len(constraints) == 1
    assert constraints[0].module_path == ":bom-consumer"
    assert constraints[0].source_component == (
        "com.fasterxml.jackson:jackson-bom:2.13.4"
    )
    assert constraints[0].selected.endswith(":2.15.2")


def test_ignores_constraint_from_unaffected_module(finding):
    graph = create_graph(
        create_edge(project=":unrelated-module"),
    )
    inspection = create_inspection()

    constraints = GradleConstraintCollector().collect(
        finding,
        inspection,
        graph,
        {":unrelated-module": "unrelated/build.gradle.kts"},
    )

    assert constraints == ()


def test_ignores_constraint_selecting_different_version(finding):
    graph = create_graph(
        create_edge(
            selected="com.fasterxml.jackson.core:jackson-databind:2.17.3",
        ),
    )

    constraints = GradleConstraintCollector().collect(
        finding,
        create_inspection(),
        graph,
        {":bom-consumer": "bom-consumer/build.gradle.kts"},
    )

    assert constraints == ()


def test_ignores_non_constraint_edges(finding):
    graph = create_graph(create_edge(is_constraint=False))

    constraints = GradleConstraintCollector().collect(
        finding,
        create_inspection(),
        graph,
        {":bom-consumer": "bom-consumer/build.gradle.kts"},
    )

    assert constraints == ()


def test_ignores_unresolved_constraints(finding):
    graph = create_graph(
        create_edge(
            selected=None,
            status="UNRESOLVED",
        ),
    )

    constraints = GradleConstraintCollector().collect(
        finding,
        create_inspection(),
        graph,
        {":bom-consumer": "bom-consumer/build.gradle.kts"},
    )

    assert constraints == ()


def test_deduplicates_identical_constraints(finding):
    edge = create_edge()
    graph = create_graph(edge, edge)

    constraints = GradleConstraintCollector().collect(
        finding,
        create_inspection(),
        graph,
        {":bom-consumer": "bom-consumer/build.gradle.kts"},
    )

    assert len(constraints) == 1


def test_ignores_affected_module_without_manifest_path(finding):
    graph = create_graph(create_edge())

    constraints = GradleConstraintCollector().collect(
        finding,
        create_inspection(),
        graph,
        {},
    )

    assert constraints == ()


def test_rejects_mismatched_finding_id(finding):
    with pytest.raises(ValueError, match="IDs do not match"):
        GradleConstraintCollector().collect(
            finding,
            create_inspection(finding_id="another-finding"),
            create_graph(create_edge()),
            {":bom-consumer": "bom-consumer/build.gradle.kts"},
        )
