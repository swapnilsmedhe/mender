from security_agent.application.gradle_dependency_report import (
    GradleDependencyEdge,
    GradleDependencyGraph,
    GradleDependencyReport,
)


TARGET = "com.fasterxml.jackson.core:jackson-databind"
TARGET_VERSION = f"{TARGET}:2.13.4"


def create_edge(
    *,
    project=":bom-consumer",
    source="com.fasterxml.jackson:jackson-bom:2.13.4",
    selected=TARGET_VERSION,
    requested=TARGET_VERSION,
    constraint=True,
    status="RESOLVED",
):
    return GradleDependencyEdge(
        project_path=project,
        configuration="runtimeClasspath",
        from_component=source,
        requested=requested,
        selected=selected,
        is_constraint=constraint,
        status=status,
    )


def test_finds_constraint_targeting_vulnerable_dependency():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(create_edge(),),
    )

    graph = GradleDependencyGraph(report)

    constraints = graph.find_constraints(
        ":bom-consumer",
        TARGET,
    )

    assert len(constraints) == 1
    assert constraints[0].from_component == ("com.fasterxml.jackson:jackson-bom:2.13.4")
    assert constraints[0].selected == TARGET_VERSION
    assert constraints[0].is_constraint is True


def test_does_not_include_constraints_from_another_project():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(create_edge(project=":another-module"),),
    )

    graph = GradleDependencyGraph(report)

    assert (
        graph.find_constraints(
            ":bom-consumer",
            TARGET,
        )
        == ()
    )


def test_does_not_include_unrelated_constraint_targets():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                selected="com.fasterxml.jackson.core:jackson-core:2.13.4",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert (
        graph.find_constraints(
            ":bom-consumer",
            TARGET,
        )
        == ()
    )


def test_does_not_include_non_constraint_dependency_edges():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(create_edge(constraint=False),),
    )

    graph = GradleDependencyGraph(report)

    assert (
        graph.find_constraints(
            ":bom-consumer",
            TARGET,
        )
        == ()
    )


def test_does_not_include_unresolved_constraints():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                selected=None,
                status="UNRESOLVED",
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert (
        graph.find_constraints(
            ":bom-consumer",
            TARGET,
        )
        == ()
    )


def test_constraint_does_not_become_an_ordinary_dependency_path():
    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_edge(
                source="project :bom-consumer",
                selected="com.fasterxml.jackson:jackson-bom:2.13.4",
                constraint=False,
            ),
            create_edge(
                source="com.fasterxml.jackson:jackson-bom:2.13.4",
                constraint=True,
            ),
        ),
    )

    graph = GradleDependencyGraph(report)

    assert (
        graph.find_paths(
            ":bom-consumer",
            TARGET,
        )
        == ()
    )

    assert len(graph.find_constraints(":bom-consumer", TARGET)) == 1
