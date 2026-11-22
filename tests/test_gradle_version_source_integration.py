from unittest.mock import Mock

from security_agent.application.ai_recommendation_context_builder import (
    AIRecommendationContextBuilder,
)
from security_agent.application.gradle_dependency_report import (
    GradleDependencyEdge,
    GradleDependencyReport,
)
from security_agent.application.module_discovery import GradleModule
from security_agent.application.repository_inspector import (
    RepositoryInspector,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyRelationship,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)
from security_agent.infrastructure.ai.copilot_provider import (
    CopilotRecommendationProvider,
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
        file="build.gradle.kts",
    )


def create_module(project_path=":service"):
    name = project_path.split(":")[-1]

    return GradleModule(
        name=name,
        project_path=project_path,
        directory=name,
        build_file=f"{name}/build.gradle.kts",
        configurations=("runtimeClasspath",),
    )


def create_report_edge(project, source, selected):
    return GradleDependencyEdge(
        project_path=project,
        configuration="runtimeClasspath",
        from_component=source,
        requested=selected,
        selected=selected,
        is_constraint=False,
        status="RESOLVED",
    )


def configure_inspector(inspector, modules, report):
    inspector.discovery.discover = lambda: modules
    inspector.report_collector.collect = lambda configuration: report


def create_inspection(
    finding,
    build_file_content,
    *,
    project_path=":service",
    transitive=False,
):
    tools = Mock()
    tools.read_file.return_value = build_file_content

    module = create_module(project_path)

    vulnerable_dependency = "com.fasterxml.jackson.core:jackson-databind:2.15.2"

    if transitive:
        introducing_dependency = (
            "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4"
        )
        edges = (
            create_report_edge(
                project_path,
                f"project {project_path}",
                introducing_dependency,
            ),
            create_report_edge(
                project_path,
                introducing_dependency,
                vulnerable_dependency,
            ),
        )
    else:
        edges = (
            create_report_edge(
                project_path,
                f"project {project_path}",
                vulnerable_dependency,
            ),
        )

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=edges,
    )

    inspector = RepositoryInspector(tools=tools)
    configure_inspector(inspector, [module], report)

    return inspector.inspect(finding), tools


def test_inspector_attaches_inline_version_source_to_direct_match():
    finding = create_finding()

    build_file = """
dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:2.15.2"
    )
}
"""

    inspection, tools = create_inspection(
        finding,
        build_file,
    )

    assert len(inspection.matches) == 1
    assert inspection.matches[0].version_source is not None

    evidence = inspection.matches[0].version_source

    assert evidence.source_type == "INLINE"
    assert evidence.value == "2.15.2"
    assert evidence.resolved is True
    assert evidence.source_file == "service/build.gradle.kts"
    tools.read_file.assert_called_once_with("service/build.gradle.kts")


def test_inspector_attaches_gradle_property_source_to_direct_match():
    finding = create_finding()

    build_file = """
val jacksonVersion: String by project

dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
    )
}
"""

    inspection, _ = create_inspection(
        finding,
        build_file,
    )

    assert len(inspection.matches) == 1

    evidence = inspection.matches[0].version_source

    assert evidence is not None
    assert evidence.source_type == "GRADLE_PROJECT_PROPERTY"
    assert evidence.property_name == "jacksonVersion"
    assert evidence.lookup_scope == "CURRENT_PROJECT"
    assert evidence.value is None
    assert evidence.resolved is False


def test_inspector_does_not_attach_direct_source_to_transitive_match():
    finding = create_finding()

    build_file = """
dependencies {
    implementation(
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4"
    )
}
"""

    inspection, tools = create_inspection(
        finding,
        build_file,
        transitive=True,
    )

    assert inspection.matches == ()
    assert len(inspection.transitive_matches) == 1
    assert inspection.transitive_matches[0].version_source is None

    # The build file is not read for a transitive-only match.
    tools.read_file.assert_not_called()


def test_context_builder_carries_version_source_evidence():
    finding = create_finding()

    build_file = """
val jacksonVersion: String by project

dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
    )
}
"""

    inspection, _ = create_inspection(
        finding,
        build_file,
    )

    context = AIRecommendationContextBuilder().build(
        finding,
        inspection,
    )

    assert len(context.locations) == 1

    location = context.locations[0]

    assert location.relationship == DependencyRelationship.DIRECT
    assert location.declaration is not None
    assert "jacksonVersion" in location.declaration
    assert location.version_source_type == "GRADLE_PROJECT_PROPERTY"
    assert location.version_property_name == "jacksonVersion"
    assert location.version_lookup_scope == "CURRENT_PROJECT"
    assert location.declared_version is None
    assert location.version_source_resolved is False


def test_context_builder_does_not_attach_source_evidence_to_transitive_match():
    finding = create_finding()

    build_file = """
dependencies {
    implementation(
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4"
    )
}
"""

    inspection, _ = create_inspection(
        finding,
        build_file,
        transitive=True,
    )

    context = AIRecommendationContextBuilder().build(
        finding,
        inspection,
    )

    assert len(context.locations) == 1

    location = context.locations[0]

    assert location.relationship == DependencyRelationship.TRANSITIVE
    assert location.version_source_type is None
    assert location.version_property_name is None
    assert location.version_source_resolved is None


def test_copilot_prompt_contains_version_source_evidence():
    finding = create_finding()

    build_file = """
val jacksonVersion: String by project

dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
    )
}
"""

    inspection, _ = create_inspection(
        finding,
        build_file,
    )

    context = AIRecommendationContextBuilder().build(
        finding,
        inspection,
    )

    prompt = CopilotRecommendationProvider._build_prompt(
        finding,
        context,
    )

    assert '"source_type": "GRADLE_PROJECT_PROPERTY"' in prompt
    assert '"property_name": "jacksonVersion"' in prompt
    assert '"lookup_scope": "CURRENT_PROJECT"' in prompt
    assert '"resolved": false' in prompt
    assert "Do not invent or infer it" in prompt
    assert "Do not assume a BOM controls a dependency" in prompt
