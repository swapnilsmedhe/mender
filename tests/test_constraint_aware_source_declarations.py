import json
from types import SimpleNamespace

from security_agent.application.constraint_aware_context_builder import (
    ConstraintAwareAIRecommendationContextBuilder,
)
from security_agent.application.constraint_aware_repository_inspector import (
    ConstraintAwareRepositoryInspector,
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
from security_agent.infrastructure.ai.constraint_aware_copilot_provider import (
    ConstraintAwareCopilotRecommendationProvider,
)


def create_finding():
    return SecurityFinding(
        id="finding-1",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2024-0001",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.13.4",
        fixed_versions=["2.13.4.2"],
        repository="/repo",
        file="build.gradle.kts",
    )


class FakeReportCollector:
    def collect(self, configuration):
        from security_agent.application.gradle_dependency_report import (
            GradleDependencyReport,
        )

        return GradleDependencyReport(configuration=configuration)


class FakeRepositoryTools:
    def __init__(self, files):
        self.files = files
        self.reads = []

    def read_file(self, path):
        self.reads.append(path)
        return self.files[path]


class FakeDiscovery:
    def __init__(self, modules):
        self.modules = modules

    def discover(self):
        return self.modules


class FakeInspector:
    def __init__(self, inspection, tools, modules=()):
        self.inspection = inspection
        self.tools = tools
        self.discovery = FakeDiscovery(modules)
        self.report_collector = FakeReportCollector()

    def inspect(self, finding):
        self.report_collector.collect("runtimeClasspath")
        return self.inspection


def create_transitive_inspection(paths=None):
    finding = create_finding()
    dependency_paths = paths or (
        (
            "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        ),
    )

    match = ModuleMatch(
        project_path=":service",
        build_file="service/build.gradle.kts",
        command_output="dependency path",
        resolved_version=finding.current_version,
        dependency_paths=dependency_paths,
    )

    return RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        transitive_matches=(match,),
    )


def test_direct_declaration_can_introduce_transitive_vulnerable_dependency():
    finding = create_finding()
    build_file = """
dependencies {
    implementation(
        platform("com.fasterxml.jackson:jackson-bom:2.13.4")
    )
    implementation(
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4"
    )
}
"""
    tools = FakeRepositoryTools({"service/build.gradle.kts": build_file})
    result = ConstraintAwareRepositoryInspector(
        FakeInspector(create_transitive_inspection(), tools)
    ).inspect(finding)

    assert len(result.source_declarations) == 2
    declarations = {item.dependency: item for item in result.source_declarations}

    introducing = declarations[
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310"
    ]
    assert introducing.declaration_relationship.value == "DIRECT"
    assert introducing.vulnerable_dependency_relationship.value == "TRANSITIVE"
    assert introducing.dependency_paths == (
        (
            "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        ),
    )
    assert "jackson-datatype-jsr310" in introducing.declaration

    bom = declarations["com.fasterxml.jackson:jackson-bom"]
    assert bom.declaration_kind == "PLATFORM"
    assert bom.declaration_relationship.value == "DIRECT"
    assert bom.vulnerable_dependency_relationship.value == "UNKNOWN"
    assert bom.constraint_provenance == ()


def test_same_declaration_is_deduplicated_and_all_paths_are_retained():
    finding = create_finding()
    first_path = (
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
    )
    second_path = (
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
        "com.fasterxml.jackson.core:jackson-module-parameter-names:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
    )
    build_file = """
dependencies {
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4")
}
"""
    tools = FakeRepositoryTools({"service/build.gradle.kts": build_file})
    result = ConstraintAwareRepositoryInspector(
        FakeInspector(
            create_transitive_inspection((first_path, second_path)),
            tools,
        )
    ).inspect(finding)

    datatype_declarations = [
        item for item in result.source_declarations
        if item.dependency == "com.fasterxml.jackson.datatype:jackson-datatype-jsr310"
    ]
    assert len(datatype_declarations) == 1
    assert datatype_declarations[0].declaration_relationship.value == "DIRECT"
    assert datatype_declarations[0].vulnerable_dependency_relationship.value == "TRANSITIVE"
    assert datatype_declarations[0].dependency_paths == (first_path, second_path)


def test_inspector_follows_project_dependency_to_source_module():
    finding = create_finding()
    app_build_file = """
dependencies {
    implementation(project(":service"))
}
"""
    service_build_file = """
dependencies {
    implementation(
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4"
    )
}
"""
    tools = FakeRepositoryTools(
        {
            "app/build.gradle.kts": app_build_file,
            "service/build.gradle.kts": service_build_file,
        }
    )
    app_match = ModuleMatch(
        project_path=":app",
        build_file="app/build.gradle.kts",
        command_output="project dependency path",
        resolved_version=finding.current_version,
        dependency_paths=(
            (
                "project :service",
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )
    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        transitive_matches=(app_match,),
    )
    modules = (
        SimpleNamespace(project_path=":app", build_file="app/build.gradle.kts"),
        SimpleNamespace(project_path=":service", build_file="service/build.gradle.kts"),
    )

    result = ConstraintAwareRepositoryInspector(
        FakeInspector(inspection, tools, modules)
    ).inspect(finding)

    service_declarations = [
        item for item in result.source_declarations
        if item.module_path == ":service"
        and item.dependency == "com.fasterxml.jackson.datatype:jackson-datatype-jsr310"
    ]
    assert len(service_declarations) == 1
    assert service_declarations[0].declaration_relationship.value == "DIRECT"
    assert service_declarations[0].vulnerable_dependency_relationship.value == "TRANSITIVE"
    assert "service/build.gradle.kts" in tools.reads


def test_context_builder_serializes_relationships_and_paths_separately():
    finding = create_finding()
    build_file = """
dependencies {
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4")
}
"""
    tools = FakeRepositoryTools({"service/build.gradle.kts": build_file})
    inspection = ConstraintAwareRepositoryInspector(
        FakeInspector(create_transitive_inspection(), tools)
    ).inspect(finding)

    context = ConstraintAwareAIRecommendationContextBuilder().build(
        finding,
        inspection,
    )
    facts = [
        fact for fact in context.facts
        if fact.key.startswith("source_declaration_")
    ]
    payloads = [json.loads(fact.value) for fact in facts]
    introducing = next(
        payload for payload in payloads
        if payload["dependency"].endswith("jackson-datatype-jsr310")
    )

    assert introducing["declaration_relationship"] == "DIRECT"
    assert introducing["vulnerable_dependency_relationship"] == "TRANSITIVE"
    assert len(introducing["dependency_paths"]) == 1
    assert "relationship" not in introducing
    assert "dependency_path" not in introducing


def test_copilot_prompt_explains_shared_version_authority():
    finding = create_finding()
    build_file = """
dependencies {
    implementation(
        platform("com.fasterxml.jackson:jackson-bom:2.13.4")
    )
    implementation(
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4"
    )
}
"""
    tools = FakeRepositoryTools({"service/build.gradle.kts": build_file})
    inspection = ConstraintAwareRepositoryInspector(
        FakeInspector(create_transitive_inspection(), tools)
    ).inspect(finding)
    context = ConstraintAwareAIRecommendationContextBuilder().build(
        finding,
        inspection,
    )
    prompt = ConstraintAwareCopilotRecommendationProvider._build_prompt(
        finding,
        context,
    )

    assert "shared version authority" in prompt
    assert "upgrading that BOM once" in prompt
    assert "source_declaration_1" in prompt
    assert "jackson-bom" in prompt
    assert "jackson-datatype-jsr310" in prompt
    assert "declaration_relationship" in prompt
    assert "vulnerable_dependency_relationship" in prompt
    assert "constraint_provenance" in prompt
