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


def create_transitive_inspection():
    finding = create_finding()

    match = ModuleMatch(
        project_path=":service",
        build_file="service/build.gradle.kts",
        command_output="dependency path",
        resolved_version=finding.current_version,
        dependency_paths=(
            (
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
                "com.fasterxml.jackson.core:jackson-databind:2.13.4",
            ),
        ),
    )

    return RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        transitive_matches=(match,),
    )


def test_inspector_finds_introducing_dependency_and_bom_declaration():
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
    inspection = create_transitive_inspection()

    result = ConstraintAwareRepositoryInspector(
        FakeInspector(inspection, tools)
    ).inspect(finding)

    assert len(result.source_declarations) == 2

    dependencies = {item.dependency: item for item in result.source_declarations}

    introducing = dependencies["com.fasterxml.jackson.datatype:jackson-datatype-jsr310"]

    assert introducing.relationship.value == "TRANSITIVE"
    assert introducing.dependency_path == (
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
        "com.fasterxml.jackson.core:jackson-databind:2.13.4",
    )
    assert "jackson-datatype-jsr310" in introducing.declaration

    bom = dependencies["com.fasterxml.jackson:jackson-bom"]

    assert bom.declaration_kind == "PLATFORM"
    assert "jackson-bom" in bom.declaration
    assert bom.relationship.value == "UNKNOWN"


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
        platform("com.fasterxml.jackson:jackson-bom:2.13.4")
    )
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
        SimpleNamespace(
            project_path=":app",
            build_file="app/build.gradle.kts",
        ),
        SimpleNamespace(
            project_path=":service",
            build_file="service/build.gradle.kts",
        ),
    )

    result = ConstraintAwareRepositoryInspector(
        FakeInspector(inspection, tools, modules)
    ).inspect(finding)

    assert any(
        item.module_path == ":service"
        and item.dependency == "com.fasterxml.jackson.datatype:jackson-datatype-jsr310"
        for item in result.source_declarations
    )

    assert "service/build.gradle.kts" in tools.reads


def test_context_builder_passes_source_declarations_to_ai_facts():
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
    inspection = create_transitive_inspection()

    enriched_inspection = ConstraintAwareRepositoryInspector(
        FakeInspector(inspection, tools)
    ).inspect(finding)

    context = ConstraintAwareAIRecommendationContextBuilder().build(
        finding,
        enriched_inspection,
    )

    declaration_facts = [
        fact for fact in context.facts if fact.key.startswith("source_declaration_")
    ]

    assert len(declaration_facts) == 2

    payloads = [json.loads(fact.value) for fact in declaration_facts]

    assert {payload["dependency"] for payload in payloads} == {
        "com.fasterxml.jackson:jackson-bom",
        "com.fasterxml.jackson.datatype:jackson-datatype-jsr310",
    }


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
    inspection = create_transitive_inspection()

    enriched_inspection = ConstraintAwareRepositoryInspector(
        FakeInspector(inspection, tools)
    ).inspect(finding)

    context = ConstraintAwareAIRecommendationContextBuilder().build(
        finding,
        enriched_inspection,
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
