from security_agent.application.constraint_aware_repository_inspector import (
    ConstraintAwareRepositoryInspector,
)
from security_agent.application.gradle_dependency_report import (
    GradleDependencyReport,
)
from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyConstraint,
    DependencyRelationship,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)

BOM = "com.fasterxml.jackson:jackson-bom:2.13.4"
DATABIND = "com.fasterxml.jackson.core:jackson-databind:2.13.4"


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


class FakeReportCollector:
    def collect(self, configuration):
        return GradleDependencyReport(configuration=configuration)


class FakeRepositoryTools:
    def __init__(self, files):
        self.files = files

    def read_file(self, path):
        return self.files[path]


class FakeConstraintCollector:
    def __init__(self, constraints):
        self.constraints = constraints

    def collect(self, **kwargs):
        return self.constraints


class FakeInspector:
    def __init__(self, inspection, tools):
        self.inspection = inspection
        self.tools = tools
        self.report_collector = FakeReportCollector()
        self.discovery = None

    def inspect(self, finding):
        self.report_collector.collect("runtimeClasspath")
        return self.inspection


def create_constraint(
    module_path,
    manifest,
    relationship,
    provenance_path,
):
    return DependencyConstraint(
        module_path=module_path,
        manifest_file=manifest,
        source_component=BOM,
        requested=DATABIND,
        selected=DATABIND,
        provenance_path=provenance_path,
        source_relationship=relationship,
        selection_reason="constraint; requested",
    )


def test_bom_declaration_only_receives_same_module_constraint_provenance():
    finding = create_finding()
    build_file = """
dependencies {
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.13.4"))
    implementation("com.fasterxml.jackson.core:jackson-databind")
}
"""
    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        matches=(
            ModuleMatch(
                project_path=":bom-consumer",
                build_file="bom-consumer/build.gradle.kts",
                command_output="",
                resolved_version="2.13.4",
                dependency_paths=((DATABIND,),),
            ),
        ),
    )
    constraints = (
        create_constraint(
            ":bom-consumer",
            "bom-consumer/build.gradle.kts",
            DependencyRelationship.DIRECT,
            (BOM,),
        ),
        create_constraint(
            ":direct-consumer",
            "direct-consumer/build.gradle.kts",
            DependencyRelationship.TRANSITIVE,
            (
                DATABIND,
                "com.fasterxml.jackson.core:jackson-annotations:2.13.4",
                BOM,
            ),
        ),
        create_constraint(
            ":service",
            "service/build.gradle.kts",
            DependencyRelationship.TRANSITIVE,
            (
                DATABIND,
                "com.fasterxml.jackson.core:jackson-core:2.13.4",
                BOM,
            ),
        ),
    )
    tools = FakeRepositoryTools({"bom-consumer/build.gradle.kts": build_file})
    inspector = ConstraintAwareRepositoryInspector(
        FakeInspector(inspection, tools),
        constraint_collector=FakeConstraintCollector(constraints),
    )

    result = inspector.inspect(finding)
    bom_declarations = [
        item for item in result.source_declarations
        if item.dependency == "com.fasterxml.jackson:jackson-bom"
    ]

    assert len(bom_declarations) == 1
    bom = bom_declarations[0]
    assert bom.module_path == ":bom-consumer"
    assert bom.declaration_relationship == DependencyRelationship.DIRECT
    assert bom.vulnerable_dependency_relationship == DependencyRelationship.UNKNOWN
    assert len(bom.constraint_provenance) == 1
    assert bom.constraint_provenance[0].source_relationship == DependencyRelationship.DIRECT
    assert bom.constraint_provenance[0].provenance_path == (BOM,)
    assert "direct-consumer" not in " ".join(bom.constraint_provenance[0].provenance_path)
