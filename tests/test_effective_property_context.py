import json
from dataclasses import dataclass
from security_agent.application.constraint_aware_context_builder import ConstraintAwareAIRecommendationContextBuilder
from security_agent.application.effective_property_inspector import EffectiveSourceDeclaration
from security_agent.domain.ai_recommendation_context import DependencyRelationship
from security_agent.domain.finding import Scanner, SecurityFinding, Severity


@dataclass(frozen=True)
class Inspection:
    finding_id: str
    configuration: str = "runtimeClasspath"
    command_output: str = ""
    is_consistent: bool = True
    matches: tuple = ()
    errors: tuple = ()
    transitive_matches: tuple = ()
    constraints: tuple = ()
    source_declarations: tuple = ()


def test_context_distinguishes_effective_value_from_file_candidate():
    finding = SecurityFinding(
        id="f1", scanner=Scanner.BLACK_DUCK, severity=Severity.HIGH,
        cve="CVE-2024-0001", component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.13.4", fixed_versions=["2.13.4.2"],
        repository="repo", file="build.gradle.kts",
    )
    declaration = EffectiveSourceDeclaration(
        module_path=":service", manifest_file="service/build.gradle.kts",
        dependency=finding.component,
        declaration='implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")',
        declaration_kind="DEPENDENCY", declaration_relationship=DependencyRelationship.DIRECT,
        vulnerable_dependency_relationship=DependencyRelationship.DIRECT,
        source_type="GRADLE_PROJECT_PROPERTY", property_name="jacksonVersion",
        lookup_scope="CURRENT_PROJECT", source_resolved=False,
        candidate_source_file="gradle.properties", candidate_value="2.13.4",
        effective_property_value="2.13.4", effective_property_status="RESOLVED",
    )
    inspection = Inspection(finding_id=finding.id, source_declarations=(declaration,))
    context = ConstraintAwareAIRecommendationContextBuilder().build(finding, inspection)
    fact = next(item for item in context.facts if item.key == "source_declaration_1")
    source = json.loads(fact.value)["version_source"]
    assert source["effective_property_value"] == "2.13.4"
    assert source["effective_property_status"] == "RESOLVED"
    assert source["candidate_value"] == "2.13.4"
    assert source["resolved"] is False
