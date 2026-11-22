from security_agent.application.ai_recommendation_context_builder import (
    AIRecommendationContextBuilder,
)
from security_agent.application.gradle_version_source_resolver import (
    VersionSourceEvidence,
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
        current_version="2.13.4",
        fixed_versions=["2.13.4.2"],
        repository="/repo",
        file="build.gradle.kts",
    )


def create_version_source():
    return VersionSourceEvidence(
        dependency="com.fasterxml.jackson.core:jackson-databind",
        declaration=(
            'implementation("com.fasterxml.jackson.core:'
            'jackson-databind:$jacksonVersion")'
        ),
        source_type="GRADLE_PROJECT_PROPERTY",
        source_file=None,
        property_name="jacksonVersion",
        value=None,
        resolved=False,
        lookup_scope="CURRENT_PROJECT",
        candidate_source_file="gradle.properties",
        candidate_value="2.13.4",
    )


def create_inspection(finding):
    match = ModuleMatch(
        project_path=":service",
        build_file="service/build.gradle.kts",
        command_output="dependency output",
        resolved_version="2.13.4",
        dependency_paths=(("com.fasterxml.jackson.core:jackson-databind:2.13.4",),),
        version_source=create_version_source(),
    )

    return RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        matches=(match,),
    )


def test_context_builder_carries_property_candidate_evidence():
    finding = create_finding()
    inspection = create_inspection(finding)

    context = AIRecommendationContextBuilder().build(
        finding,
        inspection,
    )

    assert len(context.locations) == 1

    location = context.locations[0]

    assert location.version_source_type == "GRADLE_PROJECT_PROPERTY"
    assert location.version_property_name == "jacksonVersion"
    assert location.version_candidate_source_file == "gradle.properties"
    assert location.version_candidate_value == "2.13.4"

    # Candidate evidence must not be promoted to a verified value.
    assert location.declared_version is None
    assert location.version_source_resolved is False


def test_copilot_prompt_includes_property_candidate_evidence():
    finding = create_finding()
    inspection = create_inspection(finding)

    context = AIRecommendationContextBuilder().build(
        finding,
        inspection,
    )

    prompt = CopilotRecommendationProvider._build_prompt(
        finding,
        context,
    )

    assert '"candidate_source_file": "gradle.properties"' in prompt
    assert '"candidate_value": "2.13.4"' in prompt
    assert "It is not proof of Gradle's effective property value" in prompt
    assert (
        "Do not claim that a candidate value is the resolved dependency version"
        in prompt
    )
