import base64
from types import SimpleNamespace

from security_agent.application.gradle_bom_candidate_inspector import (
    GradleBomCandidateCollector,
    GradleBomCandidateEvidence,
    GradleBomCandidateInspector,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyConstraint,
    DependencyRelationship,
)


def enc(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def output_record():
    values = (
        ":service", "runtimeClasspath", "2.13.+",
        "com.fasterxml.jackson:jackson-bom", "RESOLVED",
        "2.13.4.20221012",
        "com.fasterxml.jackson.core:jackson-databind", "2.13.4.2",
        '["com.fasterxml.jackson.core:jackson-databind:2.13.4.2"]', "",
    )
    return "MENDER_BOM_CANDIDATE\t" + "\t".join(enc(item) for item in values)


def test_parses_candidate_resolution():
    result = GradleBomCandidateCollector.parse_output(output_record())[0]
    assert result.status == "RESOLVED"
    assert result.selected_bom_version == "2.13.4.20221012"
    assert result.target_selected_version == "2.13.4.2"
    assert result.related_module_versions == (
        "com.fasterxml.jackson.core:jackson-databind:2.13.4.2",
    )


def test_ignores_malformed_records():
    assert GradleBomCandidateCollector.parse_output("MENDER_BOM_CANDIDATE\tbad") == ()


def test_exact_fixed_match_requires_exact_scanner_version():
    evidence = GradleBomCandidateEvidence(
        module_path=":service", configuration="runtimeClasspath",
        bom_coordinate="com.fasterxml.jackson:jackson-bom",
        candidate_selector="2.13.+", status="RESOLVED",
        target_selected_version="2.13.4.2",
        scanner_fixed_versions=("2.13.4.2",),
    )
    assert evidence.exact_scanner_fixed_match is True


def test_newer_non_exact_version_is_not_claimed_as_scanner_fixed():
    evidence = GradleBomCandidateEvidence(
        module_path=":service", configuration="runtimeClasspath",
        bom_coordinate="com.fasterxml.jackson:jackson-bom",
        candidate_selector="2.+", status="RESOLVED",
        target_selected_version="2.15.0",
        scanner_fixed_versions=("2.13.4.2",),
    )
    assert evidence.exact_scanner_fixed_match is False


def test_candidate_selectors_are_bounded_to_current_major_and_minor():
    assert GradleBomCandidateInspector._candidate_selectors("2.13.4") == (
        "2.13.+", "2.+",
    )
    assert GradleBomCandidateInspector._candidate_selectors("2.x") == ()


def test_builds_module_scoped_requests_from_constraint_provenance():
    finding = SimpleNamespace(
        component="com.fasterxml.jackson.core:jackson-databind",
        fixed_versions=["2.13.4.2"],
    )
    constraint = DependencyConstraint(
        module_path=":service", manifest_file="service/build.gradle.kts",
        source_component="com.fasterxml.jackson:jackson-bom:2.13.4",
        requested="com.fasterxml.jackson.core:jackson-databind:2.13.4",
        selected="com.fasterxml.jackson.core:jackson-databind:2.13.4",
        source_relationship=DependencyRelationship.TRANSITIVE,
    )
    inspection = SimpleNamespace(
        configuration="runtimeClasspath",
        matches=(SimpleNamespace(project_path=":app"),),
        transitive_matches=(),
        constraints=(constraint,),
        source_declarations=(),
    )
    requests = GradleBomCandidateInspector._build_requests(finding, inspection)
    assert len(requests) == 4
    assert {item.module_path for item in requests} == {":app", ":service"}
    assert {item.candidate_selector for item in requests} == {"2.13.+", "2.+"}


def test_init_script_temporarily_adds_platform_to_configuration():
    script = GradleBomCandidateCollector._create_init_script()
    assert "project.dependencies.platform(notation)" in script
    assert "configuration.dependencies.add(platform)" in script
    assert "configuration.incoming.resolutionResult" in script
    assert "MENDER_BOM_CANDIDATE" in script
