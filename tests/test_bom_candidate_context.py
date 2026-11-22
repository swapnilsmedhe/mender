import json
from dataclasses import dataclass

from security_agent.application.constraint_aware_context_builder import (
    ConstraintAwareAIRecommendationContextBuilder,
)
from security_agent.application.gradle_bom_candidate_inspector import (
    GradleBomCandidateEvidence,
)
from security_agent.domain.finding import Scanner, SecurityFinding, Severity
from security_agent.infrastructure.ai.constraint_aware_copilot_provider import (
    ConstraintAwareCopilotRecommendationProvider,
)


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
    bom_candidate_evidence: tuple = ()


def test_candidate_evidence_reaches_copilot_context_and_prompt():
    finding = SecurityFinding(
        id="f1", scanner=Scanner.BLACK_DUCK, severity=Severity.HIGH,
        cve="CVE-2022-42003",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.13.4", fixed_versions=["2.13.4.2"],
        repository="repo", file="build.gradle.kts",
    )
    evidence = GradleBomCandidateEvidence(
        module_path=":service", configuration="runtimeClasspath",
        bom_coordinate="com.fasterxml.jackson:jackson-bom",
        candidate_selector="2.13.+", status="RESOLVED",
        selected_bom_version="2.13.4.20221012",
        target_component="com.fasterxml.jackson.core:jackson-databind",
        target_selected_version="2.13.4.2",
        related_module_versions=(
            "com.fasterxml.jackson.core:jackson-databind:2.13.4.2",
        ),
        scanner_fixed_versions=("2.13.4.2",),
    )
    context = ConstraintAwareAIRecommendationContextBuilder().build(
        finding, Inspection(finding_id=finding.id, bom_candidate_evidence=(evidence,))
    )
    fact = next(item for item in context.facts if item.key == "bom_candidate_1")
    payload = json.loads(fact.value)
    assert payload["selected_bom_version"] == "2.13.4.20221012"
    assert payload["target_selected_version"] == "2.13.4.2"
    assert payload["exact_scanner_fixed_match"] is True
    assert payload["experiment"] == "TEMPORARY_PLATFORM_ADDED_TO_CONFIGURATION"

    prompt = ConstraintAwareCopilotRecommendationProvider._build_prompt(
        finding, context
    )
    assert "DYNAMIC GRADLE BOM CANDIDATE INVESTIGATION" in prompt
    assert "exact_scanner_fixed_match" in prompt
    assert "do not prove that changing one existing source" in prompt
