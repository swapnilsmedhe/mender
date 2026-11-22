
from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
    DependencyConstraint,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)
from security_agent.infrastructure.ai.constraint_aware_copilot_provider import (
    ConstraintAwareCopilotRecommendationProvider,
)


def test_prompt_includes_relevant_gradle_constraint_evidence():
    finding = SecurityFinding(
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

    constraint = DependencyConstraint(
        module_path=":bom-consumer",
        manifest_file="bom-consumer/build.gradle.kts",
        source_component="com.fasterxml.jackson:jackson-bom:2.15.2",
        requested="com.fasterxml.jackson.core:jackson-databind:2.15.2",
        selected="com.fasterxml.jackson.core:jackson-databind:2.15.2",
    )

    context = AIRecommendationContext(
        finding_id=finding.id,
        dependency_name=finding.component,
        resolved_version=finding.current_version,
        constraints=(constraint,),
    )

    prompt = ConstraintAwareCopilotRecommendationProvider._build_prompt(
        finding,
        context,
    )

    assert "ADDITIONAL FINDING-SPECIFIC GRADLE CONSTRAINT EVIDENCE" in prompt
    assert "jackson-bom" in prompt
    assert ":bom-consumer" in prompt
    assert "selected" in prompt
    assert "do not automatically assume it is a BOM" in prompt
