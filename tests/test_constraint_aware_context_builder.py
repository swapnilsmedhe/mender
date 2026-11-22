from security_agent.application.constraint_aware_context_builder import (
    ConstraintAwareAIRecommendationContextBuilder,
)
from security_agent.application.constraint_aware_repository_inspector import (
    ConstraintAwareRepositoryInspection,
)
from security_agent.application.repository_inspector import ModuleMatch
from security_agent.domain.ai_recommendation_context import (
    DependencyConstraint,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
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
        file="build.gradle",
    )


def test_adds_inspection_constraints_to_ai_context():
    finding = create_finding()

    constraint = DependencyConstraint(
        module_path=":bom-consumer",
        manifest_file="bom-consumer/build.gradle.kts",
        source_component="com.fasterxml.jackson:jackson-bom:2.15.2",
        requested="com.fasterxml.jackson.core:jackson-databind:2.15.2",
        selected="com.fasterxml.jackson.core:jackson-databind:2.15.2",
    )

    inspection = ConstraintAwareRepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
        matches=(
            ModuleMatch(
                project_path=":bom-consumer",
                build_file="bom-consumer/build.gradle.kts",
                command_output="",
                resolved_version="2.15.2",
                dependency_paths=(
                    ("com.fasterxml.jackson.core:jackson-databind:2.15.2",),
                ),
            ),
        ),
        constraints=(constraint,),
    )

    context = ConstraintAwareAIRecommendationContextBuilder().build(
        finding,
        inspection,
    )

    assert context.constraints == (constraint,)
    assert context.dependency_name == finding.component
    assert context.resolved_version == finding.current_version


def test_does_not_add_constraints_for_ordinary_inspection():
    finding = create_finding()

    from security_agent.application.repository_inspector import (
        RepositoryInspection,
    )

    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="",
        is_consistent=True,
    )

    context = ConstraintAwareAIRecommendationContextBuilder().build(
        finding,
        inspection,
    )

    assert context.constraints == ()
