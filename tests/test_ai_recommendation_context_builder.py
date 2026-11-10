
import pytest

from security_agent.application.ai_recommendation_context_builder import (
    AIRecommendationContextBuilder,
)
from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    DependencyRelationship,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


@pytest.fixture
def finding():
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


def create_match(
        project_path=":app",
        build_file="app/build.gradle",
        command_output="dependency output",
):
    return ModuleMatch(
        project_path=project_path,
        build_file=build_file,
        command_output=command_output,
    )


def create_inspection(
        finding_id="finding-1",
        matches=None,
        transitive_matches=None,
        command_output="raw gradle output",
        is_consistent=True,
        errors=None,
):
    return RepositoryInspection(
        finding_id=finding_id,
        configuration="runtimeClasspath",
        command_output=command_output,
        is_consistent=is_consistent,
        matches=matches or [],
        errors=errors or [],
        transitive_matches=transitive_matches or [],
    )


@pytest.fixture
def builder():
    return AIRecommendationContextBuilder()


class TestAIRecommendationContextBuilder:
    def test_builds_context_from_direct_matches(self, builder, finding):
        inspection = create_inspection(
            matches=[
                create_match(
                    project_path=":app",
                    build_file="app/build.gradle",
                )
            ]
        )

        context = builder.build(finding, inspection)

        assert context.finding_id == finding.id
        assert context.dependency_name == finding.component
        assert context.resolved_version == finding.current_version
        assert context.dependency_scope == "runtimeClasspath"
        assert len(context.locations) == 1
        assert context.locations[0].relationship == (
            DependencyRelationship.DIRECT
        )

    def test_builds_context_from_transitive_matches(self, builder, finding):
        inspection = create_inspection(
            transitive_matches=[
                create_match(
                    project_path=":service",
                    build_file="service/build.gradle",
                )
            ]
        )

        context = builder.build(finding, inspection)

        assert len(context.locations) == 1
        assert context.locations[0].relationship == (
            DependencyRelationship.TRANSITIVE
        )

    def test_includes_direct_and_transitive_matches(self, builder, finding):
        inspection = create_inspection(
            matches=[create_match(":app", "app/build.gradle")],
            transitive_matches=[
                create_match(":service", "service/build.gradle")
            ],
        )

        context = builder.build(finding, inspection)

        assert len(context.locations) == 2
        assert context.locations[0].relationship == (
            DependencyRelationship.DIRECT
        )
        assert context.locations[1].relationship == (
            DependencyRelationship.TRANSITIVE
        )

    def test_includes_inspection_summary_facts(self, builder, finding):
        inspection = create_inspection(
            matches=[create_match()],
            transitive_matches=[
                create_match(":service", "service/build.gradle")
            ],
            is_consistent=False,
            errors=["Gradle inspection warning"],
        )

        context = builder.build(finding, inspection)
        facts = {fact.key: fact.value for fact in context.facts}

        assert facts["inspection_consistent"] == "false"
        assert facts["direct_match_count"] == "1"
        assert facts["transitive_match_count"] == "1"
        assert facts["inspection_error_count"] == "1"

    def test_builds_context_when_no_matches_exist(self, builder, finding):
        inspection = create_inspection()

        context = builder.build(finding, inspection)

        assert context.locations == ()
        assert context.finding_id == finding.id

    def test_rejects_mismatched_finding_id(self, builder, finding):
        inspection = create_inspection(finding_id="another-finding")

        with pytest.raises(ValueError, match="IDs do not match"):
            builder.build(finding, inspection)

    def test_does_not_include_raw_command_output(self, builder, finding):
        secret_output = "RAW_GRADLE_OUTPUT_SHOULD_NOT_BE_INCLUDED"

        inspection = create_inspection(
            matches=[create_match(command_output=secret_output)],
            command_output=secret_output,
        )

        context = builder.build(finding, inspection)

        assert secret_output not in repr(context)

    def test_deduplicates_identical_locations(self, builder, finding):
        match = create_match()

        inspection = create_inspection(matches=[match, match])

        context = builder.build(finding, inspection)

        assert len(context.locations) == 1

    def test_preserves_different_relationships(self, builder, finding):
        match = create_match()

        inspection = create_inspection(
            matches=[match],
            transitive_matches=[match],
        )

        context = builder.build(finding, inspection)

        assert len(context.locations) == 2
        assert context.locations[0].relationship == (
            DependencyRelationship.DIRECT
        )
        assert context.locations[1].relationship == (
            DependencyRelationship.TRANSITIVE
        )

    def test_limits_number_of_locations(self, builder, finding):
        matches = [
            create_match(
                project_path=f":module{index}",
                build_file=f"module{index}/build.gradle",
            )
            for index in range(25)
        ]

        inspection = create_inspection(matches=matches)

        context = builder.build(finding, inspection)

        assert len(context.locations) == 20

        facts = {fact.key: fact.value for fact in context.facts}
        assert facts["locations_omitted"] == "5"

    def test_respects_context_character_limit(self, builder, finding):
        matches = [
            create_match(
                project_path=f":{index}-{'m' * 480}",
                build_file=f"{index}-{'b' * 480}.gradle",
            )
            for index in range(20)
        ]

        inspection = create_inspection(matches=matches)

        context = builder.build(finding, inspection)

        assert (
                context.estimated_characters
                <= context.MAX_CONTEXT_CHARACTERS
        )

        facts = {fact.key: fact.value for fact in context.facts}
        assert "locations_omitted" in facts


    def test_skips_invalid_location_and_keeps_smaller_locations(
            self,
            builder,
            finding,
    ):
        matches = [
            create_match(
                project_path=f":{'m' * 12000}",
                build_file="large/build.gradle",
            ),
            create_match(
                project_path=":small",
                build_file="small/build.gradle",
            ),
        ]

        inspection = create_inspection(matches=matches)

        context = builder.build(finding, inspection)

        assert len(context.locations) == 1
        assert context.locations[0].module_path == ":small"

        facts = {fact.key: fact.value for fact in context.facts}
        assert facts["locations_omitted"] == "1"


    def test_skips_oversized_location_and_keeps_smaller_locations(
            self,
            builder,
            finding,
    ):
        matches = [
            create_match(
                project_path=f":{'m' * 12000}",
                build_file="large/build.gradle",
            ),
            create_match(
                project_path=":small",
                build_file="small/build.gradle",
            ),
        ]

        inspection = create_inspection(matches=matches)

        context = builder.build(finding, inspection)

        assert len(context.locations) == 1
        assert context.locations[0].module_path == ":small"

        facts = {fact.key: fact.value for fact in context.facts}
        assert facts["locations_omitted"] == "1"
