import pytest

from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
    ContextFact,
    DependencyLocation,
    DependencyRelationship,
)


def create_location(**overrides):
    values = {
        "module_path": ":app",
        "manifest_file": "app/build.gradle",
        "relationship": DependencyRelationship.DIRECT,
    }
    values.update(overrides)
    return DependencyLocation(**values)


def create_context(**overrides):
    values = {
        "finding_id": "finding-1",
        "dependency_name": "jackson-databind",
        "resolved_version": "2.15.2",
    }
    values.update(overrides)
    return AIRecommendationContext(**values)


class TestContextFact:
    def test_creates_valid_fact(self):
        fact = ContextFact(
            key="scanner",
            value="Black Duck",
        )

        assert fact.key == "scanner"
        assert fact.value == "Black Duck"

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("", "Black Duck"),
            ("   ", "Black Duck"),
            ("scanner", ""),
            ("scanner", "   "),
        ],
    )
    def test_rejects_empty_fields(self, key, value):
        with pytest.raises(ValueError):
            ContextFact(key=key, value=value)

    def test_rejects_long_key(self):
        with pytest.raises(ValueError):
            ContextFact(
                key="k" * 1001,
                value="value",
            )

    def test_rejects_long_value(self):
        with pytest.raises(ValueError):
            ContextFact(
                key="scanner",
                value="v" * 1001,
            )


class TestDependencyLocation:
    def test_creates_valid_location(self):
        location = create_location(
            lock_file="gradle.lockfile",
            dependency_path=(
                "com.example:parent:1.0",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
            declaration="implementation 'jackson-databind:2.15.2'",
        )

        assert location.module_path == ":app"
        assert location.relationship == DependencyRelationship.DIRECT
        assert location.lock_file == "gradle.lockfile"
        assert len(location.dependency_path) == 2

    @pytest.mark.parametrize(
        "overrides",
        [
            {"module_path": ""},
            {"module_path": "   "},
            {"manifest_file": ""},
            {"manifest_file": "   "},
            {"relationship": "DIRECT"},
            {"lock_file": ""},
            {"lock_file": "   "},
            {"dependency_path": ("",)},
            {"declaration": ""},
            {"declaration": "   "},
        ],
    )
    def test_rejects_invalid_fields(self, overrides):
        with pytest.raises(ValueError):
            create_location(**overrides)

    def test_rejects_too_many_dependency_path_entries(self):
        with pytest.raises(ValueError):
            create_location(
                dependency_path=tuple(
                    f"dependency-{index}"
                    for index in range(11)
                )
            )

    def test_rejects_long_module_path(self):
        with pytest.raises(ValueError):
            create_location(module_path="m" * 501)

    def test_rejects_long_manifest_path(self):
        with pytest.raises(ValueError):
            create_location(manifest_file="f" * 501)

    def test_rejects_long_dependency_path_entry(self):
        with pytest.raises(ValueError):
            create_location(
                dependency_path=("d" * 501,)
            )

    def test_rejects_long_declaration(self):
        with pytest.raises(ValueError):
            create_location(declaration="d" * 1001)


class TestAIRecommendationContext:
    def test_creates_valid_context(self):
        location = create_location()
        fact = ContextFact(
            key="scanner",
            value="Black Duck",
        )

        context = create_context(
            dependency_scope="runtimeClasspath",
            locations=(location,),
            facts=(fact,),
        )

        assert context.finding_id == "finding-1"
        assert context.dependency_name == "jackson-databind"
        assert context.resolved_version == "2.15.2"
        assert context.dependency_scope == "runtimeClasspath"
        assert context.locations == (location,)
        assert context.facts == (fact,)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"finding_id": ""},
            {"finding_id": "   "},
            {"dependency_name": ""},
            {"dependency_name": "   "},
            {"resolved_version": ""},
            {"resolved_version": "   "},
            {"dependency_scope": ""},
            {"dependency_scope": "   "},
        ],
    )
    def test_rejects_empty_required_or_optional_fields(self, overrides):
        with pytest.raises(ValueError):
            create_context(**overrides)

    def test_rejects_too_many_locations(self):
        locations = tuple(
            create_location(module_path=f":module{index}")
            for index in range(21)
        )

        with pytest.raises(ValueError):
            create_context(locations=locations)

    def test_rejects_too_many_facts(self):
        facts = tuple(
            ContextFact(key=f"key-{index}", value="value")
            for index in range(31)
        )

        with pytest.raises(ValueError):
            create_context(facts=facts)

    def test_rejects_invalid_location_type(self):
        with pytest.raises(ValueError):
            create_context(locations=("not-a-location",))

    def test_rejects_invalid_fact_type(self):
        with pytest.raises(ValueError):
            create_context(facts=("not-a-fact",))

    def test_rejects_context_exceeding_character_limit(self):
        facts = tuple(
            ContextFact(
                key=f"key-{index}",
                value="v" * 1000,
            )
            for index in range(13)
        )

        with pytest.raises(ValueError):
            create_context(facts=facts)

    def test_calculates_estimated_characters(self):
        location = create_location(
            lock_file="gradle.lockfile",
            dependency_path=("parent:1.0",),
            declaration="implementation 'example:library:1.0'",
        )
        fact = ContextFact(
            key="scanner",
            value="Black Duck",
        )

        context = create_context(
            dependency_scope="runtimeClasspath",
            locations=(location,),
            facts=(fact,),
        )

        expected = (
                len("finding-1")
                + len("jackson-databind")
                + len("2.15.2")
                + len("runtimeClasspath")
                + len(":app")
                + len("app/build.gradle")
                + len("gradle.lockfile")
                + len("parent:1.0")
                + len("implementation 'example:library:1.0'")
                + len("scanner")
                + len("Black Duck")
        )

        assert context.estimated_characters == expected

    def test_allows_context_without_optional_details(self):
        context = create_context()

        assert context.locations == ()
        assert context.facts == ()
        assert context.dependency_scope is None