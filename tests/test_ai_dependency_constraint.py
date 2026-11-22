import pytest

from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
    DependencyConstraint,
)


def create_constraint(**overrides):
    values = {
        "module_path": ":bom-consumer",
        "manifest_file": "bom-consumer/build.gradle.kts",
        "source_component": "com.fasterxml.jackson:jackson-bom:2.13.4",
        "requested": "com.fasterxml.jackson.core:jackson-databind:2.13.4",
        "selected": "com.fasterxml.jackson.core:jackson-databind:2.13.4",
    }
    values.update(overrides)
    return DependencyConstraint(**values)


def test_creates_valid_dependency_constraint():
    constraint = create_constraint()

    assert constraint.module_path == ":bom-consumer"
    assert constraint.source_component == ("com.fasterxml.jackson:jackson-bom:2.13.4")


@pytest.mark.parametrize(
    "field",
    [
        "module_path",
        "manifest_file",
        "source_component",
        "requested",
        "selected",
    ],
)
def test_rejects_empty_constraint_fields(field):
    with pytest.raises(ValueError):
        create_constraint(**{field: " "})


def test_rejects_oversized_constraint_field():
    with pytest.raises(ValueError):
        create_constraint(source_component="x" * 501)


def test_context_accepts_dependency_constraints():
    constraint = create_constraint()

    context = AIRecommendationContext(
        finding_id="finding-1",
        dependency_name="com.fasterxml.jackson.core:jackson-databind",
        resolved_version="2.13.4",
        constraints=(constraint,),
    )

    assert context.constraints == (constraint,)


def test_context_rejects_invalid_constraint_type():
    with pytest.raises(ValueError, match="Invalid dependency constraint"):
        AIRecommendationContext(
            finding_id="finding-1",
            dependency_name="jackson-databind",
            resolved_version="2.13.4",
            constraints=("not-a-constraint",),
        )


def test_context_enforces_constraint_limit():
    constraints = tuple(
        create_constraint(module_path=f":module-{index}") for index in range(21)
    )

    with pytest.raises(ValueError, match="Too many dependency constraints"):
        AIRecommendationContext(
            finding_id="finding-1",
            dependency_name="jackson-databind",
            resolved_version="2.13.4",
            constraints=constraints,
        )


def test_context_counts_constraint_characters():
    constraint = create_constraint()

    context = AIRecommendationContext(
        finding_id="finding-1",
        dependency_name="jackson-databind",
        resolved_version="2.13.4",
        constraints=(constraint,),
    )

    expected = (
        len("finding-1")
        + len("jackson-databind")
        + len("2.13.4")
        + len(constraint.module_path)
        + len(constraint.manifest_file)
        + len(constraint.source_component)
        + len(constraint.requested)
        + len(constraint.selected)
    )

    assert context.estimated_characters == expected
