import pytest

from security_agent.domain.ai_recommendation import (
    AIRecommendation,
    AIRecommendationResult,
    RecommendationRisk,
    RecommendationType,
    RiskLevel,
)
from security_agent.domain.analysis import Confidence


def create_upgrade_recommendation(
        recommendation_id="REC-001",
        finding_id="FINDING-001",
):
    return AIRecommendation(
        recommendation_id=recommendation_id,
        finding_id=finding_id,
        recommendation_type=RecommendationType.VERSION_UPGRADE,
        title="Upgrade jackson-databind",
        description="Upgrade to a scanner-reported fixed version.",
        rationale="The current version contains a reported vulnerability.",
        target_version="2.16.0",
        compatibility_notes=(
            "Validate compatibility with the existing application.",
        ),
        risks=(
            RecommendationRisk(
                level=RiskLevel.MEDIUM,
                description="Potential API compatibility changes.",
            ),
        ),
        confidence=Confidence.HIGH,
    )


def test_create_version_upgrade_recommendation():
    recommendation = create_upgrade_recommendation()

    assert recommendation.recommendation_type == (
        RecommendationType.VERSION_UPGRADE
    )
    assert recommendation.target_version == "2.16.0"
    assert recommendation.confidence == Confidence.HIGH
    assert recommendation.requires_manual_review is True


def test_create_dependency_replacement_recommendation():
    recommendation = AIRecommendation(
        recommendation_id="REC-002",
        finding_id="FINDING-001",
        recommendation_type=RecommendationType.DEPENDENCY_REPLACEMENT,
        title="Replace vulnerable dependency",
        description="Use an alternative dependency.",
        rationale="The existing dependency cannot be safely upgraded.",
        target_dependency="com.example:alternative-library",
    )

    assert recommendation.target_dependency == (
        "com.example:alternative-library"
    )


def test_version_upgrade_requires_target_version():
    with pytest.raises(ValueError, match="target_version is required"):
        AIRecommendation(
            recommendation_id="REC-001",
            finding_id="FINDING-001",
            recommendation_type=RecommendationType.VERSION_UPGRADE,
            title="Upgrade dependency",
            description="Upgrade the dependency.",
            rationale="A newer version is needed.",
        )


def test_dependency_override_requires_target_version():
    with pytest.raises(ValueError, match="target_version is required"):
        AIRecommendation(
            recommendation_id="REC-001",
            finding_id="FINDING-001",
            recommendation_type=RecommendationType.DEPENDENCY_OVERRIDE,
            title="Override dependency",
            description="Override the transitive dependency.",
            rationale="Use a fixed version.",
        )


def test_dependency_replacement_requires_target_dependency():
    with pytest.raises(
            ValueError,
            match="target_dependency is required",
    ):
        AIRecommendation(
            recommendation_id="REC-001",
            finding_id="FINDING-001",
            recommendation_type=RecommendationType.DEPENDENCY_REPLACEMENT,
            title="Replace dependency",
            description="Use an alternative.",
            rationale="The existing dependency is unsuitable.",
        )


def test_recommendation_requires_non_empty_title():
    with pytest.raises(ValueError, match="title cannot be empty"):
        AIRecommendation(
            recommendation_id="REC-001",
            finding_id="FINDING-001",
            recommendation_type=RecommendationType.MANUAL_REMEDIATION,
            title=" ",
            description="Investigate manually.",
            rationale="No automated option is available.",
        )


def test_recommendation_risk_requires_description():
    with pytest.raises(
            ValueError,
            match="Risk description cannot be empty",
    ):
        RecommendationRisk(
            level=RiskLevel.HIGH,
            description=" ",
        )


def test_create_multiple_recommendations_for_one_finding():
    first = create_upgrade_recommendation()

    second = AIRecommendation(
        recommendation_id="REC-002",
        finding_id="FINDING-001",
        recommendation_type=RecommendationType.TEMPORARY_MITIGATION,
        title="Apply temporary mitigation",
        description="Use a temporary configuration mitigation.",
        rationale="Provides an interim risk reduction.",
    )

    result = AIRecommendationResult(
        finding_id="FINDING-001",
        summary="Two possible remediation options identified.",
        provider="openai_compatible",
        model="example-model",
        recommendations=(first, second),
    )

    assert len(result.recommendations) == 2
    assert result.provider == "openai_compatible"
    assert result.model == "example-model"


def test_result_rejects_recommendation_for_different_finding():
    recommendation = create_upgrade_recommendation(
        finding_id="OTHER-FINDING"
    )

    with pytest.raises(ValueError, match="must belong to the result"):
        AIRecommendationResult(
            finding_id="FINDING-001",
            summary="Test result.",
            provider="test-provider",
            recommendations=(recommendation,),
        )


def test_result_rejects_duplicate_recommendation_ids():
    first = create_upgrade_recommendation()
    second = create_upgrade_recommendation()

    with pytest.raises(ValueError, match="must be unique"):
        AIRecommendationResult(
            finding_id="FINDING-001",
            summary="Test result.",
            provider="test-provider",
            recommendations=(first, second),
        )


def test_result_can_contain_no_recommendations():
    result = AIRecommendationResult(
        finding_id="FINDING-001",
        summary="No safe automatic remediation was identified.",
        provider="test-provider",
    )

    assert result.recommendations == ()
