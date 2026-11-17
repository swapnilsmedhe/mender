
import json

import pytest

from security_agent.domain.ai_recommendation import (
    RecommendationType,
)
from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
    ContextFact,
    DependencyLocation,
    DependencyRelationship,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)
from security_agent.infrastructure.ai.copilot_provider import (
    CopilotRecommendationProvider,
)


@pytest.fixture
def finding():
    return SecurityFinding(
        id="FINDING-001",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2025-12345",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="sample-repository",
        file="app/build.gradle",
    )


@pytest.fixture
def context():
    return AIRecommendationContext(
        finding_id="FINDING-001",
        dependency_name="com.fasterxml.jackson.core:jackson-databind",
        resolved_version="2.15.2",
        dependency_scope="runtimeClasspath",
        locations=(
            DependencyLocation(
                module_path=":app",
                manifest_file="app/build.gradle",
                relationship=DependencyRelationship.TRANSITIVE,
                dependency_path=(
                    "org.springframework.boot:spring-boot-starter-web:3.2.1",
                    "com.fasterxml.jackson.core:jackson-databind:2.15.2",
                ),
            ),
        ),
        facts=(
            ContextFact(
                key="transitive_match_count",
                value="1",
            ),
        ),
    )


@pytest.fixture
def provider():
    return CopilotRecommendationProvider()


def test_builds_prompt_with_finding_and_gradle_evidence(
        provider,
        finding,
        context,
):
    prompt = provider._build_prompt(finding, context)

    assert finding.cve in prompt
    assert finding.component in prompt
    assert finding.current_version in prompt
    assert "spring-boot-starter-web" in prompt
    assert "runtimeClasspath" in prompt


def test_parses_valid_json_response(provider):
    response = {
        "summary": "A safe remediation was identified.",
        "recommendations": [],
    }

    result = provider._parse_response(json.dumps(response))

    assert result == response


def test_parses_json_code_fence(provider):
    response = """
```json
{
    "summary": "Analysis complete",
    "recommendations": []
}
```
"""

    result = provider._parse_response(response)

    assert result["summary"] == "Analysis complete"


def test_rejects_invalid_json(provider):
    with pytest.raises(ValueError, match="invalid JSON"):
        provider._parse_response("This is not JSON")


def test_rejects_missing_recommendations(provider):
    with pytest.raises(ValueError, match="recommendations array"):
        provider._parse_response(
            json.dumps({"summary": "No recommendations field"})
        )


def test_converts_recommendation_to_domain_model(
        provider,
        finding,
):
    payload = {
        "summary": "Upgrade the vulnerable dependency.",
        "recommendations": [
            {
                "recommendation_id": "REC-001",
                "recommendation_type": "VERSION_UPGRADE",
                "title": "Upgrade Jackson",
                "description": "Upgrade to the scanner-reported fixed version.",
                "rationale": "The scanner identifies this version as fixed.",
                "target_version": "2.17.3",
                "target_dependency": None,
                "compatibility_notes": ["Check application compatibility."],
                "risks": [
                    {
                        "level": "MEDIUM",
                        "description": "Potential behavioral changes.",
                    }
                ],
                "confidence": "MEDIUM",
                "requires_manual_review": True,
            }
        ],
    }

    result = provider._to_result(finding, payload)

    assert result.finding_id == finding.id
    assert result.provider == "github_copilot"
    assert len(result.recommendations) == 1

    recommendation = result.recommendations[0]

    assert recommendation.recommendation_type == (
        RecommendationType.VERSION_UPGRADE
    )
    assert recommendation.target_version == "2.17.3"
    assert recommendation.requires_manual_review is True


def test_rejects_recommendation_with_invalid_type(
        provider,
        finding,
):
    payload = {
        "summary": "Invalid recommendation.",
        "recommendations": [
            {
                "recommendation_id": "REC-001",
                "recommendation_type": "RUN_ARBITRARY_COMMAND",
                "title": "Invalid",
                "description": "Invalid",
                "rationale": "Invalid",
            }
        ],
    }

    with pytest.raises(ValueError):
        provider._to_result(finding, payload)


def test_rejects_recommendation_for_missing_target_version(
        provider,
        finding,
):
    payload = {
        "summary": "Invalid upgrade.",
        "recommendations": [
            {
                "recommendation_id": "REC-001",
                "recommendation_type": "VERSION_UPGRADE",
                "title": "Upgrade",
                "description": "Upgrade dependency.",
                "rationale": "A version is required.",
            }
        ],
    }

    with pytest.raises(ValueError, match="target_version is required"):
        provider._to_result(finding, payload)
