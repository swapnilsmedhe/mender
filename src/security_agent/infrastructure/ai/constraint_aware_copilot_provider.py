import json

from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
)
from security_agent.domain.finding import SecurityFinding
from security_agent.infrastructure.ai.copilot_provider import (
    CopilotRecommendationProvider,
)


class ConstraintAwareCopilotRecommendationProvider(CopilotRecommendationProvider):
    """
    Add structured Gradle constraint evidence to the existing Copilot prompt.

    The underlying Copilot SDK integration and response parsing remain
    unchanged.
    """

    @staticmethod
    def _build_prompt(
        finding: SecurityFinding,
        context: AIRecommendationContext,
    ) -> str:
        prompt = CopilotRecommendationProvider._build_prompt(
            finding,
            context,
        )

        constraints = [
            {
                "module": constraint.module_path,
                "manifest": constraint.manifest_file,
                "source_component": constraint.source_component,
                "requested": constraint.requested,
                "selected": constraint.selected,
            }
            for constraint in context.constraints
        ]

        constraint_evidence = json.dumps(
            constraints,
            indent=2,
        )

        return f"""
{prompt}

ADDITIONAL FINDING-SPECIFIC GRADLE CONSTRAINT EVIDENCE:

The following constraints were collected from Gradle's resolved
dependency report. They belong to modules already identified as
affected by this finding.

{constraint_evidence}

Interpretation rules for this evidence:
- These records describe resolved Gradle constraint edges.
- The source component is the component associated with the
  constraint edge; do not automatically assume it is a BOM.
- The selected component is the version Gradle selected for the
  constrained dependency.
- A constraint selecting the vulnerable component is evidence
  that the constraint participates in version selection.
- Do not conclude that this constraint is the only source of
  the selected version.
- Consider upgrading the source component only when the available
  evidence supports that strategy.
- Compare this strategy with direct dependency upgrades and
  other relevant parent dependency upgrades.
- If the evidence does not establish a safe change, explain
  what additional targeted evidence is required.
""".strip()
