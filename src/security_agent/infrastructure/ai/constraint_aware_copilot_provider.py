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
    Add structured Gradle constraint provenance to the Copilot prompt.

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
                "affected_module": constraint.module_path,
                "affected_module_manifest": constraint.manifest_file,
                "constraint_source_component": constraint.source_component,
                "constraint_source_relationship": (
                    constraint.source_relationship.value
                ),
                "constraint_provenance_path": list(constraint.provenance_path),
                "requested_component": constraint.requested,
                "selected_component": constraint.selected,
                "selection_reason": constraint.selection_reason,
            }
            for constraint in context.constraints
        ]

        constraint_evidence = json.dumps(
            constraints,
            indent=2,
        )

        return f"""
{prompt}

ADDITIONAL FINDING-SPECIFIC GRADLE CONSTRAINT PROVENANCE:

The following records describe resolved Gradle constraints that
select the vulnerable component.

{constraint_evidence}

Interpretation rules:
- "affected_module_manifest" is the build file of the affected module.
  It is NOT necessarily the file that declared the constraint source.
- "constraint_source_component" is the component from which the
  constraint edge originates in Gradle's resolved graph.
- "constraint_provenance_path" describes the ordinary dependency path
  from the affected project to that source component.
- "DIRECT" means the source component is a direct dependency of the
  affected project in the resolved graph.
- "TRANSITIVE" means the source component was reached through one or
  more other resolved components.
- "UNKNOWN" means Mender could not establish a provenance path.
- A resolved graph path does not prove the exact source-code
  declaration location. Do not invent one.
- "selection_reason" describes Gradle's selection reason for the
  selected component. Treat it as supporting evidence, not proof
  that one constraint is the only version authority.
- Compare a BOM/platform upgrade with upgrades to introducing
  dependencies and direct dependency changes.
- Do not assume a transitive BOM should be upgraded in the affected
  module's build file.
- If the evidence does not establish a safe remediation, identify
  the specific additional evidence needed.
""".strip()
