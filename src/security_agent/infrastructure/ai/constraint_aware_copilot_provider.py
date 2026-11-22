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
    Add Gradle constraint provenance and source declaration evidence
    to the Copilot remediation reasoning prompt.
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

        source_declarations = []

        for fact in context.facts:
            if not fact.key.startswith("source_declaration_"):
                continue

            try:
                source_declarations.append(json.loads(fact.value))
            except json.JSONDecodeError:
                continue

        return f"""
{prompt}

ADDITIONAL FINDING-SPECIFIC GRADLE CONSTRAINT PROVENANCE:

{json.dumps(constraints, indent=2)}

SOURCE-LEVEL GRADLE DECLARATIONS:

{json.dumps(source_declarations, indent=2)}

HOW TO REASON ABOUT THE EVIDENCE:

1. Reconstruct the dependency flow for each affected module using
   dependency paths, introducing dependency declarations, and
   resolved Gradle constraints.

2. Correlate declarations across paths. Multiple paths to the same
   vulnerable component do not necessarily represent multiple
   independent version sources.

3. Look for a shared version authority. For example, if a module
   declares one Jackson BOM and Gradle constraint provenance shows
   that this BOM supplies the selected version of jackson-databind,
   treat the BOM as a candidate shared control point for the
   Jackson modules it constrains.

4. If several transitive paths converge on the same BOM or platform,
   explicitly consider upgrading that BOM once instead of proposing
   separate overrides for every transitive path.

5. Do not assume that a BOM controls every dependency merely because
   it appears somewhere in the graph. Require matching component
   coordinates and relevant Gradle constraint evidence.

6. Distinguish a BOM declared directly by the affected module from
   a BOM that arrives transitively through another dependency.
   Do not recommend editing a transitive library's build file.

7. Compare candidate remediation strategies:
   - Upgrade the shared BOM or platform.
   - Upgrade the direct introducing dependency.
   - Upgrade a higher-level parent dependency.
   - Upgrade the vulnerable component directly.
   - Use a dependency constraint or override only when justified.

8. Prefer the smallest change that fixes the vulnerable selected
   version across all affected paths. Do not create one change per
   path when a single shared source can explain those paths.

9. A declaration's presence is source-level evidence. A Gradle
   constraint edge is resolution evidence. A candidate property
   value is not proof of the effective Gradle property value.
   Keep these evidence types distinct.

10. If one source appears to control multiple paths, explain exactly
    which evidence supports that conclusion and which paths it covers.
    If the evidence is incomplete, state what is missing instead of
    presenting the source as confirmed.

11. Do not claim a proposed upgrade is compatible or tested unless
    the supplied evidence establishes that. Recommend targeted
    compatibility checks where needed.

12. Return multiple materially different remediation strategies
    when evidence supports them, and rank them by safety and scope.
    Do not return duplicate recommendations for the same underlying
    source change.

The affected dependency paths should be understood as a connected
dependency graph, not as unrelated findings.
""".strip()
