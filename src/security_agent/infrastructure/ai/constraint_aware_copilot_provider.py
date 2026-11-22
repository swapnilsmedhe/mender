import json

from security_agent.domain.ai_recommendation_context import AIRecommendationContext
from security_agent.domain.finding import SecurityFinding
from security_agent.infrastructure.ai.copilot_provider import (
    CopilotRecommendationProvider,
)


class ConstraintAwareCopilotRecommendationProvider(CopilotRecommendationProvider):
    @staticmethod
    def _build_prompt(finding: SecurityFinding, context: AIRecommendationContext) -> str:
        prompt = CopilotRecommendationProvider._build_prompt(finding, context)
        constraints = [
            {
                "affected_module": item.module_path,
                "affected_module_manifest": item.manifest_file,
                "constraint_source_component": item.source_component,
                "constraint_source_relationship": item.source_relationship.value,
                "constraint_provenance_path": list(item.provenance_path),
                "requested_component": item.requested,
                "selected_component": item.selected,
                "selection_reason": item.selection_reason,
            }
            for item in context.constraints
        ]

        source_declarations = []
        bom_candidates = []
        for fact in context.facts:
            try:
                if fact.key.startswith("source_declaration_"):
                    source_declarations.append({"fact_key": fact.key, "data": json.loads(fact.value)})
                elif (
                    fact.key.startswith("bom_candidate_")
                    and fact.key.removeprefix("bom_candidate_").isdigit()
                ):
                    bom_candidates.append({"fact_key": fact.key, "data": json.loads(fact.value)})
            except json.JSONDecodeError:
                continue

        return f'''
{prompt}

ADDITIONAL FINDING-SPECIFIC GRADLE CONSTRAINT PROVENANCE:
{json.dumps(constraints, indent=2)}

SOURCE-LEVEL GRADLE DECLARATIONS:
{json.dumps(source_declarations, indent=2)}

DYNAMIC GRADLE BOM CANDIDATE INVESTIGATION:
{json.dumps(bom_candidates, indent=2)}

HOW TO REASON ABOUT THE EVIDENCE:

1. Reconstruct dependency flow for each affected module using dependency
   paths, source declarations and resolved Gradle constraints.

2. Treat declaration identity and dependency-path identity separately.
   One source declaration may participate in multiple paths.

3. declaration_relationship describes whether a declaration is written
   in that module's build file. vulnerable_dependency_relationship
   describes whether the vulnerable component is direct or transitive.

4. A platform declaration is source-level evidence. Constraint provenance
   is resolution evidence. Do not conflate the two.

5. Look for a shared version authority. For example, if a module declares
   one Jackson BOM and Gradle constraint provenance shows that this BOM
   supplies the selected version of jackson-databind, treat the BOM as a
   candidate shared control point for the Jackson modules it constrains.

6. If several transitive paths converge on the same BOM or platform,
   explicitly consider upgrading that BOM once instead of proposing
   separate overrides for every transitive path.

5. A BOM that arrives transitively must not be treated as a directly
   editable source declaration. Identify the direct introducing dependency.

6. Effective Gradle property values are separate from repository-file
   candidates. Use effective_property_value only when
   effective_property_status is RESOLVED.

7. Candidate selectors such as 2.13.+ and 2.+ are search selectors, not
   recommended versions. selected_bom_version is the actual version Gradle
   resolved through the repository's configured repositories.

8. Candidate BOM experiments temporarily add a platform dependency to the
   affected configuration in an isolated Gradle invocation. They do not
   modify build files and do not prove that changing one existing source
   declaration would affect every module in the same way.

9. Inspect target_selected_version for each module. exact_scanner_fixed_match
   means the selected version exactly matches a scanner-reported fixed
   version. Do not claim a non-exact version is fixed merely because it is
   numerically higher.

10. A RESOLVED experiment establishes only the dependency selection observed
    in that configuration with the temporary platform. It does not establish
    source-level compatibility, successful compilation, passing tests,
    runtime behaviour or post-change scanner results.

11. Compare results across all affected modules. A candidate that fixes
    only some modules is not a complete repository-wide remediation.

12. Compare a BOM upgrade with direct property changes, introducing
    dependency upgrades and explicit constraints. Do not assume the BOM
    is the sole authority.

13. If the evidence does not prove one source change fixes all affected
    paths, keep the recommendation manual and state what remains unverified.
    Do not invent BOM versions or compatibility facts.

14. Return materially different remediation strategies only when the
    supplied evidence supports them. Never claim an experiment has tested
    the actual repository after a source change.
'''.strip()
