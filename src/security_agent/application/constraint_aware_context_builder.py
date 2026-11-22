from dataclasses import replace

from security_agent.application.ai_recommendation_context_builder import (
    AIRecommendationContextBuilder,
)
from security_agent.domain.ai_recommendation_context import ContextFact
from security_agent.domain.finding import SecurityFinding


class ConstraintAwareAIRecommendationContextBuilder(AIRecommendationContextBuilder):
    """
    Extend the normal AI context with relevant Gradle constraints.

    The existing context builder still controls dependency-path
    filtering, location deduplication, and context-size validation.
    """

    def build(self, finding, inspection):
        context = super().build(finding, inspection)

        constraints = getattr(inspection, "constraints", ())
        included = []
        omitted_count = 0

        for constraint in constraints:
            if len(included) >= context.MAX_CONSTRAINTS:
                omitted_count += 1
                continue

            candidate_constraints = (*included, constraint)

            try:
                candidate_context = replace(
                    context,
                    constraints=candidate_constraints,
                )
            except ValueError:
                omitted_count += 1
                continue

            included.append(constraint)
            context = candidate_context

        if omitted_count:
            omission_fact = ContextFact(
                key="constraints_omitted",
                value=str(omitted_count),
            )

            if len(context.facts) < context.MAX_FACTS:
                try:
                    context = replace(
                        context,
                        facts=(*context.facts, omission_fact),
                    )
                except ValueError:
                    # The constraint evidence already respects the
                    # context limit. Omission metadata is supplementary.
                    pass

        return context
