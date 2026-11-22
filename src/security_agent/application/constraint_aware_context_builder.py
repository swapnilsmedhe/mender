import json
from dataclasses import replace

from security_agent.application.ai_recommendation_context_builder import (
    AIRecommendationContextBuilder,
)
from security_agent.domain.ai_recommendation_context import ContextFact
from security_agent.domain.finding import SecurityFinding


class ConstraintAwareAIRecommendationContextBuilder(AIRecommendationContextBuilder):
    """
    Extend the normal AI context with Gradle constraints and the
    source declarations that explain affected dependency paths.
    """

    MAX_DECLARATION_FACTS = 20
    MAX_DECLARATION_FACT_LENGTH = 950

    def build(self, finding: SecurityFinding, inspection):
        context = super().build(finding, inspection)

        context = self._add_constraints(
            context,
            getattr(inspection, "constraints", ()),
        )

        return self._add_source_declarations(
            context,
            getattr(inspection, "source_declarations", ()),
        )

    @staticmethod
    def _add_constraints(context, constraints):
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
            context = ConstraintAwareAIRecommendationContextBuilder._append_fact(
                context,
                ContextFact(
                    key="constraints_omitted",
                    value=str(omitted_count),
                ),
            )

        return context

    def _add_source_declarations(self, context, declarations):
        included_count = 0
        omitted_count = 0

        for declaration in declarations:
            if included_count >= self.MAX_DECLARATION_FACTS:
                omitted_count += 1
                continue

            payload = {
                "module": declaration.module_path,
                "manifest": declaration.manifest_file,
                "dependency": declaration.dependency,
                "declaration_kind": declaration.declaration_kind,
                "relationship": declaration.relationship.value,
                "dependency_path": list(declaration.dependency_path),
                "declaration": declaration.declaration,
                "version_source": {
                    "type": declaration.source_type,
                    "property_name": declaration.property_name,
                    "lookup_scope": declaration.lookup_scope,
                    "source_file": declaration.source_file,
                    "declared_version": declaration.declared_version,
                    "resolved": declaration.source_resolved,
                    "candidate_source_file": (declaration.candidate_source_file),
                    "candidate_value": declaration.candidate_value,
                },
            }

            value = json.dumps(payload, separators=(",", ":"))

            if len(value) > self.MAX_DECLARATION_FACT_LENGTH:
                omitted_count += 1
                continue

            fact = ContextFact(
                key=f"source_declaration_{included_count + 1}",
                value=value,
            )

            updated_context = self._append_fact(context, fact)

            if updated_context is context:
                omitted_count += 1
                continue

            context = updated_context
            included_count += 1

        if omitted_count:
            context = self._append_fact(
                context,
                ContextFact(
                    key="source_declarations_omitted",
                    value=str(omitted_count),
                ),
            )

        return context

    @staticmethod
    def _append_fact(context, fact: ContextFact):
        if len(context.facts) >= context.MAX_FACTS:
            return context

        try:
            return replace(
                context,
                facts=(*context.facts, fact),
            )
        except ValueError:
            return context
