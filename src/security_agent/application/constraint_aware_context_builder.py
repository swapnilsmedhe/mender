import json
from dataclasses import replace

from security_agent.application.ai_recommendation_context_builder import AIRecommendationContextBuilder
from security_agent.domain.ai_recommendation_context import ContextFact
from security_agent.domain.finding import SecurityFinding


class ConstraintAwareAIRecommendationContextBuilder(AIRecommendationContextBuilder):
    """Add constraint, source-declaration, and effective-property evidence to AI context."""

    MAX_DECLARATION_FACTS = 20
    MAX_DECLARATION_FACT_LENGTH = 1000

    def build(self, finding: SecurityFinding, inspection):
        context = super().build(finding, inspection)
        context = self._add_constraints(context, getattr(inspection, "constraints", ()))
        return self._add_source_declarations(context, getattr(inspection, "source_declarations", ()))

    @staticmethod
    def _add_constraints(context, constraints):
        included, omitted = [], 0
        for constraint in constraints:
            if len(included) >= context.MAX_CONSTRAINTS:
                omitted += 1
                continue
            try:
                context = replace(context, constraints=(*included, constraint))
                included.append(constraint)
            except ValueError:
                omitted += 1
        if omitted:
            context = ConstraintAwareAIRecommendationContextBuilder._append_fact(
                context, ContextFact(key="constraints_omitted", value=str(omitted)))
        return context

    def _add_source_declarations(self, context, declarations):
        included, omitted = 0, 0
        for declaration in declarations:
            if included >= self.MAX_DECLARATION_FACTS:
                omitted += 1
                continue
            payload = {
                "module": declaration.module_path,
                "manifest": declaration.manifest_file,
                "dependency": declaration.dependency,
                "declaration_kind": declaration.declaration_kind,
                "declaration_relationship": declaration.declaration_relationship.value,
                "vulnerable_dependency_relationship": declaration.vulnerable_dependency_relationship.value,
                "dependency_paths": [list(path) for path in declaration.dependency_paths],
                "constraint_provenance": [{
                    "source_relationship": item.source_relationship.value,
                    "provenance_path": list(item.provenance_path),
                    "requested_component": item.requested_component,
                    "selected_component": item.selected_component,
                    "selection_reason": item.selection_reason,
                } for item in declaration.constraint_provenance],
                "declaration": declaration.declaration,
                "version_source": {
                    "type": declaration.source_type,
                    "property_name": declaration.property_name,
                    "lookup_scope": declaration.lookup_scope,
                    "source_file": declaration.source_file,
                    "declared_version": declaration.declared_version,
                    "resolved": declaration.source_resolved,
                    "candidate_source_file": declaration.candidate_source_file,
                    "candidate_value": declaration.candidate_value,
                    "effective_property_value": getattr(declaration, "effective_property_value", None),
                    "effective_property_status": getattr(declaration, "effective_property_status", None),
                    "effective_property_error": getattr(declaration, "effective_property_error", None),
                },
            }
            value = json.dumps(payload, separators=(",", ":"))
            if len(value) > self.MAX_DECLARATION_FACT_LENGTH:
                omitted += 1
                continue
            fact = ContextFact(key=f"source_declaration_{included + 1}", value=value)
            updated_context = self._append_fact(context, fact)
            if updated_context is context:
                omitted += 1
                continue
            context = updated_context
            included += 1
        if omitted:
            context = self._append_fact(context, ContextFact(
                key="source_declarations_omitted", value=str(omitted)))
        return context

    @staticmethod
    def _append_fact(context, fact: ContextFact):
        if len(context.facts) >= context.MAX_FACTS:
            return context
        try:
            return replace(context, facts=(*context.facts, fact))
        except ValueError:
            return context
