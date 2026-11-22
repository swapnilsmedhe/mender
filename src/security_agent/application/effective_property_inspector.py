from dataclasses import dataclass, replace

from security_agent.application.constraint_aware_repository_inspector import SourceDeclaration
from security_agent.application.gradle_property_collector import (
    GradlePropertyCollector, GradlePropertyRequest,
)


@dataclass(frozen=True)
class EffectiveSourceDeclaration(SourceDeclaration):
    effective_property_value: str | None = None
    effective_property_status: str | None = None
    effective_property_error: str | None = None


class EffectiveGradlePropertyInspector:
    """Attach targeted Gradle property lookup results to source declarations."""

    def __init__(self, inspector, property_collector: GradlePropertyCollector):
        self.inspector = inspector
        self.property_collector = property_collector

    def inspect(self, finding):
        inspection = self.inspector.inspect(finding)
        declarations = inspection.source_declarations
        requests = tuple(dict.fromkeys(
            GradlePropertyRequest(item.module_path, item.property_name, item.lookup_scope)
            for item in declarations
            if item.source_type == "GRADLE_PROJECT_PROPERTY" and item.property_name
            and item.lookup_scope in ("CURRENT_PROJECT", "ROOT_PROJECT")
        ))
        if not requests:
            return inspection

        try:
            results = self.property_collector.collect(requests)
            indexed = {(r.module_path, r.property_name, r.lookup_scope): r for r in results}
            updated = []
            for declaration in declarations:
                result = indexed.get((declaration.module_path, declaration.property_name,
                                      declaration.lookup_scope)) if declaration.property_name else None
                updated.append(EffectiveSourceDeclaration(
                    **declaration.__dict__,
                    effective_property_value=result.value if result and result.status == "RESOLVED" else None,
                    effective_property_status=result.status if result else None,
                    effective_property_error=result.error if result and result.status == "ERROR" else None,
                ))
        except (RuntimeError, OSError, ValueError, FileNotFoundError):
            updated = [EffectiveSourceDeclaration(
                **declaration.__dict__,
                effective_property_status=("COLLECTION_FAILED"
                    if declaration.source_type == "GRADLE_PROJECT_PROPERTY" else None),
            ) for declaration in declarations]
        return replace(inspection, source_declarations=tuple(updated))
