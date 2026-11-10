from security_agent.application.repository_inspector import (
    RepositoryInspection,
)
from security_agent.domain.ai_recommendation_context import (
    AIRecommendationContext,
    ContextFact,
    DependencyLocation,
    DependencyRelationship,
)
from security_agent.domain.finding import SecurityFinding


class AIRecommendationContextBuilder:
    def build(
            self,
            finding: SecurityFinding,
            inspection: RepositoryInspection,
    ) -> AIRecommendationContext:
        if inspection.finding_id != finding.id:
            raise ValueError(
                "Finding and repository inspection IDs do not match."
            )

        facts = (
            ContextFact(
                key="inspection_consistent",
                value=str(inspection.is_consistent).lower(),
            ),
            ContextFact(
                key="direct_match_count",
                value=str(len(inspection.matches)),
            ),
            ContextFact(
                key="transitive_match_count",
                value=str(len(inspection.transitive_matches)),
            ),
            ContextFact(
                key="inspection_error_count",
                value=str(len(inspection.errors)),
            ),
        )

        candidates = []
        omitted_count = 0

        match_groups = (
            (inspection.matches, DependencyRelationship.DIRECT),
            (
                inspection.transitive_matches,
                DependencyRelationship.TRANSITIVE,
            ),
        )

        for matches, relationship in match_groups:
            for match in matches:
                try:
                    location = self._to_location(
                        match,
                        relationship,
                    )
                    candidates.append(location)
                except ValueError:
                    # Individual location validation failed.
                    omitted_count += 1

        candidates = self._deduplicate(candidates)

        included = []

        for location in candidates:
            if len(included) >= AIRecommendationContext.MAX_LOCATIONS:
                omitted_count += 1
                continue

            try:
                self._create_context(
                    finding=finding,
                    inspection=inspection,
                    locations=(*included, location),
                    facts=facts,
                )
            except ValueError:
                # The location would exceed the overall context budget.
                omitted_count += 1
                continue

            included.append(location)

        if omitted_count:
            while True:
                final_facts = (
                    *facts,
                    ContextFact(
                        key="locations_omitted",
                        value=str(omitted_count),
                    ),
                )

                try:
                    return self._create_context(
                        finding=finding,
                        inspection=inspection,
                        locations=tuple(included),
                        facts=final_facts,
                    )
                except ValueError:
                    if not included:
                        raise

                    # Make room for the omission summary.
                    included.pop()
                    omitted_count += 1

        return self._create_context(
            finding=finding,
            inspection=inspection,
            locations=tuple(included),
            facts=facts,
        )

    @staticmethod
    def _to_location(
            match,
            relationship: DependencyRelationship,
    ) -> DependencyLocation:
        return DependencyLocation(
            module_path=str(match.project_path),
            manifest_file=str(match.build_file),
            relationship=relationship,
        )

    @staticmethod
    def _deduplicate(
            locations: list[DependencyLocation],
    ) -> list[DependencyLocation]:
        unique = []
        seen = set()

        for location in locations:
            key = (
                location.module_path,
                location.manifest_file,
                location.relationship,
            )

            if key not in seen:
                seen.add(key)
                unique.append(location)

        return unique

    @staticmethod
    def _create_context(
            finding: SecurityFinding,
            inspection: RepositoryInspection,
            locations: tuple[DependencyLocation, ...],
            facts: tuple[ContextFact, ...],
    ) -> AIRecommendationContext:
        return AIRecommendationContext(
            finding_id=finding.id,
            dependency_name=finding.component,
            resolved_version=finding.current_version,
            dependency_scope=inspection.configuration,
            locations=locations,
            facts=facts,
        )
