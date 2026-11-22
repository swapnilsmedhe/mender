from dataclasses import replace

from security_agent.application.ai_recommendation_service import (
    AIRecommendationService,
)
from security_agent.domain.analysis import RemediationType
from security_agent.domain.remediation import RemediationPlan


class SecurityRemediationOrchestrator:
    CONFIDENCE_RANK = {  # noqa: RUF012
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def __init__(
        self,
        analyzer,
        planner,
        inspector,
        ai_recommendation_service: AIRecommendationService | None = None,
        force_ai: bool = False,
    ):
        self.analyzer = analyzer
        self.planner = planner
        self.inspector = inspector
        self.ai_recommendation_service = ai_recommendation_service
        self.force_ai = force_ai
        self.ai_recommendation_outcomes = []

    def run(self, finding):
        self.ai_recommendation_outcomes = []

        inspection = self.inspector.inspect(finding)

        if inspection.errors:
            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                f"Direct matches: {len(inspection.matches)}.\n"
                f"Transitive matches: "
                f"{len(inspection.transitive_matches)}.\n"
                f"Inspection errors: {list(inspection.errors)}.\n"
                "No remediation plan was generated."
            )

        if not inspection.matches and not inspection.transitive_matches:
            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                "No direct or transitive dependency matches were found.\n"
                "No remediation plan was generated."
            )

        if (
            inspection.matches
            and not inspection.is_consistent
            and len(inspection.matches) < 2
        ):
            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                f"Direct matches: {len(inspection.matches)}.\n"
                "No remediation plan was generated."
            )

        module_matches = [(match, False) for match in inspection.matches] + [
            (match, True) for match in inspection.transitive_matches
        ]

        plans = []
        ai_analysis = None

        # Deterministic analysis and planning remain module-specific.
        # AI analysis is deliberately not performed inside this loop.
        for match, is_transitive in module_matches:
            module_finding = replace(
                finding,
                file=match.build_file,
            )

            analysis = self.analyzer.analyze(module_finding)

            if ai_analysis is None:
                ai_analysis = analysis

            if is_transitive:
                plan = self.planner.create_plan(
                    finding=module_finding,
                    analysis=analysis,
                    is_transitive=True,
                    dependency_paths=match.dependency_paths,
                )
            else:
                plan = self.planner.create_plan(
                    finding=module_finding,
                    analysis=analysis,
                )

            plans.append(plan)

        # One AI invocation for the complete finding and inspection.
        if self.ai_recommendation_service is not None and ai_analysis is not None:
            outcome = self.ai_recommendation_service.recommend(
                finding=finding,
                analysis=ai_analysis,
                force=self.force_ai,
                inspection=inspection,
            )

            self.ai_recommendation_outcomes.append(outcome)

        return self._combine_plans(finding.id, plans)


    def _combine_plans(
            self,
            finding_id: str,
            plans: list[RemediationPlan],
    ) -> RemediationPlan:
        if not plans:
            raise ValueError(
                "No remediation plans were generated."
            )

        confidence = min(
            (plan.confidence for plan in plans),
            key=lambda item: self.CONFIDENCE_RANK[item.value],
        )

        manual_plans = [
            plan
            for plan in plans
            if plan.remediation_type
            == RemediationType.NO_AUTOMATIC_REMEDIATION
        ]

        # Do not partially remediate a finding when any affected
        # dependency path cannot be safely addressed.
        if manual_plans:
            reasons = list(
                dict.fromkeys(plan.reason for plan in plans)
            )

            manual_review_reasons = list(
                dict.fromkeys(
                    reason
                    for plan in manual_plans
                    for reason in (
                        plan.manual_review_reasons or [plan.reason]
                    )
                )
            )

            return RemediationPlan(
                finding_id=finding_id,
                remediation_type=(
                    RemediationType.NO_AUTOMATIC_REMEDIATION
                ),
                reason="; ".join(reasons),
                confidence=confidence,
                changes=[],
                validation_steps=[],
                manual_review_reasons=manual_review_reasons,
            )

        changes_by_key = {}

        for plan in plans:
            for change in plan.changes:
                key = (change.file, change.dependency)
                changes_by_key[key] = change

        changes = list(changes_by_key.values())

        validation_steps = list(
            dict.fromkeys(
                step
                for plan in plans
                for step in plan.validation_steps
            )
        )

        reasons = list(
            dict.fromkeys(plan.reason for plan in plans)
        )

        return RemediationPlan(
            finding_id=finding_id,
            remediation_type=plans[0].remediation_type,
            reason="; ".join(reasons),
            confidence=confidence,
            changes=changes,
            validation_steps=validation_steps,
        )

        reasons = list(dict.fromkeys(plan.reason for plan in plans))

        return RemediationPlan(
            finding_id=finding_id,
            remediation_type=RemediationType.NO_AUTOMATIC_REMEDIATION,
            reason="; ".join(reasons),
            confidence=confidence,
            changes=[],
            validation_steps=[],
            manual_review_reasons=manual_review_reasons,
        )
