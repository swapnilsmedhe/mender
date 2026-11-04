
from dataclasses import replace

from security_agent.domain.remediation import RemediationPlan


class SecurityRemediationOrchestrator:
    def __init__(self, analyzer, planner, inspector):
        self.analyzer = analyzer
        self.planner = planner
        self.inspector = inspector

    def run(self, finding):
        inspection = self.inspector.inspect(finding)

        # Inspection errors always stop the workflow.
        if inspection.errors:
            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                f"Direct matches: {len(inspection.matches)}.\n"
                f"Inspection errors: {list(inspection.errors)}.\n"
                "No remediation plan was generated."
            )

        # No direct declaration means there is nothing safe to change.
        if not inspection.matches:
            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                "No direct dependency declarations were found.\n"
                "No remediation plan was generated."
            )

        # Multiple direct matches are actionable when there are no
        # inspection errors. Other inconsistent results remain blocked.
        if not inspection.is_consistent and len(inspection.matches) < 2:
            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                f"Direct matches: {len(inspection.matches)}.\n"
                "No remediation plan was generated."
            )

        plans = []

        # Analyze and plan each direct dependency declaration.
        for match in inspection.matches:
            module_finding = replace(
                finding,
                file=match.build_file,
            )

            analysis = self.analyzer.analyze(module_finding)

            plan = self.planner.create_plan(
                finding=module_finding,
                analysis=analysis,
            )

            plans.append(plan)

        # All module plans must recommend the same remediation type.
        remediation_types = {
            plan.remediation_type
            for plan in plans
        }

        if len(remediation_types) != 1:
            raise ValueError(
                "Modules produced conflicting remediation types. "
                "No combined remediation plan was generated."
            )

        # Collect changes from every module, avoiding duplicates.
        changes_by_key = {}

        for plan in plans:
            for change in plan.changes:
                key = (change.file, change.dependency)
                changes_by_key[key] = change

        changes = list(changes_by_key.values())

        # Combine validation steps without duplicates.
        validation_steps = list(
            dict.fromkeys(
                step
                for plan in plans
                for step in plan.validation_steps
            )
        )

        # Use the lowest confidence across all module plans.
        confidence_rank = {
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
        }

        confidence = min(
            (plan.confidence for plan in plans),
            key=lambda item: confidence_rank[item.value],
        )

        reasons = list(
            dict.fromkeys(plan.reason for plan in plans)
        )

        return RemediationPlan(
            finding_id=finding.id,
            remediation_type=plans[0].remediation_type,
            reason="; ".join(reasons),
            confidence=confidence,
            changes=changes,
            validation_steps=validation_steps,
        )
