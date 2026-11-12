from dataclasses import replace

from security_agent.domain.analysis import RemediationType
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
                f"Transitive matches: "
                f"{len(inspection.transitive_matches)}.\n"
                f"Inspection errors: {list(inspection.errors)}.\n"
                "No remediation plan was generated."
            )

        # There must be at least one direct or transitive match.
        if not inspection.matches and not inspection.transitive_matches:
            raise ValueError(
                f"Repository evidence is not conclusive for finding "
                f"{finding.id}.\n"
                "No direct or transitive dependency matches were found.\n"
                "No remediation plan was generated."
            )

        # Preserve the existing consistency check for direct matches.
        # A transitive-only inspection can legitimately have no direct
        # matches and is_consistent=False.
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

        plans = []

        module_matches = [
                             (match, False)
                             for match in inspection.matches
                         ] + [
                             (match, True)
                             for match in inspection.transitive_matches
                         ]

        for match, is_transitive in module_matches:
            module_finding = replace(
                finding,
                file=match.build_file,
            )

            analysis = self.analyzer.analyze(module_finding)

            if is_transitive:
                plan = self.planner.create_plan(
                    finding=module_finding,
                    analysis=analysis,
                    is_transitive=True,
                    dependency_paths=match.dependency_paths,
                )
            else:
                # Preserve the existing planner call for direct matches.
                plan = self.planner.create_plan(
                    finding=module_finding,
                    analysis=analysis,
                )

            plans.append(plan)

        # If any affected module cannot be remediated automatically,
        # do not return a partial automatic upgrade for other modules.
        if any(
                plan.remediation_type
                == RemediationType.NO_AUTOMATIC_REMEDIATION
                for plan in plans
        ):
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
                remediation_type=(
                    RemediationType.NO_AUTOMATIC_REMEDIATION
                ),
                reason="; ".join(reasons),
                confidence=confidence,
                changes=[],
                validation_steps=[],
            )

        # All remaining module plans must recommend the same action.
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
