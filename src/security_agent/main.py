import argparse
from pathlib import Path

from security_agent.application.ai_analysis_policy import AIAnalysisPolicy
from security_agent.application.ai_recommendation_service import AIRecommendationService
from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.change_preview import ChangePreviewEngine
from security_agent.application.constraint_aware_context_builder import (
    ConstraintAwareAIRecommendationContextBuilder,
)
from security_agent.application.constraint_aware_repository_inspector import (
    ConstraintAwareRepositoryInspector,
)
from security_agent.application.effective_property_inspector import (
    EffectiveGradlePropertyInspector,
)
from security_agent.application.gradle_bom_candidate_inspector import (
    GradleBomCandidateCollector,
    GradleBomCandidateInspector,
)
from security_agent.application.gradle_property_collector import GradlePropertyCollector
from security_agent.application.orchestrator import SecurityRemediationOrchestrator
from security_agent.application.planner import RemediationPlanner
from security_agent.application.repository_inspector import RepositoryInspector
from security_agent.domain.finding import Scanner, SecurityFinding, Severity
from security_agent.infrastructure.ai.constraint_aware_copilot_provider import (
    ConstraintAwareCopilotRecommendationProvider,
)
from security_agent.tools.repository import RepositoryTools


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect a repository for a security finding.")
    parser.add_argument("--repo", required=True, help="Path to the target repository.")
    parser.add_argument("--file", required=True, help="Dependency declaration file relative to the repository root.")
    parser.add_argument("--component", required=True, help="Affected dependency name, e.g. jackson-databind.")
    parser.add_argument("--version", required=True, help="Currently vulnerable version.")
    parser.add_argument("--cve", required=True, help="CVE identifier.")
    parser.add_argument("--fixed-version", action="append", default=[], help="A scanner-reported fixed version. Repeat to supply alternatives.")
    parser.add_argument("--finding-id", default="LOCAL-FINDING-001", help="Finding identifier.")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH", help="Finding severity.")
    parser.add_argument("--configuration", default="runtimeClasspath", help="Gradle configuration to inspect.")
    parser.add_argument("--ai", action="store_true", help="Enable GitHub Copilot remediation analysis.")
    parser.add_argument("--ai-model", default="auto", help="GitHub Copilot model to use. Defaults to auto.")
    parser.add_argument("--ai-timeout", type=float, default=120, help="Maximum Copilot request duration in seconds.")
    return parser.parse_args()


def print_finding(finding: SecurityFinding, repository_root: Path) -> None:
    print("\nSecurity Finding")
    print("=" * 40)
    print(f"Repository: {repository_root}")
    print(f"Finding: {finding.id}")
    print(f"CVE: {finding.cve}")
    print(f"Severity: {finding.severity.value}")
    print(f"Component: {finding.component}")
    print(f"Current version: {finding.current_version}")
    print(f"Fixed versions: {finding.fixed_versions}")
    print(f"Dependency file: {finding.file}")


def print_remediation_plan(plan) -> None:
    print("\nDeterministic Remediation Plan")
    print("=" * 40)
    print(f"Action: {plan.remediation_type.value}")
    print(f"Reason: {plan.reason}")
    print(f"Confidence: {plan.confidence.value}")
    if not plan.changes:
        print("No automatic changes proposed.")
    else:
        for change in plan.changes:
            print(f"\nFile: {change.file}")
            print(f"Dependency: {change.dependency}")
            print(f"Version: {change.current_version} -> {change.target_version}")
    print(f"\nManual review required: {plan.requires_manual_review}")
    if plan.manual_review_reasons:
        print("Manual review items:")
        for reason in plan.manual_review_reasons:
            print(f"- {reason}")
    if plan.validation_steps:
        print("\nValidation steps:")
        for step in plan.validation_steps:
            print(f"- {step}")


def print_ai_recommendations(orchestrator) -> None:
    print("\nGitHub Copilot Analysis")
    print("=" * 40)
    outcomes = orchestrator.ai_recommendation_outcomes
    if not outcomes:
        print("Copilot analysis was not requested.")
        return
    for index, outcome in enumerate(outcomes, start=1):
        print(f"\nAnalysis {index}")
        print(f"AI analysis decision: {outcome.decision.reason.value}")
        if outcome.error:
            print(f"AI analysis error: {outcome.error}")
            continue
        if outcome.result is None:
            print("Copilot analysis was not required.")
            continue
        result = outcome.result
        print(f"Provider: {result.provider}")
        print(f"Model: {result.model}")
        print(f"Summary: {result.summary}")
        if not result.recommendations:
            print("No remediation recommendations returned.")
            continue
        for recommendation in result.recommendations:
            print(f"\nRecommendation: {recommendation.title}")
            print(f"Type: {recommendation.recommendation_type.value}")
            print(f"Description: {recommendation.description}")
            print(f"Rationale: {recommendation.rationale}")
            print(f"Confidence: {recommendation.confidence.value}")
            if recommendation.target_dependency:
                print(f"Target dependency: {recommendation.target_dependency}")
            if recommendation.target_version:
                print(f"Target version: {recommendation.target_version}")
            if recommendation.compatibility_notes:
                print("Compatibility notes:")
                for note in recommendation.compatibility_notes:
                    print(f"- {note}")
            if recommendation.risks:
                print("Risks:")
                for risk in recommendation.risks:
                    print(f"- {risk.level.value}: {risk.description}")
            print(f"Manual review required: {recommendation.requires_manual_review}")


def print_previews(previews) -> None:
    print("\nChange Preview")
    print("=" * 40)
    if not previews:
        print("No file changes require a preview.")
        return
    for preview in previews:
        print(f"\nFile: {preview.file}")
        print(f"Dependency: {preview.dependency}")
        print(f"Status: {preview.status.value}")
        print(f"Message: {preview.message}")
        if preview.diff:
            print("\nProposed diff:")
            print(preview.diff)
        else:
            print("No diff generated.")


def main() -> int:
    args = parse_args()
    repository_root = Path(args.repo).expanduser().resolve()
    if args.ai_timeout <= 0:
        print("AI timeout must be greater than zero.")
        return 1

    try:
        tools = RepositoryTools(repository_root)
        finding = SecurityFinding(
            id=args.finding_id,
            scanner=Scanner.BLACK_DUCK,
            severity=Severity[args.severity],
            cve=args.cve,
            component=args.component,
            current_version=args.version,
            fixed_versions=args.fixed_version,
            repository=repository_root.name,
            file=args.file,
        )
        base_inspector = RepositoryInspector(tools, configuration=args.configuration)
        constraint_inspector = ConstraintAwareRepositoryInspector(base_inspector)
        effective_inspector = EffectiveGradlePropertyInspector(
            constraint_inspector, GradlePropertyCollector(tools)
        )

        inspector = effective_inspector
        if args.ai:
            inspector = GradleBomCandidateInspector(
                effective_inspector, GradleBomCandidateCollector(tools)
            )

        ai_service = None
        if args.ai:
            provider = ConstraintAwareCopilotRecommendationProvider(
                model=args.ai_model, timeout_seconds=args.ai_timeout
            )
            ai_service = AIRecommendationService(
                policy=AIAnalysisPolicy(),
                provider=provider,
                context_builder=ConstraintAwareAIRecommendationContextBuilder(),
            )

        orchestrator = SecurityRemediationOrchestrator(
            analyzer=FindingAnalyzer(),
            planner=RemediationPlanner(),
            inspector=inspector,
            ai_recommendation_service=ai_service,
            force_ai=args.ai,
        )
        plan = orchestrator.run(finding)
        previews = ChangePreviewEngine(tools).create_preview(plan)

    except (ValueError, FileNotFoundError, OSError, RuntimeError) as exc:
        print(f"\nInspection failed: {exc}")
        print("No remediation changes were applied.")
        return 1

    print("\nMender - Security Remediation Agent")
    print("=" * 40)
    print_finding(finding, repository_root)
    print_remediation_plan(plan)
    if args.ai:
        print_ai_recommendations(orchestrator)
    print_previews(previews)
    print("\nExecution Status")
    print("=" * 40)
    print("Analysis and preview completed.")
    print("No repository files were modified.")
    print("No build or security rescan was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
