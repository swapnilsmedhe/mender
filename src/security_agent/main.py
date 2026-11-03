import argparse
from pathlib import Path

from security_agent.application.analyzer import FindingAnalyzer
from security_agent.application.change_preview import ChangePreviewEngine
from security_agent.application.orchestrator import (
    SecurityRemediationOrchestrator,
)
from security_agent.application.planner import RemediationPlanner
from security_agent.application.repository_inspector import (
    RepositoryInspector,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)
from security_agent.tools.repository import RepositoryTools


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect a repository for a security finding."
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Path to the target repository.",
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Dependency declaration file relative to the repository root.",
    )
    parser.add_argument(
        "--component",
        required=True,
        help="Affected dependency name, e.g. jackson-databind.",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Currently vulnerable version.",
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="CVE identifier.",
    )
    parser.add_argument(
        "--fixed-version",
        action="append",
        default=[],
        help="A scanner-reported fixed version. Repeat to supply alternatives.",
    )
    parser.add_argument(
        "--finding-id",
        default="LOCAL-FINDING-001",
        help="Finding identifier.",
    )
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Finding severity.",
    )
    parser.add_argument(
        "--configuration",
        default="runtimeClasspath",
        help="Gradle configuration to inspect.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repository_root = Path(args.repo).expanduser().resolve()

    try:
        # Create one shared repository tools instance.
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

        # Generate the remediation plan.
        orchestrator = SecurityRemediationOrchestrator(
            analyzer=FindingAnalyzer(),
            planner=RemediationPlanner(),
            inspector=RepositoryInspector(
                tools,
                configuration=args.configuration,
            ),
        )

        plan = orchestrator.run(finding)

        # Generate a read-only change preview.
        preview_engine = ChangePreviewEngine(tools)
        previews = preview_engine.create_preview(plan)

    except (ValueError, FileNotFoundError, OSError, RuntimeError) as exc:
        print(f"Inspection failed: {exc}")
        print("No remediation plan or preview was generated.")
        return 1

    # Display finding information.
    print("Security Remediation Agent")
    print("=" * 32)
    print(f"Repository: {repository_root}")
    print(f"Finding: {finding.id}")
    print(f"CVE: {finding.cve}")
    print(f"Severity: {finding.severity.value}")
    print(f"Component: {finding.component}")
    print(f"Current version: {finding.current_version}")
    print(f"Dependency file: {finding.file}")

    # Display remediation plan.
    print("\nRemediation plan")
    print(f"Action: {plan.remediation_type.value}")
    print(f"Reason: {plan.reason}")
    print(f"Confidence: {plan.confidence.value}")

    if plan.changes:
        for change in plan.changes:
            print(f"\nFile: {change.file}")
            print(f"Dependency: {change.dependency}")
            print(
                f"Version: {change.current_version}"
                f" -> {change.target_version}"
            )
    else:
        print("No automatic changes proposed.")

    # Display change previews.
    print("\nChange Preview")
    print("=" * 32)

    if not previews:
        print("No file changes require a preview.")
    else:
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

    # Display validation steps.
    if plan.validation_steps:
        print("\nProposed validation steps")
        for step in plan.validation_steps:
            print(f"- {step}")

    print("\nExecution status")
    print("Preview completed; no files were modified.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())