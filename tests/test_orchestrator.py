
import pytest
from unittest.mock import Mock

from security_agent.application.orchestrator import (
    SecurityRemediationOrchestrator,
)
from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspection,
)
from security_agent.domain.analysis import Confidence, RemediationType
from security_agent.domain.finding import Scanner, SecurityFinding, Severity
from security_agent.domain.remediation import RemediationPlan


def make_finding():
    return SecurityFinding(
        id="BD-12345",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2026-12345",
        component="jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="sample-repo",
        file="old/path/build.gradle",
    )


def make_inspection(
        is_consistent=True,
        matches=None,
        errors=(),
):
    if matches is None and is_consistent:
        matches = (
            ModuleMatch(
                project_path=":app",
                build_file="app/build.gradle",
                command_output="jackson-databind:2.15.2",
            ),
        )

    return RepositoryInspection(
        finding_id="BD-12345",
        configuration="runtimeClasspath",
        command_output="Gradle dependency inspection output",
        is_consistent=is_consistent,
        matches=tuple(matches or ()),
        errors=tuple(errors),
    )


@pytest.fixture
def orchestrator():
    analyzer = Mock()
    planner = Mock()
    inspector = Mock()

    analyzer.analyze.return_value = Mock(
        finding_id="BD-12345",
        root_cause="Vulnerable dependency version",
        recommended_action=RemediationType.VERSION_UPGRADE,
        target_version="2.17.3",
        confidence=Confidence.HIGH,
    )

    planner.create_plan.return_value = RemediationPlan(
        finding_id="BD-12345",
        remediation_type=RemediationType.VERSION_UPGRADE,
        reason="Upgrade vulnerable dependency",
        confidence=Confidence.HIGH,
    )

    inspector.inspect.return_value = make_inspection()

    return SecurityRemediationOrchestrator(
        analyzer=analyzer,
        planner=planner,
        inspector=inspector,
    )


def test_successful_orchestration(orchestrator):
    finding = make_finding()

    result = orchestrator.run(finding)

    assert result.finding_id == "BD-12345"

    orchestrator.inspector.inspect.assert_called_once_with(finding)
    orchestrator.analyzer.analyze.assert_called_once()

    analyzed_finding = orchestrator.analyzer.analyze.call_args.args[0]
    assert analyzed_finding.file == "app/build.gradle"

    orchestrator.planner.create_plan.assert_called_once()


def test_inconsistent_inspection_stops_workflow(orchestrator):
    orchestrator.inspector.inspect.return_value = make_inspection(
        is_consistent=False,
        matches=(),
    )

    with pytest.raises(
            ValueError,
            match="Repository evidence is not conclusive",
    ):
        orchestrator.run(make_finding())

    orchestrator.analyzer.analyze.assert_not_called()
    orchestrator.planner.create_plan.assert_not_called()


def test_planner_error_is_propagated(orchestrator):
    orchestrator.planner.create_plan.side_effect = RuntimeError(
        "Planner failed"
    )

    with pytest.raises(RuntimeError, match="Planner failed"):
        orchestrator.run(make_finding())

    orchestrator.analyzer.analyze.assert_called_once()
    orchestrator.planner.create_plan.assert_called_once()


def test_multiple_matching_modules_stop_workflow(orchestrator):
    matches = (
        ModuleMatch(
            project_path=":app",
            build_file="app/build.gradle",
            command_output="jackson-databind:2.15.2",
        ),
        ModuleMatch(
            project_path=":backend",
            build_file="backend/build.gradle",
            command_output="jackson-databind:2.15.2",
        ),
    )

    orchestrator.inspector.inspect.return_value = make_inspection(
        is_consistent=False,
        matches=matches,
    )

    with pytest.raises(
            ValueError,
            match="Repository evidence is not conclusive",
    ):
        orchestrator.run(make_finding())

    orchestrator.analyzer.analyze.assert_not_called()
    orchestrator.planner.create_plan.assert_not_called()


def test_inspection_errors_stop_workflow(orchestrator):
    orchestrator.inspector.inspect.return_value = make_inspection(
        is_consistent=False,
        errors=("Gradle inspection timed out",),
    )

    with pytest.raises(
            ValueError,
            match="Gradle inspection timed out",
    ):
        orchestrator.run(make_finding())

    orchestrator.analyzer.analyze.assert_not_called()
    orchestrator.planner.create_plan.assert_not_called()
