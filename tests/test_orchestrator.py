from unittest.mock import Mock

import pytest

from security_agent.application.orchestrator import (
    SecurityRemediationOrchestrator,
)
from security_agent.application.repository_inspector import (
    RepositoryInspection,
)
from security_agent.domain.analysis import (
    Confidence,
    FindingAnalysis,
    RemediationType,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)
from security_agent.domain.remediation import (
    FileChange,
    RemediationPlan,
)


@pytest.fixture
def finding():
    return SecurityFinding(
        id="BD-12345",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2026-12345",
        component="jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="sample-repo",
        file="gradle/libs.versions.toml",
    )


@pytest.fixture
def successful_inspection():
    return RepositoryInspection(
        finding_id="BD-12345",
        configuration="runtimeClasspath",
        command_output="jackson-databind:2.15.2",
        is_consistent=True,
    )


@pytest.fixture
def orchestrator():
    analyzer = Mock()
    planner = Mock()
    inspector = Mock()

    return SecurityRemediationOrchestrator(
        analyzer=analyzer,
        planner=planner,
        inspector=inspector,
    ), analyzer, planner, inspector


def test_successful_orchestration(
        finding,
        successful_inspection,
        orchestrator,
):
    service, analyzer, planner, inspector = orchestrator

    analysis = FindingAnalysis(
        finding_id=finding.id,
        root_cause="Vulnerable dependency version",
        recommended_action=RemediationType.VERSION_UPGRADE,
        target_version="2.17.3",
        confidence=Confidence.HIGH,
    )

    expected_plan = RemediationPlan(
        finding_id=finding.id,
        remediation_type=RemediationType.VERSION_UPGRADE,
        reason="Upgrade vulnerable dependency",
        confidence=Confidence.HIGH,
        changes=[
            FileChange(
                file=finding.file,
                dependency=finding.component,
                current_version=finding.current_version,
                target_version="2.17.3",
            )
        ],
    )

    inspector.inspect.return_value = successful_inspection
    analyzer.analyze.return_value = analysis
    planner.create_plan.return_value = expected_plan

    result = service.run(finding)

    assert result == expected_plan
    inspector.inspect.assert_called_once_with(finding)
    analyzer.analyze.assert_called_once_with(finding)
    planner.create_plan.assert_called_once_with(
        finding=finding,
        analysis=analysis,
    )


def test_inconsistent_inspection_stops_workflow(
        finding,
        orchestrator,
):
    service, analyzer, planner, inspector = orchestrator

    inspector.inspect.return_value = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="Dependency not found",
        is_consistent=False,
    )

    with pytest.raises(
            ValueError,
            match="Repository evidence does not match",
    ):
        service.run(finding)

    analyzer.analyze.assert_not_called()
    planner.create_plan.assert_not_called()


def test_inspection_exception_stops_workflow(
        finding,
        orchestrator,
):
    service, analyzer, planner, inspector = orchestrator

    inspector.inspect.side_effect = RuntimeError(
        "Gradle inspection failed"
    )

    with pytest.raises(RuntimeError, match="Gradle inspection failed"):
        service.run(finding)

    analyzer.analyze.assert_not_called()
    planner.create_plan.assert_not_called()


def test_planner_error_is_propagated(
        finding,
        successful_inspection,
        orchestrator,
):
    service, analyzer, planner, inspector = orchestrator

    analysis = FindingAnalysis(
        finding_id=finding.id,
        root_cause="Vulnerable dependency version",
        recommended_action=RemediationType.VERSION_UPGRADE,
        target_version="2.17.3",
        confidence=Confidence.HIGH,
    )

    inspector.inspect.return_value = successful_inspection
    analyzer.analyze.return_value = analysis
    planner.create_plan.side_effect = ValueError(
        "Invalid remediation target"
    )

    with pytest.raises(ValueError, match="Invalid remediation target"):
        service.run(finding)

    analyzer.analyze.assert_called_once_with(finding)
    planner.create_plan.assert_called_once()
