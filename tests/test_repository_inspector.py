
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from security_agent.application.repository_inspector import (
    RepositoryInspector,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)
from security_agent.tools.repository import RepositoryTools


def make_finding() -> SecurityFinding:
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
def inspector(tmp_path: Path) -> RepositoryInspector:
    # The inspector checks for the Gradle wrapper's existence.
    wrapper = tmp_path / "gradlew"
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")

    return RepositoryInspector(
        tools=RepositoryTools(tmp_path),
        configuration="runtimeClasspath",
    )


def test_inspector_verifies_dependency(inspector):
    gradle_output = """
    com.fasterxml.jackson.core:jackson-databind:2.15.2
    """

    with patch(
        "security_agent.application.repository_inspector.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=gradle_output,
            stderr="",
        )

        result = inspector.inspect(make_finding())

    assert result.finding_id == "BD-12345"
    assert result.configuration == "runtimeClasspath"
    assert result.is_consistent is True


def test_inspector_rejects_missing_dependency(inspector):
    gradle_output = """
    com.fasterxml.jackson.core:jackson-databind:2.16.0
    """

    with patch(
        "security_agent.application.repository_inspector.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=gradle_output,
            stderr="",
        )

        result = inspector.inspect(make_finding())

    assert result.is_consistent is False


def test_inspector_uses_gradle_dependency_insight(inspector):
    with patch(
        "security_agent.application.repository_inspector.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="jackson-databind:2.15.2",
            stderr="",
        )

        inspector.inspect(make_finding())

        command = mock_run.call_args.kwargs.get("args")
        if command is None:
            command = mock_run.call_args.args[0]

        assert "dependencyInsight" in command
        assert "--dependency" in command
        assert "jackson-databind" in command
        assert "--configuration" in command
        assert "runtimeClasspath" in command


def test_inspector_raises_when_gradle_fails(inspector):
    with patch(
        "security_agent.application.repository_inspector.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Gradle build failed",
        )

        with pytest.raises(RuntimeError, match="Gradle dependency inspection failed"):
            inspector.inspect(make_finding())


def test_inspector_raises_when_gradle_times_out(inspector):
    with patch(
        "security_agent.application.repository_inspector.subprocess.run"
    ) as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="gradlew",
            timeout=120,
        )

        with pytest.raises(RuntimeError, match="timed out"):
            inspector.inspect(make_finding())


def test_inspector_raises_when_gradle_wrapper_missing(
    tmp_path: Path,
):
    inspector = RepositoryInspector(
        tools=RepositoryTools(tmp_path),
    )

    with pytest.raises(FileNotFoundError, match="Gradle wrapper not found"):
        inspector.inspect(make_finding())
