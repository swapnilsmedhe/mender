from pathlib import Path

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
        file="build.gradle.kts",
    )


def test_inspector_finds_component_and_version(
    tmp_path: Path,
) -> None:
    (tmp_path / "build.gradle.kts").write_text(
        'implementation("com.example:jackson-databind:2.15.2")\n',
        encoding="utf-8",
    )

    inspector = RepositoryInspector(RepositoryTools(tmp_path))

    result = inspector.inspect(make_finding())

    assert result.finding_id == "BD-12345"
    assert result.is_consistent
    assert result.inspected_file == "build.gradle.kts"


def test_inspector_detects_missing_component(
    tmp_path: Path,
) -> None:
    (tmp_path / "build.gradle.kts").write_text(
        'implementation("com.example:other-library:2.15.2")\n',
        encoding="utf-8",
    )

    inspector = RepositoryInspector(RepositoryTools(tmp_path))

    result = inspector.inspect(make_finding())

    assert not result.component_matches
    assert not result.is_consistent


def test_inspector_rejects_missing_finding_file(
    tmp_path: Path,
) -> None:
    inspector = RepositoryInspector(RepositoryTools(tmp_path))

    try:
        inspector.inspect(make_finding())
        assert False, "Expected missing-file error"
    except ValueError as exc:
        assert "regular file" in str(exc)
