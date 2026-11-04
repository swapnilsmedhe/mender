
from types import SimpleNamespace

import pytest

from security_agent.application.module_discovery import GradleModule
from security_agent.application.repository_inspector import (
    RepositoryInspector,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)
from security_agent.tools.repository import RepositoryTools


@pytest.fixture
def finding():
    return SecurityFinding(
        id="LOCAL-FINDING-001",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2026-12345",
        component="jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="sample-repo",
        file="build.gradle",
    )


@pytest.fixture
def repository(tmp_path):
    (tmp_path / "gradlew").write_text(
        "#!/bin/sh\nexit 0\n",
        encoding="utf-8",
    )

    return RepositoryTools(tmp_path)


def make_module(
        project_path: str,
        directory: str,
        build_file: str | None,
) -> GradleModule:
    return GradleModule(
        name=project_path.split(":")[-1] or "root",
        project_path=project_path,
        directory=directory,
        build_file=build_file,
    )


def mock_gradle_output(monkeypatch, output=None):
    if output is None:
        output = (
            "jackson-databind\n"
            "com.fasterxml.jackson.core:jackson-databind:2.15.2"
        )

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=output,
            stderr="",
        )

    monkeypatch.setattr(
        "security_agent.application.repository_inspector.subprocess.run",
        fake_run,
    )


def test_identifies_direct_dependency(
        repository,
        finding,
        tmp_path,
        monkeypatch,
):
    build_file = tmp_path / "app" / "build.gradle"
    build_file.parent.mkdir(parents=True)
    build_file.write_text(
        """
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'
}
""",
        encoding="utf-8",
    )

    module = make_module(
        ":app",
        "app",
        "app/build.gradle",
    )

    inspector = RepositoryInspector(repository)
    inspector.discovery.discover = lambda: [module]

    mock_gradle_output(monkeypatch)

    result = inspector.inspect(finding)

    assert len(result.matches) == 1
    assert result.matches[0].project_path == ":app"
    assert result.matches[0].build_file == "app/build.gradle"
    assert result.transitive_matches == ()
    assert result.errors == ()
    assert result.is_consistent is True


def test_identifies_transitive_dependency(
        repository,
        finding,
        tmp_path,
        monkeypatch,
):
    build_file = tmp_path / "app" / "build.gradle"
    build_file.parent.mkdir(parents=True)
    build_file.write_text(
        """
dependencies {
    implementation 'com.example:another-library:1.0.0'
}
""",
        encoding="utf-8",
    )

    module = make_module(
        ":app",
        "app",
        "app/build.gradle",
    )

    inspector = RepositoryInspector(repository)
    inspector.discovery.discover = lambda: [module]

    mock_gradle_output(monkeypatch)

    result = inspector.inspect(finding)

    assert result.matches == ()
    assert len(result.transitive_matches) == 1
    assert result.transitive_matches[0].project_path == ":app"
    assert result.errors == ()
    assert result.is_consistent is False


def test_direct_and_transitive_modules_are_separated(
        repository,
        finding,
        tmp_path,
        monkeypatch,
):
    direct_file = tmp_path / "backend" / "payment" / "build.gradle"
    direct_file.parent.mkdir(parents=True)
    direct_file.write_text(
        """
dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
}
""",
        encoding="utf-8",
    )

    transitive_file = tmp_path / "backend" / "order" / "build.gradle"
    transitive_file.parent.mkdir(parents=True)
    transitive_file.write_text(
        """
dependencies {
    implementation 'com.example:another-library:1.0.0'
}
""",
        encoding="utf-8",
    )

    modules = [
        make_module(
            ":backend",
            "backend",
            None,
        ),
        make_module(
            ":backend:payment",
            "backend/payment",
            "backend/payment/build.gradle",
        ),
        make_module(
            ":backend:order",
            "backend/order",
            "backend/order/build.gradle",
        ),
    ]

    inspector = RepositoryInspector(repository)
    inspector.discovery.discover = lambda: modules

    mock_gradle_output(monkeypatch)

    result = inspector.inspect(finding)

    assert len(result.matches) == 1
    assert result.matches[0].project_path == ":backend:payment"

    assert len(result.transitive_matches) == 1
    assert (
            result.transitive_matches[0].project_path
            == ":backend:order"
    )

    assert result.errors == ()
    assert result.is_consistent is True


def test_multiple_direct_modules_are_not_consistent(
        repository,
        finding,
        tmp_path,
        monkeypatch,
):
    modules = []

    for project_path in (":backend:payment", ":backend:order"):
        relative_directory = project_path.replace(":", "/").strip("/")
        relative_file = f"{relative_directory}/build.gradle"

        build_file = tmp_path / relative_file
        build_file.parent.mkdir(parents=True, exist_ok=True)
        build_file.write_text(
            """
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'
}
""",
            encoding="utf-8",
        )

        modules.append(
            make_module(
                project_path,
                relative_directory,
                relative_file,
            )
        )

    inspector = RepositoryInspector(repository)
    inspector.discovery.discover = lambda: modules

    mock_gradle_output(monkeypatch)

    result = inspector.inspect(finding)

    assert len(result.matches) == 2
    assert result.transitive_matches == ()
    assert result.is_consistent is False


def test_skips_parent_projects_without_build_files(
        repository,
        finding,
        tmp_path,
        monkeypatch,
):
    build_file = tmp_path / "backend" / "payment" / "build.gradle"
    build_file.parent.mkdir(parents=True)
    build_file.write_text(
        """
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'
}
""",
        encoding="utf-8",
    )

    modules = [
        make_module(":backend", "backend", None),
        make_module(":backend:services", "backend/services", None),
        make_module(
            ":backend:services:payment",
            "backend/services/payment",
            "backend/payment/build.gradle",
        ),
    ]

    inspector = RepositoryInspector(repository)
    inspector.discovery.discover = lambda: modules

    mock_gradle_output(monkeypatch)

    result = inspector.inspect(finding)

    assert len(result.matches) == 1
    assert result.matches[0].project_path == (
        ":backend:services:payment"
    )
    assert result.errors == ()


def test_reports_no_build_files(
        repository,
        finding,
):
    modules = [
        make_module(":backend", "backend", None),
        make_module(":backend:services", "backend/services", None),
    ]

    inspector = RepositoryInspector(repository)
    inspector.discovery.discover = lambda: modules

    result = inspector.inspect(finding)

    assert result.matches == ()
    assert result.transitive_matches == ()
    assert result.is_consistent is False
    assert any(
        "No Gradle projects with existing build files"
        in error
        for error in result.errors
    )


def test_reports_gradle_inspection_failure(
        repository,
        finding,
        tmp_path,
        monkeypatch,
):
    build_file = tmp_path / "app" / "build.gradle"
    build_file.parent.mkdir(parents=True)
    build_file.write_text(
        "dependencies {}",
        encoding="utf-8",
    )

    module = make_module(
        ":app",
        "app",
        "app/build.gradle",
    )

    inspector = RepositoryInspector(repository)
    inspector.discovery.discover = lambda: [module]

    def failed_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Gradle task failed",
        )

    monkeypatch.setattr(
        "security_agent.application.repository_inspector.subprocess.run",
        failed_run,
    )

    result = inspector.inspect(finding)

    assert result.matches == ()
    assert result.transitive_matches == ()
    assert result.is_consistent is False
    assert any(
        "Gradle dependency inspection failed"
        in error
        for error in result.errors
    )


def test_supports_map_notation(
        finding,
):
    content = """
dependencies {
    implementation group: 'com.fasterxml.jackson.core',
        name: 'jackson-databind',
        version: '2.15.2'
}
"""

    assert RepositoryInspector._contains_direct_dependency(
        content,
        finding,
    )


def test_does_not_match_different_version(
        finding,
):
    content = """
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.17.3'
}
"""

    assert not RepositoryInspector._contains_direct_dependency(
        content,
        finding,
    )
