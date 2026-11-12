
import pytest

from security_agent.application.repository_inspector import (
    ModuleMatch,
    RepositoryInspector,
)
from security_agent.domain.finding import (
    Scanner,
    SecurityFinding,
    Severity,
)


@pytest.fixture
def finding():
    return SecurityFinding(
        id="finding-1",
        scanner=Scanner.BLACK_DUCK,
        severity=Severity.HIGH,
        cve="CVE-2024-0001",
        component="com.fasterxml.jackson.core:jackson-databind",
        current_version="2.15.2",
        fixed_versions=["2.17.3"],
        repository="/repo",
        file="build.gradle",
    )


class TestResolvedDependencyVersion:
    def test_extracts_resolved_version(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.2
"""

        assert RepositoryInspector._contains_finding(
            output,
            finding,
        )

        assert RepositoryInspector._extract_resolved_version(
            output,
            finding,
        ) == "2.15.2"

    def test_uses_selected_version_after_gradle_conflict_resolution(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.2 -> 2.17.3
"""

        assert RepositoryInspector._extract_resolved_version(
            output,
            finding,
        ) == "2.17.3"

    def test_does_not_report_finding_when_gradle_selected_a_fixed_version(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.2 -> 2.17.3
"""

        assert not RepositoryInspector._contains_finding(
            output,
            finding,
        )

    def test_does_not_match_a_different_resolved_version(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.3
"""

        assert not RepositoryInspector._contains_finding(
            output,
            finding,
        )


class TestDependencyPathExtraction:
    def test_extracts_transitive_dependency_path(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.2
  Selection reasons:
  \\--- org.springframework.boot:spring-boot-starter-json:3.2.1
       \\--- org.springframework.boot:spring-boot-starter-web:3.2.1
"""

        paths = RepositoryInspector._extract_dependency_paths(
            output,
            finding,
        )

        assert paths == (
            (
                "org.springframework.boot:spring-boot-starter-web:3.2.1",
                "org.springframework.boot:spring-boot-starter-json:3.2.1",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
        )

    def test_extracts_multiple_dependency_paths(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.2
  +--- org.springframework.boot:spring-boot-starter-json:3.2.1
  |    \\--- org.springframework.boot:spring-boot-starter-web:3.2.1
  \\--- com.example:legacy-client:1.4.0
"""

        paths = RepositoryInspector._extract_dependency_paths(
            output,
            finding,
        )

        assert paths == (
            (
                "org.springframework.boot:spring-boot-starter-web:3.2.1",
                "org.springframework.boot:spring-boot-starter-json:3.2.1",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
            (
                "com.example:legacy-client:1.4.0",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
        )

    def test_returns_empty_paths_when_gradle_does_not_report_a_tree(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.2
"""

        paths = RepositoryInspector._extract_dependency_paths(
            output,
            finding,
        )

        assert paths == ()

    def test_ignores_paths_for_a_different_resolved_version(
            self,
            finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.17.3
  \\--- org.springframework.boot:spring-boot-starter-web:3.2.1
"""

        paths = RepositoryInspector._extract_dependency_paths(
            output,
            finding,
        )

        assert paths == ()


class TestModuleMatchStructuredInformation:
    def test_exposes_first_dependency_path(self):
        match = ModuleMatch(
            project_path=":app",
            build_file="app/build.gradle",
            command_output="Gradle output",
            resolved_version="2.15.2",
            dependency_paths=(
                (
                    "org.springframework.boot:spring-boot-starter-web:3.2.1",
                    "com.fasterxml.jackson.core:jackson-databind:2.15.2",
                ),
                (
                    "com.example:legacy-client:1.4.0",
                    "com.fasterxml.jackson.core:jackson-databind:2.15.2",
                ),
            ),
        )

        assert match.resolved_version == "2.15.2"

        assert match.dependency_path == (
            "org.springframework.boot:spring-boot-starter-web:3.2.1",
            "com.fasterxml.jackson.core:jackson-databind:2.15.2",
        )

    def test_identifies_introducing_dependency(self):
        match = ModuleMatch(
            project_path=":app",
            build_file="app/build.gradle",
            command_output="Gradle output",
            resolved_version="2.15.2",
            dependency_paths=(
                (
                    "org.springframework.boot:spring-boot-starter-web:3.2.1",
                    "org.springframework.boot:spring-boot-starter-json:3.2.1",
                    "com.fasterxml.jackson.core:jackson-databind:2.15.2",
                ),
            ),
        )

        assert match.introducing_dependency == (
            "org.springframework.boot:spring-boot-starter-web:3.2.1"
        )

    def test_introducing_dependency_is_none_without_a_parent(self):
        match = ModuleMatch(
            project_path=":app",
            build_file="app/build.gradle",
            command_output="Gradle output",
        )

        assert match.dependency_path == ()
        assert match.introducing_dependency is None

    def test_preserves_existing_module_match_construction(self):
        match = ModuleMatch(
            project_path=":app",
            build_file="app/build.gradle",
            command_output="Gradle output",
        )

        assert match.resolved_version is None
        assert match.dependency_paths == ()
