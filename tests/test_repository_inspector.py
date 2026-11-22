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

        assert (
            RepositoryInspector._extract_resolved_version(
                output,
                finding,
            )
            == "2.15.2"
        )

    def test_uses_selected_version_after_gradle_conflict_resolution(
        self,
        finding,
    ):
        output = """
com.fasterxml.jackson.core:jackson-databind:2.15.2 -> 2.17.3
"""

        assert (
            RepositoryInspector._extract_resolved_version(
                output,
                finding,
            )
            == "2.17.3"
        )

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


def test_multiple_direct_matches_are_consistent_when_no_errors(
    finding,
):
    from security_agent.application.repository_inspector import (
        RepositoryInspection,
    )

    match_one = ModuleMatch(
        project_path=":service",
        build_file="service/build.gradle.kts",
        command_output="Jackson 2.15.2",
        resolved_version="2.15.2",
    )

    match_two = ModuleMatch(
        project_path=":direct-consumer",
        build_file="direct-consumer/build.gradle.kts",
        command_output="Jackson 2.15.2",
        resolved_version="2.15.2",
    )

    inspection = RepositoryInspection(
        finding_id=finding.id,
        configuration="runtimeClasspath",
        command_output="Gradle output",
        is_consistent=True,
        matches=(match_one, match_two),
    )

    assert inspection.is_consistent
    assert len(inspection.matches) == 2
    assert not inspection.errors


from security_agent.application.module_discovery import GradleModule
from security_agent.application.gradle_dependency_report import (
    GradleDependencyEdge,
    GradleDependencyReport,
)


def create_report_edge(
    project: str,
    source: str,
    selected: str,
    *,
    constraint: bool = False,
) -> GradleDependencyEdge:
    return GradleDependencyEdge(
        project_path=project,
        configuration="runtimeClasspath",
        from_component=source,
        requested=selected,
        selected=selected,
        is_constraint=constraint,
        status="RESOLVED",
    )


def create_module(
    project_path: str,
) -> GradleModule:
    name = project_path.split(":")[-1]

    return GradleModule(
        name=name,
        project_path=project_path,
        directory=name,
        build_file=f"{name}/build.gradle.kts",
        configurations=("runtimeClasspath",),
    )


def configure_inspector(
    inspector,
    modules,
    report,
):
    inspector.discovery.discover = lambda: modules
    inspector.report_collector.collect = lambda configuration: report


def test_inspector_finds_direct_dependency(
    finding,
):
    module = create_module(":service")

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_report_edge(
                ":service",
                "project :service",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
        ),
    )

    inspector = RepositoryInspector(
        tools=None,
    )

    configure_inspector(inspector, [module], report)

    inspection = inspector.inspect(finding)

    assert inspection.is_consistent
    assert len(inspection.matches) == 1
    assert inspection.transitive_matches == ()

    assert inspection.matches[0].dependency_paths == (
        ("com.fasterxml.jackson.core:jackson-databind:2.15.2",),
    )


def test_inspector_finds_transitive_dependency(
    finding,
):
    module = create_module(":integration")

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_report_edge(
                ":integration",
                "project :integration",
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            ),
            create_report_edge(
                ":integration",
                "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
        ),
    )

    inspector = RepositoryInspector(tools=None)
    configure_inspector(inspector, [module], report)

    inspection = inspector.inspect(finding)

    assert inspection.is_consistent
    assert inspection.matches == ()
    assert len(inspection.transitive_matches) == 1

    assert inspection.transitive_matches[0].dependency_paths == (
        (
            "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4",
            "com.fasterxml.jackson.core:jackson-databind:2.15.2",
        ),
    )


def test_inspector_preserves_direct_and_transitive_paths_in_same_module(
    finding,
):
    module = create_module(":bom-consumer")

    databind = "com.fasterxml.jackson.core:jackson-databind:2.15.2"
    jsr310 = "com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4"
    bom = "com.fasterxml.jackson:jackson-bom:2.13.4"

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_report_edge(
                ":bom-consumer",
                "project :bom-consumer",
                databind,
            ),
            create_report_edge(
                ":bom-consumer",
                "project :bom-consumer",
                jsr310,
            ),
            create_report_edge(
                ":bom-consumer",
                jsr310,
                databind,
            ),
            create_report_edge(
                ":bom-consumer",
                "project :bom-consumer",
                bom,
            ),
            create_report_edge(
                ":bom-consumer",
                bom,
                databind,
                constraint=True,
            ),
        ),
    )

    inspector = RepositoryInspector(tools=None)
    configure_inspector(inspector, [module], report)

    inspection = inspector.inspect(finding)

    assert inspection.is_consistent
    assert len(inspection.matches) == 1
    assert len(inspection.transitive_matches) == 1

    assert inspection.matches[0].dependency_paths == ((databind,),)

    assert inspection.transitive_matches[0].dependency_paths == ((jsr310, databind),)


def test_inspector_ignores_fixed_resolved_version(
    finding,
):
    module = create_module(":service")

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_report_edge(
                ":service",
                "project :service",
                "com.fasterxml.jackson.core:jackson-databind:2.17.3",
            ),
        ),
    )

    inspector = RepositoryInspector(tools=None)
    configure_inspector(inspector, [module], report)

    inspection = inspector.inspect(finding)

    assert not inspection.matches
    assert not inspection.transitive_matches
    assert not inspection.is_consistent


def test_inspector_preserves_report_errors(
    finding,
):
    module = create_module(":service")

    report = GradleDependencyReport(
        configuration="runtimeClasspath",
        edges=(
            create_report_edge(
                ":service",
                "project :service",
                "com.fasterxml.jackson.core:jackson-databind:2.15.2",
            ),
        ),
        errors=(":integration (runtimeClasspath): resolution failed",),
    )

    inspector = RepositoryInspector(tools=None)
    configure_inspector(inspector, [module], report)

    inspection = inspector.inspect(finding)

    assert len(inspection.matches) == 1
    assert not inspection.is_consistent
    assert inspection.errors == (":integration (runtimeClasspath): resolution failed",)
