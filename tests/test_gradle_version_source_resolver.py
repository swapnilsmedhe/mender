from unittest.mock import Mock

import pytest

from security_agent.application.gradle_version_source_resolver import (
    GradleVersionSourceResolver,
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
        current_version="2.23.0",
        fixed_versions=["2.24.0"],
        repository="/repo",
        file="build.gradle.kts",
    )


@pytest.fixture
def tools():
    return Mock()


@pytest.fixture
def resolver(tools):
    return GradleVersionSourceResolver(tools)


def test_resolves_inline_version(resolver, finding, tools):
    content = """
dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:2.23.0"
    )
}
"""

    evidence = resolver.resolve("app/build.gradle.kts", content, finding)

    assert evidence is not None
    assert evidence.source_type == "INLINE"
    assert evidence.value == "2.23.0"
    assert evidence.source_file == "app/build.gradle.kts"
    assert evidence.resolved is True
    tools.read_file.assert_not_called()


@pytest.mark.parametrize(
    ("declaration", "expected_scope"),
    [
        (
            'val jacksonVersion = rootProject.findProperty("jacksonVersion") as String',
            "ROOT_PROJECT",
        ),
        (
            'val jacksonVersion = project.findProperty("jacksonVersion") as String',
            "CURRENT_PROJECT",
        ),
        (
            "val jacksonVersion: String by project",
            "CURRENT_PROJECT",
        ),
        (
            "val jacksonVersion by project",
            "CURRENT_PROJECT",
        ),
    ],
)
def test_identifies_gradle_property_lookup(
    resolver,
    finding,
    declaration,
    expected_scope,
):
    content = f"""
{declaration}

dependencies {{
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
    )
}}
"""

    evidence = resolver.resolve("app/build.gradle.kts", content, finding)

    assert evidence is not None
    assert evidence.source_type == "GRADLE_PROJECT_PROPERTY"
    assert evidence.property_name == "jacksonVersion"
    assert evidence.lookup_scope == expected_scope

    # The resolver does not claim to know Gradle's effective property value.
    assert evidence.value is None
    assert evidence.source_file is None
    assert evidence.resolved is False


def test_supports_braced_property_interpolation(resolver, finding):
    content = """
val jacksonVersion: String by project

dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}"
    )
}
"""

    evidence = resolver.resolve("app/build.gradle.kts", content, finding)

    assert evidence is not None
    assert evidence.property_name == "jacksonVersion"
    assert evidence.lookup_scope == "CURRENT_PROJECT"


def test_returns_unknown_for_unrecognised_variable(resolver, finding):
    content = """
dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$version"
    )
}
"""

    evidence = resolver.resolve("app/build.gradle.kts", content, finding)

    assert evidence is not None
    assert evidence.source_type == "UNKNOWN"
    assert evidence.resolved is False


def test_ignores_different_dependency(resolver, finding):
    content = """
dependencies {
    implementation("org.example:some-library:1.0.0")
}
"""

    evidence = resolver.resolve("app/build.gradle.kts", content, finding)

    assert evidence is None


def test_matches_artifact_only_finding(resolver, finding):
    finding = SecurityFinding(
        id=finding.id,
        scanner=finding.scanner,
        severity=finding.severity,
        cve=finding.cve,
        component="jackson-databind",
        current_version=finding.current_version,
        fixed_versions=finding.fixed_versions,
        repository=finding.repository,
        file=finding.file,
    )

    content = """
dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:2.23.0"
    )
}
"""

    evidence = resolver.resolve("app/build.gradle.kts", content, finding)

    assert evidence is not None
    assert evidence.source_type == "INLINE"
