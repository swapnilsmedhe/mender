
from pathlib import Path
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
    repository = Mock()
    repository.read_file.return_value = "jacksonVersion=2.23.0\n"
    return repository


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

    evidence = resolver.resolve(
        "app/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is not None
    assert evidence.source_type == "INLINE"
    assert evidence.value == "2.23.0"
    assert evidence.source_file == "app/build.gradle.kts"
    assert evidence.resolved is True
    tools.read_file.assert_not_called()


def test_resolves_root_gradle_property(resolver, finding, tools):
    content = """
val jacksonVersion =
    rootProject.findProperty("jacksonVersion") as String

dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
    )
}
"""

    evidence = resolver.resolve(
        "app/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is not None
    assert evidence.source_type == "GRADLE_PROPERTY"
    assert evidence.property_name == "jacksonVersion"
    assert evidence.source_file == "gradle.properties"
    assert evidence.value == "2.23.0"
    assert evidence.resolved is True


def test_resolves_braced_property_interpolation(
    resolver,
    finding,
):
    content = """
val jacksonVersion =
    rootProject.findProperty("jacksonVersion") as String

dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}"
    )
}
"""

    evidence = resolver.resolve(
        "app/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is not None
    assert evidence.source_type == "GRADLE_PROPERTY"
    assert evidence.property_name == "jacksonVersion"


def test_returns_unknown_when_property_is_missing(
    resolver,
    finding,
    tools,
):
    tools.read_file.return_value = "otherVersion=1.0.0\n"

    content = """
val jacksonVersion =
    rootProject.findProperty("jacksonVersion") as String

dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
    )
}
"""

    evidence = resolver.resolve(
        "app/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is not None
    assert evidence.source_type == "GRADLE_PROPERTY"
    assert evidence.property_name == "jacksonVersion"
    assert evidence.value is None
    assert evidence.resolved is False


def test_returns_unknown_for_unrecognised_variable(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:$version"
    )
}
"""

    evidence = resolver.resolve(
        "app/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is not None
    assert evidence.source_type == "UNKNOWN"
    assert evidence.resolved is False


def test_ignores_different_dependency(resolver, finding):
    content = """
dependencies {
    implementation("org.example:some-library:1.0.0")
}
"""

    evidence = resolver.resolve(
        "app/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is None
