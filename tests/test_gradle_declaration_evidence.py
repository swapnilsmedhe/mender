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
        current_version="2.13.4",
        fixed_versions=["2.13.4.2"],
        repository="/repo",
        file="build.gradle.kts",
    )


@pytest.fixture
def tools():
    return Mock()


@pytest.fixture
def resolver(tools):
    return GradleVersionSourceResolver(tools)


def test_finds_versionless_dependency_declaration(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind"
    )
}
"""

    declarations = resolver.find_declarations(
        "bom-consumer/build.gradle.kts",
        content,
        finding,
    )

    assert len(declarations) == 1

    evidence = declarations[0]

    assert evidence.dependency == ("com.fasterxml.jackson.core:jackson-databind")
    assert evidence.declaration_kind == "DEPENDENCY"
    assert evidence.source_type == "VERSIONLESS"
    assert evidence.source_file == "bom-consumer/build.gradle.kts"
    assert evidence.resolved is False


def test_resolve_returns_versionless_dependency_evidence(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind")
}
"""

    evidence = resolver.resolve(
        "bom-consumer/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is not None
    assert evidence.source_type == "VERSIONLESS"
    assert evidence.declaration_kind == "DEPENDENCY"


def test_finds_direct_inline_dependency_declaration(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation(
        "com.fasterxml.jackson.core:jackson-databind:2.13.4"
    )
}
"""

    evidence = resolver.resolve(
        "direct-consumer/build.gradle.kts",
        content,
        finding,
    )

    assert evidence is not None
    assert evidence.source_type == "INLINE"
    assert evidence.value == "2.13.4"
    assert evidence.resolved is True


def test_finds_platform_bom_declaration(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation(
        platform("com.fasterxml.jackson:jackson-bom:2.13.4")
    )
    implementation(
        "com.fasterxml.jackson.core:jackson-databind"
    )
}
"""

    declarations = resolver.find_declarations(
        "bom-consumer/build.gradle.kts",
        content,
        finding,
    )

    platforms = [item for item in declarations if item.declaration_kind == "PLATFORM"]

    dependencies = [
        item for item in declarations if item.declaration_kind == "DEPENDENCY"
    ]

    assert len(platforms) == 1
    assert platforms[0].dependency == ("com.fasterxml.jackson:jackson-bom")
    assert platforms[0].source_type == "INLINE"
    assert platforms[0].value == "2.13.4"

    assert len(dependencies) == 1
    assert dependencies[0].dependency == ("com.fasterxml.jackson.core:jackson-databind")


def test_finds_enforced_platform_declaration(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation(
        enforcedPlatform("com.fasterxml.jackson:jackson-bom:2.13.4")
    )
    implementation("com.fasterxml.jackson.core:jackson-databind")
}
"""

    declarations = resolver.find_declarations(
        "bom-consumer/build.gradle.kts",
        content,
        finding,
    )

    platforms = [item for item in declarations if item.declaration_kind == "PLATFORM"]

    assert len(platforms) == 1
    assert platforms[0].dependency == ("com.fasterxml.jackson:jackson-bom")


def test_finds_multiple_platforms_without_misclassifying_them(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.13.4"))
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.1"))
    implementation("com.fasterxml.jackson.core:jackson-databind")
}
"""

    declarations = resolver.find_declarations(
        "build.gradle.kts",
        content,
        finding,
    )

    platforms = [item for item in declarations if item.declaration_kind == "PLATFORM"]

    dependencies = [
        item for item in declarations if item.declaration_kind == "DEPENDENCY"
    ]

    assert len(platforms) == 2
    assert len(dependencies) == 1
    assert dependencies[0].dependency == ("com.fasterxml.jackson.core:jackson-databind")


def test_finds_property_backed_platform_declaration(
    resolver,
    finding,
    tools,
):
    tools.read_file.return_value = "jacksonBomVersion=2.13.4"

    content = """
val jacksonBomVersion: String by project

dependencies {
    implementation(
        platform("com.fasterxml.jackson:jackson-bom:$jacksonBomVersion")
    )
    implementation("com.fasterxml.jackson.core:jackson-databind")
}
"""

    declarations = resolver.find_declarations(
        "bom-consumer/build.gradle.kts",
        content,
        finding,
    )

    platform = next(
        item for item in declarations if item.declaration_kind == "PLATFORM"
    )

    assert platform.source_type == "GRADLE_PROJECT_PROPERTY"
    assert platform.property_name == "jacksonBomVersion"
    assert platform.lookup_scope == "CURRENT_PROJECT"
    assert platform.candidate_source_file == "gradle.properties"
    assert platform.candidate_value == "2.13.4"
    assert platform.resolved is False


def test_does_not_treat_unrelated_dependency_as_finding_declaration(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation("org.example:some-library:1.0.0")
}
"""

    assert (
        resolver.find_declarations(
            "app/build.gradle.kts",
            content,
            finding,
        )
        == ()
    )


def test_does_not_treat_bom_as_vulnerable_dependency_declaration(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.13.4"))
}
"""

    assert (
        resolver.resolve(
            "app/build.gradle.kts",
            content,
            finding,
        )
        is None
    )


def test_supports_groovy_dependency_syntax(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.13.4'
    implementation platform('com.fasterxml.jackson:jackson-bom:2.13.4')
}
"""

    declarations = resolver.find_declarations(
        "build.gradle",
        content,
        finding,
    )

    assert any(
        item.declaration_kind == "DEPENDENCY" and item.source_type == "INLINE"
        for item in declarations
    )

    assert any(item.declaration_kind == "PLATFORM" for item in declarations)


def test_deduplicates_repeated_declarations(
    resolver,
    finding,
):
    content = """
dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.core:jackson-databind")
}
"""

    declarations = resolver.find_declarations(
        "build.gradle.kts",
        content,
        finding,
    )

    assert len(declarations) == 1
