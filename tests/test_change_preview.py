
from pathlib import Path

import pytest

from security_agent.application.change_preview import ChangePreviewEngine
from security_agent.domain.analysis import Confidence, RemediationType
from security_agent.domain.remediation import FileChange, RemediationPlan
from security_agent.domain.preview import PreviewStatus
from security_agent.tools.repository import RepositoryTools


@pytest.fixture
def repository(tmp_path: Path):
    return tmp_path


@pytest.fixture
def engine(repository):
    return ChangePreviewEngine(RepositoryTools(repository))


@pytest.fixture
def plan():
    return RemediationPlan(
        finding_id="BD-12345",
        remediation_type=RemediationType.VERSION_UPGRADE,
        reason="Upgrade vulnerable dependency",
        confidence=Confidence.HIGH,
        changes=[
            FileChange(
                file="build.gradle",
                dependency="jackson-databind",
                current_version="2.15.2",
                target_version="2.17.3",
            )
        ],
    )


def test_generates_preview_without_modifying_file(
        repository,
        engine,
        plan,
):
    original = """dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'
}
"""

    file = repository / "build.gradle"
    file.write_text(original, encoding="utf-8")

    results = engine.create_preview(plan)

    assert len(results) == 1
    assert results[0].status == PreviewStatus.READY
    assert "2.15.2" in results[0].diff
    assert "2.17.3" in results[0].diff
    assert file.read_text(encoding="utf-8") == original


def test_detects_missing_dependency(engine, plan):
    results = engine.create_preview(plan)

    assert results[0].status == PreviewStatus.FILE_NOT_FOUND


def test_detects_missing_declaration(repository, engine, plan):
    file = repository / "build.gradle"
    file.write_text(
        "dependencies { implementation 'org.example:other:1.0' }",
        encoding="utf-8",
    )

    results = engine.create_preview(plan)

    assert results[0].status == PreviewStatus.DEPENDENCY_NOT_FOUND


def test_detects_version_mismatch(repository, engine, plan):
    file = repository / "build.gradle"
    file.write_text(
        "dependencies {\n"
        "    implementation 'com.fasterxml.jackson.core:jackson-databind:2.16.0'\n"
        "}\n",
        encoding="utf-8",
    )

    results = engine.create_preview(plan)

    assert results[0].status == PreviewStatus.VERSION_MISMATCH


def test_detects_multiple_declarations(repository, engine, plan):
    file = repository / "build.gradle"
    file.write_text(
        "dependencies {\n"
        "    implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'\n"
        "    testImplementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'\n"
        "}\n",
        encoding="utf-8",
    )

    results = engine.create_preview(plan)

    assert results[0].status == PreviewStatus.AMBIGUOUS


def test_supports_kotlin_dsl(repository, engine):
    file = repository / "app" / "build.gradle.kts"
    file.parent.mkdir(parents=True)

    original = """dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
}
"""

    file.write_text(original, encoding="utf-8")

    kotlin_plan = RemediationPlan(
        finding_id="BD-12345",
        remediation_type=RemediationType.VERSION_UPGRADE,
        reason="Upgrade vulnerable dependency",
        confidence=Confidence.HIGH,
        changes=[
            FileChange(
                file="app/build.gradle.kts",
                dependency="jackson-databind",
                current_version="2.15.2",
                target_version="2.17.3",
            )
        ],
    )

    results = engine.create_preview(kotlin_plan)

    assert results[0].status == PreviewStatus.READY
    assert "2.17.3" in results[0].diff
    assert file.read_text(encoding="utf-8") == original


def test_supports_root_gradle_properties(repository, engine):
    app = repository / "app"
    app.mkdir()

    build_file = app / "build.gradle.kts"
    build_file.write_text(
        """val jacksonDatabindVersion =
    findProperty("jackson_databind_version") as String

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonDatabindVersion")
}
""",
        encoding="utf-8",
    )

    properties_file = repository / "gradle.properties"
    original_properties = "jackson_databind_version=2.15.2\n"
    properties_file.write_text(
        original_properties,
        encoding="utf-8",
    )

    property_plan = RemediationPlan(
        finding_id="BD-12345",
        remediation_type=RemediationType.VERSION_UPGRADE,
        reason="Upgrade vulnerable dependency",
        confidence=Confidence.HIGH,
        changes=[
            FileChange(
                file="app/build.gradle.kts",
                dependency="jackson-databind",
                current_version="2.15.2",
                target_version="2.17.3",
            )
        ],
    )

    results = engine.create_preview(property_plan)

    assert results[0].status == PreviewStatus.READY
    assert results[0].file == "gradle.properties"
    assert "2.15.2" in results[0].diff
    assert "2.17.3" in results[0].diff

    assert properties_file.read_text(
        encoding="utf-8"
    ) == original_properties


def test_rejects_unsupported_file(repository, engine, plan):
    unsupported_plan = RemediationPlan(
        finding_id=plan.finding_id,
        remediation_type=plan.remediation_type,
        reason=plan.reason,
        confidence=plan.confidence,
        changes=[
            FileChange(
                file="pom.xml",
                dependency="jackson-databind",
                current_version="2.15.2",
                target_version="2.17.3",
            )
        ],
    )

    results = engine.create_preview(unsupported_plan)

    assert results[0].status == PreviewStatus.UNSUPPORTED
