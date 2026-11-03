import base64
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from security_agent.application.module_discovery import (
    GradleModuleDiscovery,
)
from security_agent.tools.repository import RepositoryTools


@pytest.fixture
def discovery(tmp_path):
    wrapper = tmp_path / "gradlew"
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")

    (tmp_path / "settings.gradle").write_text(
        "rootProject.name = 'sample'\n",
        encoding="utf-8",
    )

    (tmp_path / "build.gradle").write_text(
        "plugins {}\n",
        encoding="utf-8",
    )

    return GradleModuleDiscovery(
        RepositoryTools(tmp_path)
    )


def encode(value):
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("utf-8")


def test_discovers_single_module_project(discovery, tmp_path):
    output = (
        "SECURITY_AGENT_PROJECT\t"
        f"{encode(':')}\t"
        f"{encode(str(tmp_path))}\t"
        f"{encode(str(tmp_path / 'build.gradle'))}"
    )

    with patch(
            "security_agent.application.module_discovery.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=output,
            stderr="",
        )

        modules = discovery.discover()

    assert len(modules) == 1
    assert modules[0].project_path == ":"
    assert modules[0].directory == "."
    assert modules[0].build_file == "build.gradle"


def test_discovers_multiple_modules(discovery, tmp_path):
    app_dir = tmp_path / "app"
    service_dir = tmp_path / "service"

    app_dir.mkdir()
    service_dir.mkdir()

    app_build = app_dir / "build.gradle"
    service_build = service_dir / "build.gradle"

    app_build.write_text("plugins {}\n", encoding="utf-8")
    service_build.write_text("plugins {}\n", encoding="utf-8")

    output = "\n".join([
        "\t".join([
            "SECURITY_AGENT_PROJECT",
            encode(":"),
            encode(str(tmp_path)),
            encode(str(tmp_path / "build.gradle")),
        ]),
        "\t".join([
            "SECURITY_AGENT_PROJECT",
            encode(":app"),
            encode(str(app_dir)),
            encode(str(app_build)),
        ]),
        "\t".join([
            "SECURITY_AGENT_PROJECT",
            encode(":service"),
            encode(str(service_dir)),
            encode(str(service_build)),
        ]),
    ])

    with patch(
            "security_agent.application.module_discovery.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=output,
            stderr="",
        )

        modules = discovery.discover()

    assert len(modules) == 3
    assert [module.project_path for module in modules] == [
        ":",
        ":app",
        ":service",
    ]

    assert modules[1].build_file == "app/build.gradle"
    assert modules[2].build_file == "service/build.gradle"


def test_discovery_fails_when_gradle_fails(discovery):
    with patch(
            "security_agent.application.module_discovery.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Gradle failed",
        )

        with pytest.raises(
                RuntimeError,
                match="Gradle module discovery failed",
        ):
            discovery.discover()


def test_discovery_fails_when_no_projects_found(discovery):
    with patch(
            "security_agent.application.module_discovery.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="BUILD SUCCESSFUL",
            stderr="",
        )

        with pytest.raises(
                RuntimeError,
                match="no projects were discovered",
        ):
            discovery.discover()


def test_discovery_rejects_project_outside_repository(
        discovery,
        tmp_path,
):
    outside = tmp_path.parent / "outside"

    output = "\t".join([
        "SECURITY_AGENT_PROJECT",
        encode(":external"),
        encode(str(outside)),
        encode(str(outside / "build.gradle")),
    ])

    with patch(
            "security_agent.application.module_discovery.subprocess.run"
    ) as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=output,
            stderr="",
        )

        with pytest.raises(
                ValueError,
                match="outside repository",
        ):
            discovery.discover()