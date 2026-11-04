
import base64
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from security_agent.tools.repository import RepositoryTools


@dataclass(frozen=True)
class GradleModule:
    name: str
    project_path: str
    directory: str
    build_file: str | None


class GradleModuleDiscovery:
    MARKER = "SECURITY_AGENT_PROJECT"

    def __init__(
            self,
            tools: RepositoryTools,
            timeout_seconds: int = 120,
    ) -> None:
        self.tools = tools
        self.timeout_seconds = timeout_seconds

    def discover(self) -> list[GradleModule]:
        root = self.tools.root.resolve()

        wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
        wrapper = root / wrapper_name

        if not wrapper.is_file():
            raise FileNotFoundError(
                f"Gradle wrapper not found: {wrapper}"
            )

        init_script = self._create_init_script()

        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "discover.init.gradle"
            script_path.write_text(
                init_script,
                encoding="utf-8",
            )

            command = [
                str(wrapper),
                "--init-script",
                str(script_path),
                "help",
                "--console=plain",
            ]

            try:
                result = subprocess.run(
                    command,
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    shell=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    "Gradle module discovery timed out."
                ) from exc

            output = f"{result.stdout}\n{result.stderr}".strip()

            if result.returncode != 0:
                raise RuntimeError(
                    "Gradle module discovery failed.\n"
                    f"{output}"
                )

            modules = self._parse_output(output, root)

            if not modules:
                raise RuntimeError(
                    "Gradle completed, but no projects were discovered."
                )

            return modules

    @staticmethod
    def _create_init_script() -> str:
        return r"""
import java.util.Base64

def encodeValue = { value ->
    Base64.encoder.encodeToString(
        value.toString().getBytes("UTF-8")
    )
}

gradle.projectsEvaluated {
    gradle.rootProject.allprojects.each { project ->
        println(
            "SECURITY_AGENT_PROJECT\t" +
            encodeValue(project.path) + "\t" +
            encodeValue(project.projectDir.canonicalPath) + "\t" +
            encodeValue(project.buildFile.canonicalPath)
        )
    }
}
"""

    def _parse_output(
            self,
            output: str,
            root: Path,
    ) -> list[GradleModule]:
        modules = []
        root = root.resolve()

        for line in output.splitlines():
            if not line.startswith(self.MARKER + "\t"):
                continue

            parts = line.split("\t")

            if len(parts) != 4:
                continue

            try:
                project_path = self._decode(parts[1])
                directory = Path(
                    self._decode(parts[2])
                ).resolve()
                build_file_path = Path(
                    self._decode(parts[3])
                ).resolve()

            except (ValueError, OSError):
                continue

            if not directory.is_relative_to(root):
                raise ValueError(
                    "Gradle project directory is outside repository: "
                    f"{directory}"
                )

            if not build_file_path.is_relative_to(root):
                raise ValueError(
                    "Gradle build file is outside repository: "
                    f"{build_file_path}"
                )

            relative_directory = (
                directory.relative_to(root).as_posix()
            )

            # A Gradle project can exist without its own build file.
            # Preserve that project instead of failing discovery.
            relative_build_file = None

            if build_file_path.is_file():
                relative_build_file = (
                    build_file_path.relative_to(root).as_posix()
                )

            name = project_path.split(":")[-1] or root.name

            modules.append(
                GradleModule(
                    name=name,
                    project_path=project_path,
                    directory=relative_directory,
                    build_file=relative_build_file,
                )
            )

        # Avoid duplicate project entries.
        unique_modules = {
            module.project_path: module
            for module in modules
        }

        return list(unique_modules.values())

    @staticmethod
    def _decode(value: str) -> str:
        return base64.b64decode(
            value,
            validate=True,
        ).decode("utf-8")
