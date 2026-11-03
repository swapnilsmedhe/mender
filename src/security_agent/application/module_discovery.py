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
        root = self.tools.root

        wrapper_name = (
            "gradlew.bat" if os.name == "nt" else "gradlew"
        )
        wrapper = root / wrapper_name

        if not wrapper.is_file():
            raise FileNotFoundError(
                f"Gradle wrapper not found: {wrapper}"
            )

        init_script = self._create_init_script()

        try:
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
                        f"Command: {' '.join(command)}\n"
                        f"{output}"
                    )

                modules = self._parse_output(output, root)

                if not modules:
                    raise RuntimeError(
                        "Gradle completed, but no projects were discovered."
                    )

                return modules

        finally:
            # The temporary initialization script is automatically removed.
            pass

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

        for line in output.splitlines():
            if not line.startswith(self.MARKER + "\t"):
                continue

            parts = line.split("\t")

            if len(parts) != 4:
                continue

            try:
                project_path = self._decode(parts[1])
                directory = Path(self._decode(parts[2])).resolve()
                build_file = Path(self._decode(parts[3])).resolve()
            except (ValueError, OSError):
                continue

            # Do not accept project directories outside the repository.
            if not directory.is_relative_to(root):
                raise ValueError(
                    f"Gradle project directory is outside repository: "
                    f"{directory}"
                )

            # Do not accept build files outside the repository.
            if not build_file.is_relative_to(root):
                raise ValueError(
                    f"Gradle build file is outside repository: "
                    f"{build_file}"
                )

            relative_directory = directory.relative_to(root).as_posix()
            relative_build_file = (
                build_file.relative_to(root).as_posix()
                if build_file.is_file()
                else None
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

        # Preserve Gradle's project order while removing duplicates.
        unique_modules = {
            module.project_path: module
            for module in modules
        }

        return list(unique_modules.values())

    @staticmethod
    def _decode(value: str) -> str:
        return base64.b64decode(value).decode("utf-8")