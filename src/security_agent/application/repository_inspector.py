import subprocess
from dataclasses import dataclass
from pathlib import Path

from security_agent.domain.finding import SecurityFinding
from security_agent.tools.repository import RepositoryTools


@dataclass(frozen=True)
class RepositoryInspection:
    finding_id: str
    configuration: str
    command_output: str
    is_consistent: bool


class RepositoryInspector:
    def __init__(
        self,
        tools: RepositoryTools,
        configuration: str = "runtimeClasspath",
        timeout_seconds: int = 120,
    ) -> None:
        self.tools = tools
        self.configuration = configuration
        self.timeout_seconds = timeout_seconds

    def inspect(self, finding: SecurityFinding) -> RepositoryInspection:
        root = self.tools.root

        wrapper_name = (
            "gradlew.bat" if __import__("os").name == "nt" else "gradlew"
        )
        wrapper = root / wrapper_name

        if not wrapper.is_file():
            raise FileNotFoundError(
                f"Gradle wrapper not found: {wrapper}"
            )

        command = [
            str(wrapper),
            "dependencyInsight",
            "--dependency",
            finding.component,
            "--configuration",
            self.configuration,
            "--console=plain",
        ]

        print(f"Running command: {' '.join(command)} in {root} ---------------")

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
                "Gradle dependency inspection timed out."
            ) from exc

        output = f"{result.stdout}\n{result.stderr}".strip()

        if result.returncode != 0:
            raise RuntimeError(
                "Gradle dependency inspection failed.\n"
                f"Command: {' '.join(command)}\n"
                f"{output}"
            )

        # Require both the component and reported version in Gradle's
        # dependency report. This is an initial check, not a full parser
        # for every Gradle output format.
        consistent = (
            finding.component.casefold() in output.casefold()
            and finding.current_version in output
        )

        return RepositoryInspection(
            finding_id=finding.id,
            configuration=self.configuration,
            command_output=output,
            is_consistent=consistent,
        )
