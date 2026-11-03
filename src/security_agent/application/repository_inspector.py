
import os
import subprocess
from dataclasses import dataclass

from security_agent.application.module_discovery import (
    GradleModule,
    GradleModuleDiscovery,
)
from security_agent.domain.finding import SecurityFinding
from security_agent.tools.repository import RepositoryTools


@dataclass(frozen=True)
class ModuleMatch:
    project_path: str
    build_file: str
    command_output: str


@dataclass(frozen=True)
class RepositoryInspection:
    finding_id: str
    configuration: str
    command_output: str
    is_consistent: bool
    matches: tuple[ModuleMatch, ...] = ()
    errors: tuple[str, ...] = ()


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
        self.discovery = GradleModuleDiscovery(
            tools,
            timeout_seconds=timeout_seconds,
        )

    def inspect(self, finding: SecurityFinding) -> RepositoryInspection:
        modules = self.discovery.discover()

        matches: list[ModuleMatch] = []
        errors: list[str] = []
        outputs: list[str] = []

        for module in modules:
            if module.build_file is None:
                errors.append(
                    f"{module.project_path}: no build file was discovered."
                )
                continue

            try:
                output = self._inspect_module(module, finding)
                outputs.append(
                    f"Module {module.project_path}:\n{output}"
                )

                if self._contains_finding(output, finding):
                    matches.append(
                        ModuleMatch(
                            project_path=module.project_path,
                            build_file=module.build_file,
                            command_output=output,
                        )
                    )

            except RuntimeError as exc:
                errors.append(f"{module.project_path}: {exc}")

        return RepositoryInspection(
            finding_id=finding.id,
            configuration=self.configuration,
            command_output="\n\n".join(outputs),
            is_consistent=(len(matches) == 1 and not errors),
            matches=tuple(matches),
            errors=tuple(errors),
        )

    def _inspect_module(
            self,
            module: GradleModule,
            finding: SecurityFinding,
    ) -> str:
        root = self.tools.root
        wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
        wrapper = root / wrapper_name

        task = (
            f"{module.project_path}:dependencyInsight"
            if module.project_path != ":"
            else ":dependencyInsight"
        )

        command = [
            str(wrapper),
            task,
            "--dependency",
            finding.component,
            "--configuration",
            self.configuration,
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
                "Gradle dependency inspection timed out."
            ) from exc

        output = f"{result.stdout}\n{result.stderr}".strip()

        if result.returncode != 0:
            raise RuntimeError(
                "Gradle dependency inspection failed.\n"
                f"Command: {' '.join(command)}\n{output}"
            )

        return output

    @staticmethod
    def _contains_finding(
            output: str,
            finding: SecurityFinding,
    ) -> bool:
        return (
                finding.component.casefold() in output.casefold()
                and finding.current_version in output
        )
