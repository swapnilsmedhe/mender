import difflib
import re

from pathlib import Path

from security_agent.domain.preview import (
    ChangePreview,
    PreviewStatus,
)
from security_agent.domain.remediation import RemediationPlan
from security_agent.domain.analysis import RemediationType
from security_agent.tools.repository import RepositoryTools


class ChangePreviewEngine:
    SUPPORTED_CONFIGURATIONS = {
        "implementation",
        "api",
        "runtimeOnly",
        "compileOnly",
        "testImplementation",
        "testRuntimeOnly",
        "testCompileOnly",
        "annotationProcessor",
        "kapt",
    }

    def __init__(self, tools: RepositoryTools):
        self.tools = tools

    def create_preview(
            self,
            plan: RemediationPlan,
    ) -> list[ChangePreview]:

        if plan.remediation_type != RemediationType.VERSION_UPGRADE:
            return []

        previews = []

        for change in plan.changes:
            previews.append(self._preview_change(plan, change))

        return previews

    def _preview_change(self, plan, change):

        relative_path = change.file

        if Path(relative_path).name != "build.gradle":
            return self._result(
                plan,
                change,
                PreviewStatus.UNSUPPORTED,
                "Only Kotlin build.gradle files are supported.",
            )

        try:
            original = self.tools.read_file(relative_path)
        except FileNotFoundError:
            return self._result(
                plan,
                change,
                PreviewStatus.FILE_NOT_FOUND,
                "Dependency file was not found.",
            )

        pattern = re.compile(
            r"""(?m)^[ \t]*(?P<configuration>
            implementation|api|runtimeOnly|compileOnly|
            testImplementation|testRuntimeOnly|testCompileOnly|
            annotationProcessor|kapt
            )[ \t]*[('"](?P<coordinate>[^'")]+)['"][ \t]*\)?[ \t]*$""",
            re.VERBOSE,
        )

        matches = []

        for match in pattern.finditer(original):
            coordinate = match.group("coordinate").strip()

            parts = coordinate.split(":")

            if len(parts) != 3:
                continue

            group, artifact, version = parts

            if artifact == change.dependency:
                matches.append((match, group, artifact, version))

        if not matches:
            return self._result(
                plan,
                change,
                PreviewStatus.DEPENDENCY_NOT_FOUND,
                "No supported direct dependency declaration was found.",
            )

        if len(matches) > 1:
            return self._result(
                plan,
                change,
                PreviewStatus.AMBIGUOUS,
                "Multiple declarations match this dependency.",
            )

        match, group, artifact, version = matches[0]

        if version != change.current_version:
            return self._result(
                plan,
                change,
                PreviewStatus.VERSION_MISMATCH,
                f"Expected {change.current_version}, found {version}.",
            )

        old_line = match.group(0)

        new_coordinate = (
            f"{group}:{artifact}:{change.target_version}"
        )

        new_line = old_line.replace(
            match.group("coordinate"),
            new_coordinate,
        )

        updated = (
                original[:match.start()]
                + new_line
                + original[match.end():]
        )

        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=relative_path,
                tofile=relative_path,
            )
        )

        return self._result(
            plan,
            change,
            PreviewStatus.READY,
            "Preview generated successfully.",
            diff=diff,
        )

    @staticmethod
    def _result(
            plan,
            change,
            status,
            message,
            diff="",
    ):
        return ChangePreview(
            finding_id=plan.finding_id,
            file=change.file,
            dependency=change.dependency,
            current_version=change.current_version,
            target_version=change.target_version,
            status=status,
            diff=diff,
            message=message,
        )
