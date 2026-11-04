
import difflib
import re
from pathlib import Path

from security_agent.domain.analysis import RemediationType
from security_agent.domain.preview import ChangePreview, PreviewStatus
from security_agent.domain.remediation import RemediationPlan


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

    def __init__(self, tools):
        self.tools = tools

        configurations = "|".join(
            re.escape(configuration)
            for configuration in sorted(
                self.SUPPORTED_CONFIGURATIONS,
                key=len,
                reverse=True,
            )
        )

        # Matches Groovy:
        # implementation 'group:artifact:version'
        #
        # Matches Kotlin:
        # implementation("group:artifact:version")
        self.dependency_pattern = re.compile(
            rf"""
            ^[ \t]*
            (?P<configuration>{configurations})
            [ \t]*
            (?:
                \(
                    [ \t]*["'](?P<coordinate_parenthesized>[^"']+)["']
                    [ \t]*\)
                |
                [ \t]+["'](?P<coordinate_plain>[^"']+)["']
            )
            """,
            re.VERBOSE | re.MULTILINE,
            )

        self.variable_pattern = re.compile(
            r"\$(?:\{(?P<braced>[A-Za-z_]\w*)\}|(?P<plain>[A-Za-z_]\w*))"
        )

        self.property_pattern = re.compile(
            r"(?m)^[ \t]*(?P<key>[A-Za-z_][\w.-]*)"
            r"[ \t]*=[ \t]*(?P<value>[^\r\n#]+)"
        )

    def create_preview(self, plan: RemediationPlan):
        if plan.remediation_type != RemediationType.VERSION_UPGRADE:
            return []

        return [
            self._preview_change(plan, change)
            for change in plan.changes
        ]

    def _preview_change(self, plan, change):
        build_file = Path(change.file)

        if build_file.name not in {
            "build.gradle",
            "build.gradle.kts",
        }:
            return self._result(
                plan,
                change,
                PreviewStatus.UNSUPPORTED,
                "Only build.gradle and build.gradle.kts files are supported.",
            )

        try:
            original = self.tools.read_file(change.file)
        except FileNotFoundError:
            return self._result(
                plan,
                change,
                PreviewStatus.FILE_NOT_FOUND,
                f"Build file not found: {change.file}",
            )

        matches = []

        for match in self.dependency_pattern.finditer(original):
            coordinate = (
                    match.group("coordinate_parenthesized")
                    or match.group("coordinate_plain")
            )

            parts = coordinate.strip().split(":")

            if len(parts) != 3:
                continue

            group, artifact, version = parts

            if artifact == change.dependency:
                matches.append(
                    {
                        "match": match,
                        "group": group,
                        "artifact": artifact,
                        "version": version,
                        "coordinate": coordinate,
                    }
                )

        if not matches:
            return self._result(
                plan,
                change,
                PreviewStatus.DEPENDENCY_NOT_FOUND,
                f"Dependency {change.dependency} was not found in {change.file}.",
            )

        if len(matches) > 1:
            return self._result(
                plan,
                change,
                PreviewStatus.AMBIGUOUS,
                (
                    f"Multiple declarations of {change.dependency} "
                    f"were found in {change.file}."
                ),
            )

        dependency = matches[0]
        version = dependency["version"]

        variable_match = self.variable_pattern.search(version)

        if variable_match:
            variable_name = (
                    variable_match.group("braced")
                    or variable_match.group("plain")
            )

            return self._preview_property_change(
                plan,
                change,
                build_file,
                variable_name,
            )

        if version != change.current_version:
            return self._result(
                plan,
                change,
                PreviewStatus.VERSION_MISMATCH,
                (
                    f"Expected version {change.current_version}, "
                    f"but found {version}."
                ),
            )

        match = dependency["match"]

        updated_coordinate = (
            f"{dependency['group']}:"
            f"{dependency['artifact']}:"
            f"{change.target_version}"
        )

        coordinate_start = (
            match.start("coordinate_parenthesized")
            if match.group("coordinate_parenthesized") is not None
            else match.start("coordinate_plain")
        )

        coordinate_end = (
            match.end("coordinate_parenthesized")
            if match.group("coordinate_parenthesized") is not None
            else match.end("coordinate_plain")
        )

        updated = (
                original[:coordinate_start]
                + updated_coordinate
                + original[coordinate_end:]
        )

        return self._ready(
            plan,
            change,
            change.file,
            original,
            updated,
        )

    def _preview_property_change(
            self,
            plan,
            change,
            build_file,
            variable_name,
    ):
        property_key = self._to_property_key(variable_name)

        properties_path = self._find_properties_file(
            build_file,
            property_key,
        )

        if properties_path is None:
            return self._result(
                plan,
                change,
                PreviewStatus.UNSUPPORTED,
                (
                    f"Could not find property '{property_key}' "
                    "in module or root gradle.properties."
                ),
            )

        try:
            original = self.tools.read_file(properties_path)
        except FileNotFoundError:
            return self._result(
                plan,
                change,
                PreviewStatus.FILE_NOT_FOUND,
                f"Properties file not found: {properties_path}",
            )

        matches = [
            match
            for match in self.property_pattern.finditer(original)
            if match.group("key") == property_key
        ]

        if not matches:
            return self._result(
                plan,
                change,
                PreviewStatus.UNSUPPORTED,
                f"Property '{property_key}' was not found.",
            )

        if len(matches) > 1:
            return self._result(
                plan,
                change,
                PreviewStatus.AMBIGUOUS,
                f"Multiple definitions of '{property_key}' were found.",
            )

        match = matches[0]
        current_version = match.group("value").strip()

        if current_version != change.current_version:
            return self._result(
                plan,
                change,
                PreviewStatus.VERSION_MISMATCH,
                (
                    f"Expected version {change.current_version}, "
                    f"but found {current_version}."
                ),
            )

        updated = (
                original[:match.start("value")]
                + change.target_version
                + original[match.end("value"):]
        )

        return self._ready(
            plan,
            change,
            properties_path,
            original,
            updated,
        )

    def _find_properties_file(self, build_file, property_key):
        current_directory = build_file.parent

        while True:
            candidate = current_directory / "gradle.properties"

            try:
                content = self.tools.read_file(str(candidate))
            except FileNotFoundError:
                content = None

            if content is not None:
                property_names = {
                    match.group("key")
                    for match in self.property_pattern.finditer(content)
                }

                if property_key in property_names:
                    return str(candidate)

            if current_directory.parent == current_directory:
                break

            current_directory = current_directory.parent

        return None

    @staticmethod
    def _to_property_key(variable_name):
        first = re.sub(
            r"([A-Z]+)([A-Z][a-z])",
            r"\1_\2",
            variable_name,
        )

        return re.sub(
            r"([a-z0-9])([A-Z])",
            r"\1_\2",
            first,
        ).lower()

    def _ready(
            self,
            plan,
            change,
            file_path,
            original,
            updated,
    ):
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
            )
        )

        return ChangePreview(
            finding_id=plan.finding_id,
            file=file_path,
            dependency=change.dependency,
            current_version=change.current_version,
            target_version=change.target_version,
            status=PreviewStatus.READY,
            diff=diff,
            message=(
                "Preview generated successfully. "
                "No files were modified."
            ),
        )

    @staticmethod
    def _result(plan, change, status, message):
        return ChangePreview(
            finding_id=plan.finding_id,
            file=change.file,
            dependency=change.dependency,
            current_version=change.current_version,
            target_version=change.target_version,
            status=status,
            diff="",
            message=message,
        )
