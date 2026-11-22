
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class GradleReportEntry:
    depth: int
    notation: str
    is_repeated: bool = False
    is_runtime_classpath: bool = False


@dataclass(frozen=True)
class GradleDependencyReport:
    selected_dependency: str | None
    entries: tuple[GradleReportEntry, ...]
    is_selected_by_constraint: bool

    @property
    def repeated_entry_count(self) -> int:
        return sum(entry.is_repeated for entry in self.entries)

    @property
    def runtime_classpath_entry_count(self) -> int:
        return sum(
            entry.is_runtime_classpath
            for entry in self.entries
        )


class GradleDependencyReportParser:
    COORDINATE_PATTERN = re.compile(
        r"(?P<group>[A-Za-z0-9_.-]+):"
        r"(?P<artifact>[A-Za-z0-9_.-]+):"
        r"(?P<version>[^\s()]+)"
    )

    TREE_MARKER_PATTERN = re.compile(
        r"(?P<indent>(?:\|    |     )*)"
        r"(?P<branch>\+---|\\---)\s+"
        r"(?P<content>.*)"
    )

    def parse(self, output: str) -> GradleDependencyReport:
        lines = output.splitlines()

        selected_dependency = None
        is_selected_by_constraint = False
        entries = []

        for line in lines:
            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith("> Task"):
                continue

            if "(*)" in stripped:
                is_repeated = True
            else:
                is_repeated = False

            if stripped.endswith("(by constraint)"):
                is_selected_by_constraint = True

            coordinate_match = self.COORDINATE_PATTERN.search(
                stripped
            )

            if (
                selected_dependency is None
                and coordinate_match
                and not line[0].isspace()
            ):
                selected_dependency = (
                    f"{coordinate_match.group('group')}:"
                    f"{coordinate_match.group('artifact')}:"
                    f"{coordinate_match.group('version')}"
                )

            tree_match = self.TREE_MARKER_PATTERN.match(line)

            if not tree_match:
                continue

            content = tree_match.group("content").strip()

            # Gradle repeats previously expanded dependency subtrees
            # using (*). Preserve the occurrence as metadata, but
            # never interpret it as another dependency path.
            if is_repeated:
                coordinate = self.COORDINATE_PATTERN.search(content)

                if coordinate:
                    notation = (
                        f"{coordinate.group('group')}:"
                        f"{coordinate.group('artifact')}:"
                        f"{coordinate.group('version')}"
                    )

                    entries.append(
                        GradleReportEntry(
                            depth=self._depth(line, tree_match),
                            notation=notation,
                            is_repeated=True,
                        )
                    )

                continue

            if content.startswith("runtimeClasspath"):
                entries.append(
                    GradleReportEntry(
                        depth=self._depth(line, tree_match),
                        notation=content,
                        is_runtime_classpath=True,
                    )
                )
                continue

            coordinate = self.COORDINATE_PATTERN.search(content)

            if coordinate:
                notation = (
                    f"{coordinate.group('group')}:"
                    f"{coordinate.group('artifact')}:"
                    f"{coordinate.group('version')}"
                )

                entries.append(
                    GradleReportEntry(
                        depth=self._depth(line, tree_match),
                        notation=notation,
                    )
                )

        return GradleDependencyReport(
            selected_dependency=selected_dependency,
            entries=tuple(entries),
            is_selected_by_constraint=is_selected_by_constraint,
        )

    @staticmethod
    def _depth(line: str, match: re.Match) -> int:
        # Gradle's ASCII tree uses five-character indentation
        # levels. The first branch is depth 1.
        return match.start("branch") // 5 + 1
