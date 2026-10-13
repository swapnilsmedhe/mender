from pathlib import Path


class RepositoryTools:
    """Provides safe, read-only access to a local repository."""

    EXCLUDED_DIRS = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".idea",
        "build",
        "dist",
    }

    MAX_FILE_SIZE = 1_000_000  # 1 MB
    MAX_RESULTS = 1_000

    def __init__(self, repository_root: str | Path) -> None:
        self.root = Path(repository_root).resolve()

        if not self.root.is_dir():
            raise ValueError(
                f"Repository root is not a directory: {self.root}"
            )

    def _resolve_path(self, relative_path: str) -> Path:
        """Resolve a path and reject paths outside the repository."""
        candidate = (self.root / relative_path).resolve()

        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(
                "Access outside the repository is not allowed."
            ) from exc

        return candidate

    def _iter_files(self, start_path: Path):
        """Yield repository files while skipping excluded directories."""
        if start_path.is_file():
            yield start_path
            return

        count = 0

        for path in start_path.rglob("*"):
            if any(part in self.EXCLUDED_DIRS for part in path.parts):
                continue

            # Do not follow symlinks to other files or directories.
            if path.is_symlink():
                continue

            if path.is_file():
                yield path
                count += 1

                if count >= self.MAX_RESULTS:
                    return

    def list_files(self, relative_path: str = ".") -> list[str]:
        """List repository files as paths relative to the root."""
        start_path = self._resolve_path(relative_path)

        if not start_path.exists():
            raise FileNotFoundError(relative_path)

        if not start_path.is_dir() and not start_path.is_file():
            raise ValueError("Path must refer to a file or directory.")

        return [
            path.relative_to(self.root).as_posix()
            for path in self._iter_files(start_path)
        ]

    def read_file(self, relative_path: str) -> str:
        """Read a text file, enforcing repository and size boundaries."""
        path = self._resolve_path(relative_path)

        if not path.is_file() or path.is_symlink():
            raise ValueError("Path must refer to a regular file.")

        if path.stat().st_size > self.MAX_FILE_SIZE:
            raise ValueError("File exceeds the 1 MB read limit.")

        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("File is not valid UTF-8 text.") from exc

    def search_code(
        self,
        query: str,
        relative_path: str = ".",
    ) -> list[dict[str, str | int]]:
        """Find literal, case-insensitive matches in repository text files."""
        if not query:
            raise ValueError("Search query cannot be empty.")

        start_path = self._resolve_path(relative_path)

        if not start_path.exists():
            raise FileNotFoundError(relative_path)

        results: list[dict[str, str | int]] = []

        for path in self._iter_files(start_path):
            if path.is_symlink() or path.stat().st_size > self.MAX_FILE_SIZE:
                continue

            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (UnicodeDecodeError, OSError):
                continue

            for line_number, line in enumerate(lines, start=1):
                if query.casefold() in line.casefold():
                    results.append(
                        {
                            "file": path.relative_to(self.root).as_posix(),
                            "line": line_number,
                            "text": line.strip(),
                        }
                    )

                    if len(results) >= self.MAX_RESULTS:
                        return results

        return results
