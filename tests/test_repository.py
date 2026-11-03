from pathlib import Path

import pytest

from security_agent.tools.repository import RepositoryTools


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    """Create a small sample repository for testing."""
    root = tmp_path / "sample-repo"
    root.mkdir()

    (root / "build.gradle.kts").write_text(
        'implementation("com.example:jackson-databind:2.15.2")\n',
        encoding="utf-8",
    )

    (root / "gradle").mkdir()
    (root / "gradle" / "libs.versions.toml").write_text(
        'jackson = "2.15.2"\n',
        encoding="utf-8",
    )

    (root / "node_modules").mkdir()
    (root / "node_modules" / "ignored.txt").write_text(
        "should not appear",
        encoding="utf-8",
    )

    return root


def test_list_files_returns_repository_files(repository: Path) -> None:
    tools = RepositoryTools(repository)

    files = tools.list_files()

    assert "build.gradle.kts" in files
    assert "gradle/libs.versions.toml" in files
    assert not any("node_modules" in file for file in files)


def test_list_files_for_subdirectory(repository: Path) -> None:
    tools = RepositoryTools(repository)

    files = tools.list_files("gradle")

    assert files == ["gradle/libs.versions.toml"]


def test_read_file_returns_contents(repository: Path) -> None:
    tools = RepositoryTools(repository)

    content = tools.read_file("gradle/libs.versions.toml")

    assert 'jackson = "2.15.2"' in content


def test_search_code_finds_matching_lines(repository: Path) -> None:
    tools = RepositoryTools(repository)

    results = tools.search_code("jackson-databind")

    assert len(results) == 1
    assert results[0]["file"] == "build.gradle.kts"
    assert results[0]["line"] == 1
    assert "jackson-databind" in results[0]["text"]


def test_search_code_is_case_insensitive(repository: Path) -> None:
    tools = RepositoryTools(repository)

    results = tools.search_code("JACKSON-DATABIND")

    assert len(results) == 1


def test_read_file_rejects_path_outside_repository(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("private data", encoding="utf-8")

    tools = RepositoryTools(repository)

    with pytest.raises(ValueError, match="outside the repository"):
        tools.read_file("../outside.txt")


def test_list_files_rejects_path_outside_repository(
    repository: Path,
) -> None:
    tools = RepositoryTools(repository)

    with pytest.raises(ValueError, match="outside the repository"):
        tools.list_files("../")


def test_search_code_rejects_empty_query(repository: Path) -> None:
    tools = RepositoryTools(repository)

    with pytest.raises(ValueError, match="cannot be empty"):
        tools.search_code("")

def test_read_file_rejects_missing_file(repository):
    tools = RepositoryTools(repository)
    with pytest.raises(FileNotFoundError, match="File not found"):
        tools.read_file("missing.txt")

def test_read_file_rejects_oversized_file(repository):
    tools = RepositoryTools(repository)

    oversized_file = repository / "large.txt"
    oversized_file.write_text(
        "x" * (RepositoryTools.MAX_FILE_SIZE + 1),
        encoding="utf-8",
        )

    with pytest.raises(ValueError, match="File exceeds maximum allowed size"):
        tools.read_file("large.txt")