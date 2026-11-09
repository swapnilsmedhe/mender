from dataclasses import dataclass
from enum import Enum
from typing import ClassVar


class DependencyRelationship(str, Enum):
    DIRECT = "DIRECT"
    TRANSITIVE = "TRANSITIVE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ContextFact:
    key: str
    value: str

    MAX_FIELD_LENGTH: ClassVar[int] = 1000

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ValueError("Context fact key cannot be empty.")

        if not self.value.strip():
            raise ValueError("Context fact value cannot be empty.")

        if len(self.key) > self.MAX_FIELD_LENGTH:
            raise ValueError("Context fact key is too long.")

        if len(self.value) > self.MAX_FIELD_LENGTH:
            raise ValueError("Context fact value is too long.")


@dataclass(frozen=True)
class DependencyLocation:
    module_path: str
    manifest_file: str
    relationship: DependencyRelationship
    lock_file: str | None = None
    dependency_path: tuple[str, ...] = ()
    declaration: str | None = None

    MAX_PATH_ENTRIES: ClassVar[int] = 10
    MAX_FIELD_LENGTH: ClassVar[int] = 500
    MAX_DECLARATION_LENGTH: ClassVar[int] = 1000

    def __post_init__(self) -> None:
        if not self.module_path.strip():
            raise ValueError("Module path cannot be empty.")

        if not self.manifest_file.strip():
            raise ValueError("Manifest file cannot be empty.")

        if not isinstance(self.relationship, DependencyRelationship):
            raise ValueError("Invalid dependency relationship.")

        if len(self.module_path) > self.MAX_FIELD_LENGTH:
            raise ValueError("Module path is too long.")

        if len(self.manifest_file) > self.MAX_FIELD_LENGTH:
            raise ValueError("Manifest file path is too long.")

        if self.lock_file is not None:
            if not self.lock_file.strip():
                raise ValueError("Lock file path cannot be empty.")

            if len(self.lock_file) > self.MAX_FIELD_LENGTH:
                raise ValueError("Lock file path is too long.")

        if len(self.dependency_path) > self.MAX_PATH_ENTRIES:
            raise ValueError("Dependency path contains too many entries.")

        for entry in self.dependency_path:
            if not entry.strip():
                raise ValueError("Dependency path entries cannot be empty.")

            if len(entry) > self.MAX_FIELD_LENGTH:
                raise ValueError("Dependency path entry is too long.")

        if self.declaration is not None:
            if not self.declaration.strip():
                raise ValueError("Dependency declaration cannot be empty.")

            if len(self.declaration) > self.MAX_DECLARATION_LENGTH:
                raise ValueError("Dependency declaration is too long.")


@dataclass(frozen=True)
class AIRecommendationContext:
    finding_id: str
    dependency_name: str
    resolved_version: str
    dependency_scope: str | None = None
    locations: tuple[DependencyLocation, ...] = ()
    facts: tuple[ContextFact, ...] = ()

    MAX_LOCATIONS: ClassVar[int] = 20
    MAX_FACTS: ClassVar[int] = 30
    MAX_CONTEXT_CHARACTERS: ClassVar[int] = 12000

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("Finding ID cannot be empty.")

        if not self.dependency_name.strip():
            raise ValueError("Dependency name cannot be empty.")

        if not self.resolved_version.strip():
            raise ValueError("Resolved version cannot be empty.")

        if self.dependency_scope is not None:
            if not self.dependency_scope.strip():
                raise ValueError("Dependency scope cannot be empty.")

        if len(self.locations) > self.MAX_LOCATIONS:
            raise ValueError("Too many dependency locations.")

        if len(self.facts) > self.MAX_FACTS:
            raise ValueError("Too many context facts.")

        if not all(
                isinstance(location, DependencyLocation)
                for location in self.locations
        ):
            raise ValueError("Invalid dependency location.")

        if not all(
                isinstance(fact, ContextFact)
                for fact in self.facts
        ):
            raise ValueError("Invalid context fact.")

        if self.estimated_characters > self.MAX_CONTEXT_CHARACTERS:
            raise ValueError("AI recommendation context is too large.")

    @property
    def estimated_characters(self) -> int:
        total = (
                len(self.finding_id)
                + len(self.dependency_name)
                + len(self.resolved_version)
        )

        if self.dependency_scope:
            total += len(self.dependency_scope)

        for location in self.locations:
            total += len(location.module_path)
            total += len(location.manifest_file)

            if location.lock_file:
                total += len(location.lock_file)

            if location.declaration:
                total += len(location.declaration)

            total += sum(len(entry) for entry in location.dependency_path)

        for fact in self.facts:
            total += len(fact.key)
            total += len(fact.value)

        return total