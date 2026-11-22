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
        if not self.key.strip() or not self.value.strip():
            raise ValueError("Context fact fields cannot be empty.")
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
    version_source_type: str | None = None
    version_property_name: str | None = None
    version_lookup_scope: str | None = None
    version_source_file: str | None = None
    declared_version: str | None = None
    version_source_resolved: bool | None = None
    version_candidate_source_file: str | None = None
    version_candidate_value: str | None = None

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
            self._validate_optional_text(
                self.lock_file, "Lock file path", self.MAX_FIELD_LENGTH
            )

        if len(self.dependency_path) > self.MAX_PATH_ENTRIES:
            raise ValueError("Dependency path contains too many entries.")

        for entry in self.dependency_path:
            self._validate_optional_text(
                entry, "Dependency path entry", self.MAX_FIELD_LENGTH
            )

        if self.declaration is not None:
            self._validate_optional_text(
                self.declaration,
                "Dependency declaration",
                self.MAX_DECLARATION_LENGTH,
            )

        optional_fields = (
            ("Version source type", self.version_source_type),
            ("Version property name", self.version_property_name),
            ("Version lookup scope", self.version_lookup_scope),
            ("Version source file", self.version_source_file),
            ("Declared version", self.declared_version),
            ("Version candidate source file", self.version_candidate_source_file),
            ("Version candidate value", self.version_candidate_value),
        )

        for label, value in optional_fields:
            if value is not None:
                self._validate_optional_text(value, label, self.MAX_FIELD_LENGTH)

        if self.version_source_resolved is not None and not isinstance(
            self.version_source_resolved, bool
        ):
            raise ValueError("Version source resolved flag must be a boolean.")

    @staticmethod
    def _validate_optional_text(
        value: str,
        label: str,
        max_length: int,
    ) -> None:
        if not value.strip():
            raise ValueError(f"{label} cannot be empty.")
        if len(value) > max_length:
            raise ValueError(f"{label} is too long.")


@dataclass(frozen=True)
class DependencyConstraint:
    module_path: str
    manifest_file: str
    source_component: str
    requested: str
    selected: str

    MAX_FIELD_LENGTH: ClassVar[int] = 500

    def __post_init__(self) -> None:
        fields = (
            ("Module path", self.module_path),
            ("Manifest file", self.manifest_file),
            ("Constraint source", self.source_component),
            ("Requested component", self.requested),
            ("Selected component", self.selected),
        )

        for label, value in fields:
            if not value.strip():
                raise ValueError(f"{label} cannot be empty.")
            if len(value) > self.MAX_FIELD_LENGTH:
                raise ValueError(f"{label} is too long.")


@dataclass(frozen=True)
class AIRecommendationContext:
    finding_id: str
    dependency_name: str
    resolved_version: str
    dependency_scope: str | None = None
    locations: tuple[DependencyLocation, ...] = ()
    facts: tuple[ContextFact, ...] = ()
    constraints: tuple[DependencyConstraint, ...] = ()

    MAX_LOCATIONS: ClassVar[int] = 20
    MAX_FACTS: ClassVar[int] = 30
    MAX_CONSTRAINTS: ClassVar[int] = 20
    MAX_CONTEXT_CHARACTERS: ClassVar[int] = 12000

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("Finding ID cannot be empty.")
        if not self.dependency_name.strip():
            raise ValueError("Dependency name cannot be empty.")
        if not self.resolved_version.strip():
            raise ValueError("Resolved version cannot be empty.")
        if self.dependency_scope is not None and not self.dependency_scope.strip():
            raise ValueError("Dependency scope cannot be empty.")

        if len(self.locations) > self.MAX_LOCATIONS:
            raise ValueError("Too many dependency locations.")
        if len(self.facts) > self.MAX_FACTS:
            raise ValueError("Too many context facts.")
        if len(self.constraints) > self.MAX_CONSTRAINTS:
            raise ValueError("Too many dependency constraints.")

        if not all(isinstance(item, DependencyLocation) for item in self.locations):
            raise ValueError("Invalid dependency location.")
        if not all(isinstance(item, ContextFact) for item in self.facts):
            raise ValueError("Invalid context fact.")
        if not all(isinstance(item, DependencyConstraint) for item in self.constraints):
            raise ValueError("Invalid dependency constraint.")

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

            optional_values = (
                location.version_source_type,
                location.version_property_name,
                location.version_lookup_scope,
                location.version_source_file,
                location.declared_version,
                location.version_candidate_source_file,
                location.version_candidate_value,
            )
            total += sum(len(value) for value in optional_values if value is not None)

        for constraint in self.constraints:
            total += (
                len(constraint.module_path)
                + len(constraint.manifest_file)
                + len(constraint.source_component)
                + len(constraint.requested)
                + len(constraint.selected)
            )

        for fact in self.facts:
            total += len(fact.key) + len(fact.value)

        return total
