from dataclasses import dataclass
from enum import Enum

from security_agent.domain.analysis import Confidence


class RecommendationType(str, Enum):
    VERSION_UPGRADE = "VERSION_UPGRADE"
    DEPENDENCY_OVERRIDE = "DEPENDENCY_OVERRIDE"
    DEPENDENCY_REPLACEMENT = "DEPENDENCY_REPLACEMENT"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    TEMPORARY_MITIGATION = "TEMPORARY_MITIGATION"
    MANUAL_REMEDIATION = "MANUAL_REMEDIATION"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RecommendationRisk:
    level: RiskLevel
    description: str

    def __post_init__(self):
        try:
            object.__setattr__(
                self,
                "level",
                RiskLevel(self.level),
            )
        except ValueError as exc:
            raise ValueError(
                f"Unsupported risk level: {self.level}"
            ) from exc

        description = self.description.strip()

        if not description:
            raise ValueError("Risk description cannot be empty.")

        object.__setattr__(self, "description", description)


@dataclass(frozen=True)
class AIRecommendation:
    """
    Represents one remediation option suggested by an AI provider.

    This is a recommendation only. It does not authorize or perform
    repository modifications.
    """

    recommendation_id: str
    finding_id: str
    recommendation_type: RecommendationType
    title: str
    description: str
    rationale: str

    target_version: str | None = None
    target_dependency: str | None = None

    compatibility_notes: tuple[str, ...] = ()
    risks: tuple[RecommendationRisk, ...] = ()

    confidence: Confidence = Confidence.MEDIUM
    requires_manual_review: bool = True

    def __post_init__(self):
        try:
            object.__setattr__(
                self,
                "recommendation_type",
                RecommendationType(self.recommendation_type),
            )
            object.__setattr__(
                self,
                "confidence",
                Confidence(self.confidence),
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid recommendation type or confidence."
            ) from exc

        required_fields = (
            "recommendation_id",
            "finding_id",
            "title",
            "description",
            "rationale",
        )

        for field_name in required_fields:
            value = getattr(self, field_name)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{field_name} cannot be empty."
                )

            object.__setattr__(
                self,
                field_name,
                value.strip(),
            )

        for field_name in ("target_version", "target_dependency"):
            value = getattr(self, field_name)

            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(
                        f"{field_name} must be a string or None."
                    )

                value = value.strip() or None
                object.__setattr__(self, field_name, value)

        if (
                self.recommendation_type
                in (
                RecommendationType.VERSION_UPGRADE,
                RecommendationType.DEPENDENCY_OVERRIDE,
        )
                and not self.target_version
        ):
            raise ValueError(
                "target_version is required for version upgrades "
                "and dependency overrides."
            )

        if (
                self.recommendation_type
                == RecommendationType.DEPENDENCY_REPLACEMENT
                and not self.target_dependency
        ):
            raise ValueError(
                "target_dependency is required for dependency replacement."
            )

        notes = tuple(self.compatibility_notes)

        if any(
                not isinstance(note, str) or not note.strip()
                for note in notes
        ):
            raise ValueError(
                "Compatibility notes must contain non-empty strings."
            )

        object.__setattr__(
            self,
            "compatibility_notes",
            tuple(note.strip() for note in notes),
        )

        risks = tuple(self.risks)

        if any(not isinstance(risk, RecommendationRisk) for risk in risks):
            raise ValueError(
                "risks must contain RecommendationRisk objects."
            )

        object.__setattr__(self, "risks", risks)

        if not isinstance(self.requires_manual_review, bool):
            raise ValueError(
                "requires_manual_review must be a boolean."
            )


@dataclass(frozen=True)
class AIRecommendationResult:
    """
    Contains all remediation options returned for one security finding.

    An empty recommendations tuple is allowed when no safe remediation
    option can be recommended.
    """

    finding_id: str
    summary: str
    provider: str
    recommendations: tuple[AIRecommendation, ...] = ()
    model: str | None = None

    def __post_init__(self):
        for field_name in ("finding_id", "summary", "provider"):
            value = getattr(self, field_name)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{field_name} cannot be empty."
                )

            object.__setattr__(
                self,
                field_name,
                value.strip(),
            )

        if self.model is not None:
            if not isinstance(self.model, str):
                raise ValueError("model must be a string or None.")

            object.__setattr__(self, "model", self.model.strip() or None)

        recommendations = tuple(self.recommendations)

        if any(
                not isinstance(item, AIRecommendation)
                for item in recommendations
        ):
            raise ValueError(
                "recommendations must contain AIRecommendation objects."
            )

        for recommendation in recommendations:
            if recommendation.finding_id != self.finding_id:
                raise ValueError(
                    "All recommendations must belong to the result finding."
                )

        recommendation_ids = [
            item.recommendation_id for item in recommendations
        ]

        if len(recommendation_ids) != len(set(recommendation_ids)):
            raise ValueError(
                "Recommendation IDs must be unique."
            )

        object.__setattr__(
            self,
            "recommendations",
            recommendations,
        )
