import math
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit


class AIProviderType(str, Enum):
    RULE_BASED = "rule_based"
    OPENAI_COMPATIBLE = "openai_compatible"
    GITHUB_COPILOT = "github_copilot"


@dataclass(frozen=True)
class AIProviderConfig:
    """
    Configuration for selecting and initializing an AI provider.

    API keys are never stored here. The api_key_env field contains
    only the name of the environment variable holding the key.
    """

    provider: AIProviderType = AIProviderType.RULE_BASED
    model: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    timeout_seconds: float = 30.0

    def __post_init__(self):
        try:
            provider = AIProviderType(self.provider)
        except ValueError as exc:
            raise ValueError(
                f"Unsupported AI provider: {self.provider}"
            ) from exc

        object.__setattr__(self, "provider", provider)

        for field_name in ("model", "base_url", "api_key_env"):
            value = getattr(self, field_name)

            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(
                        f"{field_name} must be a string or None."
                    )

                value = value.strip() or None
                object.__setattr__(self, field_name, value)

        if (
                isinstance(self.timeout_seconds, bool)
                or not isinstance(self.timeout_seconds, (int, float))
                or not math.isfinite(self.timeout_seconds)
                or self.timeout_seconds <= 0
        ):
            raise ValueError(
                "timeout_seconds must be a positive finite number."
            )

        if self.api_key_env and not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*",
                self.api_key_env,
        ):
            raise ValueError(
                "api_key_env must be a valid environment variable name."
            )

        if provider == AIProviderType.OPENAI_COMPATIBLE:
            self._validate_openai_compatible_config()

        elif provider == AIProviderType.GITHUB_COPILOT:
            if self.base_url or self.api_key_env:
                raise ValueError(
                    "GitHub Copilot configuration does not accept "
                    "base_url or api_key_env."
                )

        elif provider == AIProviderType.RULE_BASED:
            if self.model or self.base_url or self.api_key_env:
                raise ValueError(
                    "Rule-based configuration does not accept "
                    "model, base_url or api_key_env."
                )

    def _validate_openai_compatible_config(self):
        if not self.model:
            raise ValueError(
                "model is required for the openai_compatible provider."
            )

        if not self.base_url:
            raise ValueError(
                "base_url is required for the openai_compatible provider."
            )

        try:
            parsed_url = urlsplit(self.base_url)
            hostname = parsed_url.hostname
            parsed_url.port
        except ValueError as exc:
            raise ValueError("Invalid AI provider base_url.") from exc

        if (
                parsed_url.scheme not in ("http", "https")
                or not parsed_url.netloc
                or not hostname
                or parsed_url.username
                or parsed_url.password
                or parsed_url.query
                or parsed_url.fragment
        ):
            raise ValueError(
                "base_url must be a valid HTTP or HTTPS URL "
                "without embedded credentials, query parameters "
                "or fragments."
            )

        object.__setattr__(
            self,
            "base_url",
            self.base_url.rstrip("/"),
        )
