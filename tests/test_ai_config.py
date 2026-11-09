import pytest

from security_agent.application.ai_config import (
    AIProviderConfig,
    AIProviderType,
)


def test_default_config_uses_rule_based_provider():
    config = AIProviderConfig()

    assert config.provider == AIProviderType.RULE_BASED
    assert config.model is None
    assert config.base_url is None
    assert config.api_key_env is None


def test_provider_can_be_configured_using_string():
    config = AIProviderConfig(provider="rule_based")

    assert config.provider == AIProviderType.RULE_BASED


def test_openai_compatible_provider_accepts_custom_configuration():
    config = AIProviderConfig(
        provider=AIProviderType.OPENAI_COMPATIBLE,
        model="custom-model",
        base_url="https://ai.example.com/v1/",
        api_key_env="MY_AI_API_KEY",
    )

    assert config.provider == AIProviderType.OPENAI_COMPATIBLE
    assert config.model == "custom-model"
    assert config.base_url == "https://ai.example.com/v1"
    assert config.api_key_env == "MY_AI_API_KEY"


def test_openai_compatible_provider_can_use_local_endpoint_without_key():
    config = AIProviderConfig(
        provider=AIProviderType.OPENAI_COMPATIBLE,
        model="local-model",
        base_url="http://localhost:8000/v1",
    )

    assert config.api_key_env is None


def test_openai_compatible_provider_requires_model():
    with pytest.raises(ValueError, match="model is required"):
        AIProviderConfig(
            provider=AIProviderType.OPENAI_COMPATIBLE,
            base_url="https://ai.example.com/v1",
        )


def test_openai_compatible_provider_requires_base_url():
    with pytest.raises(ValueError, match="base_url is required"):
        AIProviderConfig(
            provider=AIProviderType.OPENAI_COMPATIBLE,
            model="custom-model",
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "ftp://ai.example.com",
        "not-a-url",
        "https://",
        "https://user:password@ai.example.com/v1",
        "https://ai.example.com/v1?token=secret",
    ],
)
def test_openai_compatible_provider_rejects_invalid_base_url(base_url):
    with pytest.raises(ValueError, match="base_url"):
        AIProviderConfig(
            provider=AIProviderType.OPENAI_COMPATIBLE,
            model="custom-model",
            base_url=base_url,
        )


def test_invalid_api_key_environment_variable_name_is_rejected():
    with pytest.raises(ValueError, match="environment variable"):
        AIProviderConfig(
            provider=AIProviderType.OPENAI_COMPATIBLE,
            model="custom-model",
            base_url="https://ai.example.com/v1",
            api_key_env="my-api-key",
        )


def test_github_copilot_provider_accepts_model():
    config = AIProviderConfig(
        provider=AIProviderType.GITHUB_COPILOT,
        model="copilot-model",
    )

    assert config.provider == AIProviderType.GITHUB_COPILOT
    assert config.model == "copilot-model"


def test_github_copilot_rejects_custom_api_key_configuration():
    with pytest.raises(ValueError, match="GitHub Copilot"):
        AIProviderConfig(
            provider=AIProviderType.GITHUB_COPILOT,
            api_key_env="MY_AI_API_KEY",
        )


def test_rule_based_provider_rejects_external_configuration():
    with pytest.raises(ValueError, match="Rule-based"):
        AIProviderConfig(
            provider=AIProviderType.RULE_BASED,
            model="some-model",
        )


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_timeout_is_rejected(timeout):
    with pytest.raises(ValueError, match="timeout_seconds"):
        AIProviderConfig(timeout_seconds=timeout)


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError, match="Unsupported AI provider"):
        AIProviderConfig(provider="unknown_provider")
