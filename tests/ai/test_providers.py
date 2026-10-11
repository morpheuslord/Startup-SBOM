"""Providers: profiles, env auto-detection, --model override, fallback, cost estimation."""

from __future__ import annotations

import pytest

from startup_sbom.ai import AIConfigError
from startup_sbom.ai.providers import (
    PRICES,
    PRIORITY,
    PROFILES,
    PROVIDERS,
    ModelPrice,
    available_providers,
    detect_provider,
    estimate_cost,
    max_price,
    model_settings,
    price_for,
    provider_of,
    resolve,
    tier_of,
)


def test_anthropic_profile_ids_are_exact() -> None:
    profiles = PROVIDERS["anthropic"].profiles
    assert profiles["cheap"] == "anthropic:claude-haiku-4-5"
    assert profiles["balanced"] == "anthropic:claude-sonnet-5"
    assert profiles["quality"] == "anthropic:claude-opus-5"
    assert PRICES["anthropic:claude-haiku-4-5"] == ModelPrice(
        1.0, 5.0, 0.10, 200_000, verified=True
    )
    assert PRICES["anthropic:claude-sonnet-5"].input == 2.0
    assert PRICES["anthropic:claude-sonnet-5"].output == 10.0
    assert PRICES["anthropic:claude-opus-5"].input == 5.0
    assert PRICES["anthropic:claude-opus-5"].output == 25.0


def test_haiku_5_5_is_never_a_default() -> None:
    for info in PROVIDERS.values():
        assert "claude-haiku-5-5" not in info.profiles.values()
    # it stays usable through an explicit --model, with its price marked unverified
    assert PRICES["anthropic:claude-haiku-5-5"].verified is False
    choice = resolve(model="anthropic:claude-haiku-5-5", env={})
    assert choice.explicit
    assert choice.orchestrator == "anthropic:claude-haiku-5-5"


def test_every_provider_has_all_profiles() -> None:
    """Multi-LLM-provider support: each provider ships three sensible defaults."""
    assert set(PRIORITY) == set(PROVIDERS)
    for name, info in PROVIDERS.items():
        for tier in PROFILES:
            model = info.profiles[tier]
            assert model.startswith(f"{name}:"), (name, tier, model)
        # at least the cheap default has a documented price
        assert price_for(info.profiles["cheap"]) is not None, name


def test_env_detection_and_priority() -> None:
    assert detect_provider(env={}) is None
    assert detect_provider(env={"GROQ_API_KEY": "x"}) == "groq"
    assert detect_provider(env={"GROQ_API_KEY": "x", "OPENAI_API_KEY": "y"}) == "openai"
    assert detect_provider(env={"ANTHROPIC_API_KEY": "a", "OPENAI_API_KEY": "y"}) == "anthropic"
    assert detect_provider(env={"GEMINI_API_KEY": "g"}) == "google"
    assert detect_provider(env={"OLLAMA_BASE_URL": "http://localhost:11434/v1"}) == "ollama"
    flags = available_providers(env={"MISTRAL_API_KEY": "m"})
    assert flags["mistral"] is True
    assert sum(flags.values()) == 1
    assert list(flags) == list(PRIORITY)  # reported in priority order


def test_resolve_profiles_and_tiers() -> None:
    env = {"ANTHROPIC_API_KEY": "a"}
    cheap = resolve(profile="cheap", env=env)
    assert (cheap.orchestrator, cheap.specialist) == (
        "anthropic:claude-haiku-4-5",
        "anthropic:claude-haiku-4-5",
    )
    balanced = resolve(profile="balanced", env=env)
    assert (balanced.orchestrator, balanced.specialist) == (
        "anthropic:claude-sonnet-5",
        "anthropic:claude-haiku-4-5",
    )
    quality = resolve(profile="quality", env=env)
    assert (quality.orchestrator, quality.specialist) == (
        "anthropic:claude-opus-5",
        "anthropic:claude-sonnet-5",
    )


def test_resolve_explicit_provider_and_model() -> None:
    choice = resolve(provider="groq", profile="cheap", env={})
    assert choice.provider == "groq"
    assert choice.orchestrator == "groq:openai/gpt-oss-20b"

    explicit = resolve(model="mistral:mistral-small-latest", env={})
    assert explicit.explicit
    assert explicit.provider == "mistral"
    assert explicit.models == ("mistral:mistral-small-latest",)

    with pytest.raises(AIConfigError, match="does not belong"):
        resolve(provider="openai", model="google:gemini-3.1-flash-lite", env={})
    with pytest.raises(AIConfigError, match="unknown provider"):
        resolve(provider="skynet", env={})
    with pytest.raises(AIConfigError, match="unknown profile"):
        resolve(profile="free", env={"ANTHROPIC_API_KEY": "a"})
    with pytest.raises(AIConfigError, match="no AI provider configured"):
        resolve(env={})
    with pytest.raises(AIConfigError, match="provider:model-id"):
        provider_of("claude-haiku-4-5")


def test_fallback_chain_across_configured_providers() -> None:
    env = {"ANTHROPIC_API_KEY": "a", "OPENAI_API_KEY": "o", "GROQ_API_KEY": "g"}
    choice = resolve(profile="cheap", env=env)
    assert choice.provider == "anthropic"
    assert choice.fallbacks == ("openai:gpt-6-luna", "groq:openai/gpt-oss-20b")
    no_fb = resolve(profile="cheap", env=env, fallback=False)
    assert no_fb.fallbacks == ()


def test_test_model_shortcut() -> None:
    choice = resolve(model="test", env={})
    assert choice.provider == "test"
    assert choice.orchestrator == "test"


def test_model_settings_thinking() -> None:
    cheap = model_settings("anthropic:claude-haiku-4-5")
    assert cheap["thinking"] == "low"
    assert cheap["cache"] is True
    quality = model_settings("anthropic:claude-opus-5")
    assert quality["thinking"] == "high"
    openai = model_settings("openai:gpt-6-sol")
    assert openai["thinking"] == "medium"
    unknown = model_settings("azure:whatever")
    assert "thinking" not in unknown
    assert unknown["max_tokens"] == 16_000
    assert model_settings("test") == {}
    assert tier_of("anthropic:claude-sonnet-5") == "balanced"
    assert tier_of("anthropic:claude-haiku-5-5") is None


def test_cost_estimation() -> None:
    # 1M uncached input + 100K output on haiku-4-5: 1*1.0 + 0.1*5.0 = 1.5 USD
    assert estimate_cost("anthropic:claude-haiku-4-5", 1_000_000, 100_000) == pytest.approx(1.5)
    # cache reads are cheaper: 500K cached of 1M input -> 0.5*1.0 + 0.5*0.10 + 0
    assert estimate_cost("anthropic:claude-haiku-4-5", 1_000_000, 0, 500_000) == pytest.approx(0.55)
    assert estimate_cost("unknown:model", 1, 1) is None
    assert estimate_cost("ollama:granite4.1:8b", 10**6, 10**6) == 0.0

    top = max_price(("anthropic:claude-haiku-4-5", "anthropic:claude-opus-5"))
    assert top is not None
    assert top.output == 25.0
    assert max_price(("nope:nope",)) is None
