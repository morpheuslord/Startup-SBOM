"""Model providers, cost profiles, auto-detection, fallback chains and cost estimation.

Profiles (``cheap`` / ``balanced`` / ``quality``) map to concrete pydantic-ai model
strings per provider.  Prices are USD per million tokens (standard tier, October
2026); ``verified`` says whether the price was checked against the provider's own
pricing page or model reference (the rest come from genai-prices / OpenRouter).

Nothing here imports pydantic-ai at module import time.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal

from startup_sbom.ai import AIConfigError, require

if TYPE_CHECKING:
    from pydantic_ai.models import Model

Profile = Literal["cheap", "balanced", "quality"]
PROFILES: Final[tuple[Profile, ...]] = ("cheap", "balanced", "quality")

#: Auto-detection order when no ``--provider``/``--model`` is given (first configured wins).
PRIORITY: Final[tuple[str, ...]] = (
    "anthropic",
    "openai",
    "google",
    "groq",
    "mistral",
    "openrouter",
    "ollama",
)


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """Price of one model in USD per million tokens."""

    input: float
    output: float
    cache_read: float | None = None
    context: int | None = None  # tokens
    verified: bool = False
    note: str = ""


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    """A model provider: how it is configured and which model each profile uses."""

    name: str
    env: tuple[str, ...]  # any of these configures the provider
    profiles: Mapping[Profile, str]  # profile -> "provider:model"
    thinking: Mapping[Profile, str | bool | None] = field(default_factory=dict)
    cache: bool = False  # library-managed prompt caching worth enabling
    note: str = ""


PROVIDERS: Final[dict[str, ProviderInfo]] = {
    "anthropic": ProviderInfo(
        "anthropic",
        ("ANTHROPIC_API_KEY",),
        {
            "cheap": "anthropic:claude-haiku-4-5",
            "balanced": "anthropic:claude-sonnet-5",
            "quality": "anthropic:claude-opus-5",
        },
        # Haiku 4.5: budget-based thinking (low -> budget_tokens 2048);
        # Sonnet 5 / Opus 5: adaptive thinking + output_config.effort.
        {"cheap": "low", "balanced": "medium", "quality": "high"},
        cache=True,
    ),
    "openai": ProviderInfo(
        "openai",
        ("OPENAI_API_KEY",),
        {
            "cheap": "openai:gpt-6-luna",
            "balanced": "openai:gpt-6-sol",
            "quality": "openai:gpt-6-sol",
        },
        {"cheap": "low", "balanced": "medium", "quality": "high"},
        cache=True,
    ),
    "google": ProviderInfo(
        "google",
        ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
        {
            "cheap": "google:gemini-3.1-flash-lite",
            "balanced": "google:gemini-3.8-flash",
            "quality": "google:gemini-3.1-pro-preview",
        },
        {"cheap": "low", "balanced": "medium", "quality": "high"},
        note="free tier data-use terms unverified; do not send sensitive scans on it",
    ),
    "groq": ProviderInfo(
        "groq",
        ("GROQ_API_KEY",),
        {
            "cheap": "groq:openai/gpt-oss-20b",
            "balanced": "groq:openai/gpt-oss-120b",
            "quality": "groq:openai/gpt-oss-120b",
        },
        {"cheap": "low", "balanced": "medium", "quality": "high"},
    ),
    "mistral": ProviderInfo(
        "mistral",
        ("MISTRAL_API_KEY",),
        {
            "cheap": "mistral:ministral-8b-latest",
            "balanced": "mistral:mistral-small-latest",
            "quality": "mistral:mistral-large-latest",
        },
    ),
    "openrouter": ProviderInfo(
        "openrouter",
        ("OPENROUTER_API_KEY",),
        {
            "cheap": "openrouter:openai/gpt-oss-20b",
            "balanced": "openrouter:anthropic/claude-sonnet-5",
            "quality": "openrouter:anthropic/claude-opus-5",
        },
        note="never use ':free' routes for real scan data (they may log prompts)",
    ),
    "ollama": ProviderInfo(
        "ollama",
        ("OLLAMA_BASE_URL",),
        {
            "cheap": "ollama:granite4.1:8b",
            "balanced": "ollama:qwen3.8:27b",
            "quality": "ollama:qwen3.8:27b",
        },
        note="local, OpenAI-compatible endpoint (e.g. http://localhost:11434/v1); private",
    ),
}

#: Known model prices.  Models not listed here can still be used via ``--model``.
PRICES: Final[dict[str, ModelPrice]] = {
    # Anthropic (Anthropic model reference)
    "anthropic:claude-haiku-4-5": ModelPrice(1.0, 5.0, 0.10, 200_000, verified=True),
    "anthropic:claude-sonnet-5": ModelPrice(2.0, 10.0, 0.20, 1_000_000, verified=True),
    "anthropic:claude-opus-5": ModelPrice(5.0, 25.0, 0.50, 1_000_000, verified=True),
    "anthropic:claude-opus-5-5": ModelPrice(
        4.0, 20.0, None, 1_000_000, verified=True, note="use only when explicitly requested"
    ),
    "anthropic:claude-fable-5-1": ModelPrice(
        10.0, 50.0, None, 1_000_000, verified=True, note="most capable; explicit use only"
    ),
    "anthropic:claude-haiku-5-5": ModelPrice(
        0.10, 0.50, None, 1_000_000, note="not in Anthropic's model reference; explicit only"
    ),
    # OpenAI (developer docs pricing)
    "openai:gpt-6-luna": ModelPrice(0.10, 0.50, 0.01, 1_050_000, verified=True),
    "openai:gpt-6-sol": ModelPrice(2.0, 10.0, None, 1_050_000, verified=True),
    "openai:gpt-5-nano": ModelPrice(0.05, 0.40, None, 400_000, verified=True),
    "openai:gpt-5.6-luna": ModelPrice(0.20, 1.20, None, 1_050_000, verified=True),
    # Google (ai.google.dev pricing)
    "google:gemini-3.1-flash-lite": ModelPrice(0.25, 1.50, None, 1_000_000, verified=True),
    "google:gemini-3.5-flash-lite": ModelPrice(0.30, 2.50, None, 1_000_000, verified=True),
    "google:gemini-3.8-flash": ModelPrice(
        0.75, 3.75, None, 1_000_000, verified=True, note="1.50/7.50 from 2027-01-01"
    ),
    # Groq (Groq docs / genai-prices)
    "groq:openai/gpt-oss-20b": ModelPrice(0.075, 0.30, None, 131_072, verified=True),
    "groq:openai/gpt-oss-120b": ModelPrice(0.15, 0.60, None, 131_072),
    # Mistral (OpenRouter listing; Mistral's page did not render prices)
    "mistral:ministral-8b-latest": ModelPrice(0.15, 0.15, None, 262_144),
    "mistral:mistral-small-latest": ModelPrice(0.15, 0.60, None, 262_144),
    # OpenRouter (live /api/v1/models)
    "openrouter:openai/gpt-oss-20b": ModelPrice(0.018, 0.09, None, 131_072, verified=True),
    "openrouter:anthropic/claude-sonnet-5": ModelPrice(2.0, 10.0, None, 1_000_000),
    "openrouter:anthropic/claude-opus-5": ModelPrice(5.0, 25.0, None, 1_000_000),
    # Ollama (local)
    "ollama:granite4.1:8b": ModelPrice(0.0, 0.0, None, 128_000, verified=True, note="local"),
    "ollama:qwen3.8:27b": ModelPrice(0.0, 0.0, None, 256_000, verified=True, note="local"),
}


@dataclass(frozen=True, slots=True)
class ModelChoice:
    """The resolved model configuration for one analysis run."""

    provider: str
    orchestrator: str  # "provider:model"
    specialist: str
    profile: Profile
    fallbacks: tuple[str, ...] = ()  # same-profile models of other configured providers
    explicit: bool = False  # chosen with --model

    @property
    def models(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.orchestrator, self.specialist, *self.fallbacks)))


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def available_providers(env: Mapping[str, str] | None = None) -> dict[str, bool]:
    """Which providers are configured through their environment variables (priority order)."""
    e = _env(env)
    return {name: any(e.get(k) for k in PROVIDERS[name].env) for name in PRIORITY}


def detect_provider(env: Mapping[str, str] | None = None) -> str | None:
    """The first configured provider in :data:`PRIORITY`, or ``None``."""
    return next((n for n, ok in available_providers(env).items() if ok), None)


def provider_of(model: str) -> str:
    """The provider prefix of a ``provider:model`` string."""
    prefix, sep, rest = model.partition(":")
    if not sep or not prefix or not rest:
        raise AIConfigError(f"model must look like 'provider:model-id', got {model!r}")
    return prefix


_TIERS: Final[dict[Profile, tuple[Profile, Profile]]] = {
    "cheap": ("cheap", "cheap"),
    "balanced": ("balanced", "cheap"),
    "quality": ("quality", "balanced"),
}


def _tiers(profile: Profile) -> tuple[Profile, Profile]:
    """(orchestrator tier, specialist tier) for a profile."""
    return _TIERS[profile]


def resolve(
    *,
    provider: str | None = None,
    model: str | None = None,
    profile: str = "cheap",
    fallback: bool = True,
    env: Mapping[str, str] | None = None,
) -> ModelChoice:
    """Resolve CLI/API options into a :class:`ModelChoice`.

    ``model`` (``provider:id``) wins and is used for every agent.  Otherwise the
    provider (explicit or auto-detected) and profile pick orchestrator and specialist
    models; with ``fallback`` the same profile of every other configured provider is
    appended as a :class:`~pydantic_ai.models.fallback.FallbackModel` chain.
    """
    if profile not in PROFILES:
        raise AIConfigError(f"unknown profile {profile!r} (choose from {', '.join(PROFILES)})")
    prof: Profile = profile  # narrowed by the membership check above
    if model:
        if model == "test":
            return ModelChoice("test", "test", "test", prof, explicit=True)
        prov = provider_of(model)
        if provider and provider != prov:
            raise AIConfigError(f"--model {model!r} does not belong to --provider {provider!r}")
        return ModelChoice(prov, model, model, prof, explicit=True)
    available = available_providers(env)
    if provider:
        if provider not in PROVIDERS:
            raise AIConfigError(
                f"unknown provider {provider!r} (choose from {', '.join(PRIORITY)}, "
                "or pass --model provider:id)"
            )
        chosen = provider
    else:
        detected = detect_provider(env)
        if detected is None:
            keys = ", ".join(k for n in PRIORITY for k in PROVIDERS[n].env)
            raise AIConfigError(f"no AI provider configured: set one of {keys} or pass --model")
        chosen = detected
    orch_tier, spec_tier = _tiers(prof)
    info = PROVIDERS[chosen]
    fallbacks: tuple[str, ...] = ()
    if fallback:
        fallbacks = tuple(
            PROVIDERS[n].profiles[orch_tier] for n in PRIORITY if n != chosen and available[n]
        )
    return ModelChoice(
        chosen, info.profiles[orch_tier], info.profiles[spec_tier], prof, fallbacks=fallbacks
    )


def tier_of(model: str) -> Profile | None:
    """The profile tier a known model string is used for, if any."""
    for info in PROVIDERS.values():
        for tier, m in info.profiles.items():
            if m == model:
                return tier
    return None


def model_settings(model: str, profile: Profile | None = None) -> dict[str, Any]:
    """pydantic-ai ``ModelSettings`` for a model: thinking effort, caching, output budget.

    Uses the unified ``thinking`` setting, which pydantic-ai maps per provider
    (Anthropic Haiku 4.5 -> ``budget_tokens``; Sonnet 5 / Opus 5 -> adaptive thinking
    plus ``output_config.effort``; OpenAI -> ``reasoning_effort``; Gemini -> thinking
    config).  Unknown models get no thinking settings.
    """
    if model == "test":
        return {}
    prov = provider_of(model)
    info = PROVIDERS.get(prov)
    settings: dict[str, Any] = {"max_tokens": 16_000, "timeout": 120.0}
    if info is None:
        return settings
    tier = tier_of(model) or profile
    effort = info.thinking.get(tier) if tier else None
    if effort is not None:
        settings["thinking"] = effort
    if info.cache:
        settings["cache"] = True
    return settings


def price_for(model: str) -> ModelPrice | None:
    """Known price of ``provider:model`` (``None`` when unknown)."""
    return PRICES.get(model)


def estimate_cost(
    model: str | ModelPrice | None,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
) -> float | None:
    """Estimated USD cost of the given token usage (``None`` when the price is unknown).

    ``input_tokens`` includes ``cache_read_tokens`` (pydantic-ai's convention).
    """
    price = price_for(model) if isinstance(model, str) else model
    if price is None:
        return None
    cached = min(max(cache_read_tokens, 0), max(input_tokens, 0))
    cache_rate = price.cache_read if price.cache_read is not None else price.input
    uncached = max(input_tokens, 0) - cached
    total = uncached * price.input + cached * cache_rate + max(output_tokens, 0) * price.output
    return total / 1_000_000


def max_price(models: tuple[str, ...]) -> ModelPrice | None:
    """The most expensive known price among ``models`` (a conservative cost basis)."""
    prices = [p for p in (price_for(m) for m in models) if p is not None]
    if not prices:
        return None
    return max(prices, key=lambda p: (p.output, p.input))


def build_model(model: str, *, fallbacks: tuple[str, ...] = ()) -> Model:
    """Instantiate a pydantic-ai model (with a FallbackModel chain when given)."""
    models_mod = require("pydantic_ai.models")
    if model == "test":
        from pydantic_ai.models.test import TestModel

        return TestModel()
    try:
        primary: Model = models_mod.infer_model(model)
        if not fallbacks:
            return primary
        from pydantic_ai.models.fallback import FallbackModel

        return FallbackModel(primary, *(models_mod.infer_model(m) for m in fallbacks))
    except AIConfigError:
        raise
    except Exception as exc:  # provider SDK missing, key missing, unknown model ...
        raise AIConfigError(f"cannot use model {model!r}: {exc}") from exc
