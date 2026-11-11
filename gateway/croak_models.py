"""The model registry (models.yaml): one place for everything about the models.

croak-gate's LiteLLM model_list is generated from it (make_config.py), the
policy hook will turn a request's reasoning level into the model's own
parameters with it, and logged-in clients will get the listed models' names
and levels from it. Which engine and model serve an alias is written here and
nowhere else, so the engine can change without touching the clients.

The repository copy holds the current aliases with placeholder model
details; the production registry is kept outside it (like policy.yaml).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ENGINES = ("vllm", "sglang", "llamacpp", "tensorfold", "unknown")
LEVELS = ("none", "low", "high")
UPSTREAM_KEYS = ("model", "api_base", "api_key", "timeout", "stream_timeout", "num_retries")


@dataclass(frozen=True)
class Reasoning:
    default: str
    levels: dict[str, dict[str, Any]]
    max_reasoning_tokens: int | None = None


@dataclass(frozen=True)
class Model:
    name: str
    display: str
    listed: bool
    served_model: str
    engine: str
    upstream: dict[str, Any]
    limits: dict[str, int] = field(default_factory=dict)
    reasoning: Reasoning | None = None


def load_registry(data: dict[str, Any]) -> list[Model]:
    """The models in file order. Raises ValueError naming the first problem."""
    if not isinstance(data, dict) or not isinstance(data.get("models"), dict) or not data["models"]:
        raise ValueError("models.yaml needs a non-empty 'models' mapping")
    defaults = data.get("upstream_defaults") or {}
    unknown = set(defaults) - set(UPSTREAM_KEYS)
    if unknown:
        raise ValueError(f"upstream_defaults: unknown keys {sorted(unknown)}")
    models = []
    for name, raw in data["models"].items():
        models.append(_model(str(name), raw or {}, defaults))
    return models


def _model(name: str, raw: dict[str, Any], defaults: dict[str, Any]) -> Model:
    known = {"display", "listed", "served_model", "engine", "upstream", "limits", "reasoning"}
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"model {name}: unknown keys {sorted(unknown)}")
    engine = str(raw.get("engine", "unknown"))
    if engine not in ENGINES:
        raise ValueError(f"model {name}: engine must be one of {', '.join(ENGINES)}")
    upstream = {**defaults, **(raw.get("upstream") or {})}
    if set(upstream) - set(UPSTREAM_KEYS):
        raise ValueError(f"model {name}: unknown upstream keys {sorted(set(upstream) - set(UPSTREAM_KEYS))}")
    if not upstream.get("model"):
        raise ValueError(f"model {name}: upstream.model is required")
    limits = raw.get("limits") or {}
    if not all(isinstance(v, int) and v > 0 for v in limits.values()) or set(limits) - {"context", "output"}:
        raise ValueError(f"model {name}: limits takes positive integers 'context' and 'output'")
    return Model(
        name=name,
        display=str(raw.get("display") or name),
        listed=bool(raw.get("listed", True)),
        served_model=str(raw.get("served_model") or "unknown"),
        engine=engine,
        # Keep LiteLLM's usual key order so the generated file reads like the hand-written one.
        upstream={k: upstream[k] for k in UPSTREAM_KEYS if k in upstream},
        limits=dict(limits),
        reasoning=_reasoning(name, raw["reasoning"]) if raw.get("reasoning") is not None else None,
    )


def _reasoning(name: str, raw: dict[str, Any]) -> Reasoning:
    levels = raw.get("levels") or {}
    if set(levels) != set(LEVELS):
        raise ValueError(f"model {name}: reasoning.levels must define exactly {', '.join(LEVELS)}")
    if not all(isinstance(v, dict) for v in levels.values()):
        raise ValueError(f"model {name}: each reasoning level is a mapping of request parameters")
    default = str(raw.get("default", "none"))
    if default not in LEVELS:
        raise ValueError(f"model {name}: reasoning.default must be one of {', '.join(LEVELS)}")
    cap = raw.get("max_reasoning_tokens")
    if cap is not None and not (isinstance(cap, int) and cap > 0):
        raise ValueError(f"model {name}: max_reasoning_tokens is a positive integer or null")
    return Reasoning(default=default, levels={k: dict(levels[k]) for k in LEVELS}, max_reasoning_tokens=cap)


def model_list(models: list[Model]) -> list[dict[str, Any]]:
    """LiteLLM's model_list: one entry per alias, pointing at the upstream."""
    return [{"model_name": m.name, "litellm_params": dict(m.upstream)} for m in models]
