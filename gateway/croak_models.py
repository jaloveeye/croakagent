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
    if set(raw) - {"default", "levels"}:
        raise ValueError(f"model {name}: reasoning takes 'default' and 'levels' (a safety cap goes into a level's parameters)")
    return Reasoning(default=default, levels={k: dict(levels[k]) for k in LEVELS})


def model_list(models: list[Model]) -> list[dict[str, Any]]:
    """LiteLLM's model_list: one entry per alias, pointing at the upstream."""
    return [{"model_name": m.name, "litellm_params": dict(m.upstream)} for m in models]


class UnknownLevel(ValueError):
    """The request asked for a reasoning level the model does not define."""


def _merge(into: dict[str, Any], extra: dict[str, Any]) -> None:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(into.get(key), dict):
            _merge(into[key], value)
        else:
            into[key] = value


def apply_level(model: Model | None, data: dict[str, Any]) -> dict[str, Any]:
    """Turns the request's reasoning level into the model's own parameters.

    croakcode sends reasoning_effort none, low or high. For a model with
    reasoning levels it is removed and that level's parameters are merged into
    the request; without one the model's default level applies. Aliases the
    registry does not know, or that have no levels (older clients), pass
    unchanged. Returns what to record about the request.
    """
    if model is None:
        return {"alias": data.get("model"), "served_model": "unknown", "engine": "unknown", "reasoning": None}
    record = {"alias": model.name, "served_model": model.served_model, "engine": model.engine, "reasoning": None}
    if model.reasoning is None:
        return record
    asked = data.pop("reasoning_effort", None)
    level = str(asked) if asked is not None else model.reasoning.default
    if level not in model.reasoning.levels:
        raise UnknownLevel(f"추론 수준 {level}은 이 모델에 없다. {', '.join(LEVELS)} 가운데 하나를 쓴다.")
    _merge(data, _copy(model.reasoning.levels[level]))
    record["reasoning"] = level
    return record


def _copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_copy(v) for v in value]
    return value


_cache: dict[str, Any] = {"path": None, "mtime": None, "models": {}}


def current_models(path: str) -> dict[str, Model]:
    """The registry at path by alias, reloaded when the file changes. A missing file is empty."""
    import os

    import yaml

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _cache["path"] != path or _cache["mtime"] != mtime:
        with open(path, encoding="utf-8") as f:
            models = load_registry(yaml.safe_load(f) or {})
        _cache.update(path=path, mtime=mtime, models={m.name: m for m in models})
    return _cache["models"]


def client_list(models: list[Model]) -> list[dict[str, Any]]:
    """What a logged-in client may know: the listed aliases, their names, levels and limits.

    The served model and engine are left out; they are for the records only.
    """
    return [
        {
            "id": m.name,
            "display": m.display,
            "levels": list(m.reasoning.levels) if m.reasoning else [],
            "default_level": m.reasoning.default if m.reasoning else None,
            "limits": dict(m.limits),
        }
        for m in models
        if m.listed
    ]
