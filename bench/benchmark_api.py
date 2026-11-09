#!/usr/bin/env python3
"""Reproducible streaming benchmark for an OpenAI-compatible chat API.

The implementation intentionally uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import statistics
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request


PROMPT_PREFIX = (
    "This is a deterministic inference benchmark. "
    "Request nonce: {nonce}. "
    "After silently reading the padding, keep producing the word benchmark "
    "separated by spaces until the server stops you.\nPadding:\n"
)
UNKNOWN = "확인 불가"
SAMPLE_FIELDS = [
    "group",
    "concurrency",
    "target_input_tokens",
    "actual_input_tokens",
    "requested_output_tokens",
    "actual_output_tokens",
    "repeat",
    "request_index",
    "ttft_seconds",
    "e2e_seconds",
    "decode_tokens_per_second",
    "finish_reason",
    "wave_wall_seconds",
    "wave_aggregate_output_tps",
    "wave_aggregate_decode_tps",
    "error",
]


QUICK_CONDITIONS = [
    ("single", 1, 1024, 128),
    ("single", 1, 8192, 256),
    ("concurrency", 2, 8192, 256),
    ("concurrency", 10, 8192, 256),
]

BALANCED_CONDITIONS = [
    *[("single", 1, input_tokens, output_tokens) for input_tokens in (1024, 8192, 32768) for output_tokens in (128, 512)],
    *[("concurrency", concurrency, 8192, 256) for concurrency in (1, 2, 4, 6, 8, 10)],
    *[("c10-mix", 10, input_tokens, output_tokens) for input_tokens, output_tokens in ((1024, 128), (8192, 128), (32768, 128), (8192, 512))],
]


class BenchmarkError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    api_base_url: str
    model_id: str
    api_key: str
    timeout: float
    output_root: Path

    @property
    def server_root(self) -> str:
        return re.sub(r"/v1/?$", "", self.api_base_url.rstrip("/"))

    @property
    def chat_url(self) -> str:
        return f"{self.api_base_url.rstrip('/')}/chat/completions"

    @property
    def models_url(self) -> str:
        return f"{self.api_base_url.rstrip('/')}/models"

    @property
    def tokenize_url(self) -> str:
        return f"{self.server_root}/tokenize"

    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-base-url", default=os.environ.get("API_BASE_URL"))
    parser.add_argument("--model-id", default=os.environ.get("MODEL_ID"))
    parser.add_argument("--api-key", default=os.environ.get("API_KEY"))
    parser.add_argument("--preset", choices=("quick", "balanced", "all"), default="all")
    parser.add_argument("--timeout", type=float, default=1800.0)
    parser.add_argument("--output-root", type=Path, default=Path("benchmark-results"))
    args = parser.parse_args()
    missing = [name for name in ("api_base_url", "model_id", "api_key") if not getattr(args, name)]
    if missing:
        parser.error(f"missing required values: {', '.join(missing)}")
    return args


def http_json(
    config: Config,
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> Any:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = request.Request(url, data=body, headers=config.headers(), method=method)
    try:
        with request.urlopen(req, timeout=timeout or config.timeout) as response:
            raw = response.read()
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BenchmarkError(f"HTTP {exc.code} for {url}: {detail[:2000]}") from exc
    except error.URLError as exc:
        raise BenchmarkError(f"request failed for {url}: {exc}") from exc
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"non-JSON response from {url}: {raw[:1000]!r}") from exc


def http_text(config: Config, url: str, timeout: float = 15.0) -> str:
    req = request.Request(url, headers=config.headers(), method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (error.HTTPError, error.URLError, TimeoutError):
        return ""


def validate_api(config: Config) -> dict[str, Any]:
    payload = http_json(config, "GET", config.models_url, timeout=30.0)
    ids = [item.get("id") for item in payload.get("data", []) if isinstance(item, dict)]
    if config.model_id not in ids:
        raise BenchmarkError(f"MODEL_ID {config.model_id!r} not found; available IDs: {ids}")
    return next(item for item in payload["data"] if item.get("id") == config.model_id)


def prompt_messages(nonce: str, repeats: int) -> list[dict[str, str]]:
    content = PROMPT_PREFIX.format(nonce=nonce) + (" x" * repeats)
    return [{"role": "user", "content": content}]


def token_count(config: Config, messages: list[dict[str, str]]) -> int:
    payload = http_json(
        config,
        "POST",
        config.tokenize_url,
        {"model": config.model_id, "messages": messages},
        timeout=120.0,
    )
    candidates = (payload.get("count"), payload.get("token_count"))
    for value in candidates:
        if isinstance(value, int):
            return value
    tokens = payload.get("tokens")
    if isinstance(tokens, list):
        return len(tokens)
    raise BenchmarkError(f"/tokenize response has no token count: {str(payload)[:1000]}")


def calibrate_messages(config: Config, target_tokens: int) -> tuple[list[dict[str, str]], int, int]:
    nonce = uuid.uuid4().hex
    zero = token_count(config, prompt_messages(nonce, 0))
    probe_repeats = 1024
    probe = token_count(config, prompt_messages(nonce, probe_repeats))
    tokens_per_repeat = (probe - zero) / probe_repeats
    if tokens_per_repeat <= 0:
        raise BenchmarkError(
            f"invalid tokens-per-repeat calibration: zero={zero}, probe={probe}, repeats={probe_repeats}"
        )

    repeats = max(0, round((target_tokens - zero) / tokens_per_repeat))
    best: tuple[int, int, int] | None = None
    visited: set[int] = set()
    for _ in range(4):
        repeats = max(0, repeats)
        if repeats in visited:
            break
        visited.add(repeats)
        messages = prompt_messages(nonce, repeats)
        actual = token_count(config, messages)
        distance = abs(target_tokens - actual)
        if best is None or distance < best[0]:
            best = (distance, repeats, actual)
        if distance <= 2:
            return messages, actual, repeats
        correction = round((target_tokens - actual) / tokens_per_repeat)
        if correction == 0:
            correction = 1 if actual < target_tokens else -1
        repeats += correction

    assert best is not None
    if best[0] <= 2:
        messages = prompt_messages(nonce, best[1])
        return messages, best[2], best[1]
    raise BenchmarkError(
        f"input calibration missed target {target_tokens}: best={best[2]}, repeats={best[1]}, distance={best[0]}"
    )


def nonempty_stream_value(delta: Any) -> bool:
    if not isinstance(delta, dict):
        return False
    for key in ("content", "reasoning", "reasoning_content"):
        value = delta.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, (list, dict)) and value:
            return True
    return False


def stream_request(
    config: Config,
    messages: list[dict[str, str]],
    output_tokens: int,
    barrier: threading.Barrier,
) -> dict[str, Any]:
    payload = {
        "model": config.model_id,
        "messages": messages,
        "temperature": 0.0,
        "max_tokens": output_tokens,
        "min_tokens": output_tokens,
        "ignore_eos": True,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    req = request.Request(
        config.chat_url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers=config.headers(),
        method="POST",
    )
    barrier.wait(timeout=60.0)
    started = time.perf_counter()
    first_value_at: float | None = None
    usage: dict[str, Any] | None = None
    finish_reason: str | None = None
    try:
        with request.urlopen(req, timeout=config.timeout) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line or line.startswith(":"):
                    continue
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    continue
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError as exc:
                    raise BenchmarkError(f"invalid SSE JSON: {data[:1000]}") from exc
                if isinstance(chunk.get("usage"), dict):
                    usage = chunk["usage"]
                choices = chunk.get("choices") or []
                for choice in choices:
                    if first_value_at is None and nonempty_stream_value(choice.get("delta")):
                        first_value_at = time.perf_counter()
                    if choice.get("finish_reason") is not None:
                        finish_reason = str(choice["finish_reason"])
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BenchmarkError(f"HTTP {exc.code}: {detail[:2000]}") from exc
    except error.URLError as exc:
        raise BenchmarkError(f"stream request failed: {exc}") from exc
    ended = time.perf_counter()

    if first_value_at is None:
        raise BenchmarkError("stream ended without a non-empty content/reasoning/reasoning_content delta")
    if usage is None:
        raise BenchmarkError("stream ended without a final usage object")
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    if not isinstance(prompt_tokens, int) or not isinstance(completion_tokens, int):
        raise BenchmarkError(f"final usage is missing integer prompt_tokens/completion_tokens: {usage}")

    ttft = first_value_at - started
    e2e = ended - started
    decode_window = e2e - ttft
    if decode_window <= 0:
        raise BenchmarkError(f"non-positive decode window: e2e={e2e}, ttft={ttft}")
    return {
        "actual_input_tokens": prompt_tokens,
        "actual_output_tokens": completion_tokens,
        "ttft_seconds": ttft,
        "e2e_seconds": e2e,
        "decode_tokens_per_second": (completion_tokens - 1) / decode_window,
        "finish_reason": finish_reason,
        "_started": started,
        "_ended": ended,
    }


def metric_value(metrics: str, name: str) -> float | None:
    values = []
    pattern = re.compile(rf"^{re.escape(name)}(?:\{{[^}}]*\}})?\s+([-+0-9.eE]+)$")
    for line in metrics.splitlines():
        match = pattern.match(line)
        if match:
            values.append(float(match.group(1)))
    return sum(values) if values else None


def metrics_snapshot(config: Config) -> dict[str, float | None] | None:
    metrics = http_text(config, f"{config.server_root}/metrics")
    if not metrics:
        return None
    return {
        "running": metric_value(metrics, "vllm:num_requests_running"),
        "waiting": metric_value(metrics, "vllm:num_requests_waiting"),
        "success_total": metric_value(metrics, "vllm:request_success_total"),
        "prompt_tokens_total": metric_value(metrics, "vllm:prompt_tokens_total"),
        "generation_tokens_total": metric_value(metrics, "vllm:generation_tokens_total"),
    }


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        raise BenchmarkError("cannot calculate a percentile of an empty list")
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def run_wave(
    config: Config,
    group: str,
    concurrency: int,
    target_input_tokens: int,
    requested_output_tokens: int,
    repeat: int,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, float | None] | None]:
    prepared = []
    for request_index in range(concurrency):
        messages, calibrated_tokens, padding_repeats = calibrate_messages(config, target_input_tokens)
        prepared.append((request_index, messages, calibrated_tokens, padding_repeats))

    load_before = metrics_snapshot(config)
    barrier = threading.Barrier(concurrency + 1)
    samples: list[dict[str, Any]] = []
    futures: dict[Any, tuple[int, int, int]] = {}
    executor = ThreadPoolExecutor(max_workers=concurrency)
    for request_index, messages, calibrated_tokens, padding_repeats in prepared:
        future = executor.submit(stream_request, config, messages, requested_output_tokens, barrier)
        futures[future] = (request_index, calibrated_tokens, padding_repeats)
    wave_started = time.perf_counter()
    barrier.wait(timeout=60.0)
    _, unfinished_at_deadline = wait(futures, timeout=config.timeout)
    # Running Python threads cannot be killed safely. Wait for socket cleanup, then
    # retain their measurements while still marking the exceeded wave deadline.
    executor.shutdown(wait=True, cancel_futures=True)
    for future, (request_index, calibrated_tokens, padding_repeats) in futures.items():
        base = {
            "group": group,
            "concurrency": concurrency,
            "target_input_tokens": target_input_tokens,
            "actual_input_tokens": calibrated_tokens,
            "requested_output_tokens": requested_output_tokens,
            "actual_output_tokens": None,
            "repeat": repeat,
            "request_index": request_index,
            "ttft_seconds": None,
            "e2e_seconds": None,
            "decode_tokens_per_second": None,
            "finish_reason": None,
            "wave_wall_seconds": None,
            "wave_aggregate_output_tps": None,
            "wave_aggregate_decode_tps": None,
            "error": None,
            "_padding_repeats": padding_repeats,
        }
        try:
            measured = future.result()
            base.update(measured)
            if abs(measured["actual_input_tokens"] - target_input_tokens) > 2:
                raise BenchmarkError(
                    f"server usage prompt_tokens {measured['actual_input_tokens']} differs from target "
                    f"{target_input_tokens} by more than 2"
                )
            if future in unfinished_at_deadline:
                raise TimeoutError(f"request unfinished at {config.timeout:.0f}s request deadline")
        except Exception as exc:  # The sample must retain every request failure.
            base["error"] = f"{type(exc).__name__}: {exc}"
        samples.append(base)
    wave_ended = time.perf_counter()
    wave_wall = wave_ended - wave_started

    successful = [sample for sample in samples if not sample["error"]]
    aggregate_output_tps = None
    aggregate_decode_tps = None
    if len(successful) == concurrency:
        output_sum = sum(sample["actual_output_tokens"] for sample in successful)
        decode_numerator = sum(sample["actual_output_tokens"] - 1 for sample in successful)
        decode_denominator = max(sample["e2e_seconds"] for sample in successful) - min(
            sample["ttft_seconds"] for sample in successful
        )
        if decode_denominator <= 0:
            for sample in successful:
                sample["error"] = f"non-positive wave aggregate decode window: {decode_denominator}"
        else:
            aggregate_output_tps = output_sum / wave_wall
            aggregate_decode_tps = decode_numerator / decode_denominator
            for sample in successful:
                sample["wave_wall_seconds"] = wave_wall
                sample["wave_aggregate_output_tps"] = aggregate_output_tps
                sample["wave_aggregate_decode_tps"] = aggregate_decode_tps

    samples.sort(key=lambda sample: sample["request_index"])
    wave = {
        "group": group,
        "concurrency": concurrency,
        "target_input_tokens": target_input_tokens,
        "requested_output_tokens": requested_output_tokens,
        "repeat": repeat,
        "requests": concurrency,
        "successful_requests": len([sample for sample in samples if not sample["error"]]),
        "wave_wall_seconds": wave_wall,
        "aggregate_output_tps": aggregate_output_tps,
        "aggregate_decode_tps": aggregate_decode_tps,
    }
    return samples, wave, load_before


def condition_key(sample: dict[str, Any]) -> tuple[Any, ...]:
    return (
        sample["group"],
        sample["concurrency"],
        sample["target_input_tokens"],
        sample["requested_output_tokens"],
    )


def summarize(samples: list[dict[str, Any]], waves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for sample in samples:
        grouped.setdefault(condition_key(sample), []).append(sample)
    summaries = []
    for key, rows in grouped.items():
        group, concurrency, target_input_tokens, requested_output_tokens = key
        good = [row for row in rows if not row["error"]]
        condition_waves = [
            wave
            for wave in waves
            if (
                wave["group"],
                wave["concurrency"],
                wave["target_input_tokens"],
                wave["requested_output_tokens"],
            )
            == key
        ]
        matching_waves = [wave for wave in condition_waves if wave["aggregate_decode_tps"] is not None]
        complete_wave_set = bool(condition_waves) and len(matching_waves) == len(condition_waves)
        item = {
            "group": group,
            "concurrency": concurrency,
            "target_input_tokens": target_input_tokens,
            "requested_output_tokens": requested_output_tokens,
            "requests": len(rows),
            "input_tokens": sum(row["actual_input_tokens"] for row in good),
            "output_tokens": sum(row["actual_output_tokens"] for row in good),
            "ttft_p50_s": percentile([row["ttft_seconds"] for row in good], 0.50) if good else None,
            "ttft_p95_s": percentile([row["ttft_seconds"] for row in good], 0.95) if good else None,
            "decode_tps_mean": statistics.fmean(row["decode_tokens_per_second"] for row in good) if good else None,
            "decode_tps_p50": percentile([row["decode_tokens_per_second"] for row in good], 0.50) if good else None,
            "aggregate_decode_tps": percentile(
                [wave["aggregate_decode_tps"] for wave in matching_waves], 0.50
            )
            if complete_wave_set
            else None,
            "e2e_p50_s": percentile([row["e2e_seconds"] for row in good], 0.50) if good else None,
            "e2e_p95_s": percentile([row["e2e_seconds"] for row in good], 0.95) if good else None,
            "aggregate_output_tps": percentile(
                [wave["aggregate_output_tps"] for wave in matching_waves], 0.50
            )
            if complete_wave_set
            else None,
        }
        summaries.append(item)
    return sorted(summaries, key=lambda row: (row["group"], row["concurrency"], row["target_input_tokens"], row["requested_output_tokens"]))


def clean_sample(sample: dict[str, Any]) -> dict[str, Any]:
    return {field: sample.get(field) for field in SAMPLE_FIELDS}


def format_number(value: Any, digits: int = 3) -> str:
    if value is None:
        return "FAIL"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def metadata_report_lines(metadata: dict[str, Any]) -> list[str]:
    labels = [
        ("측정 시각", "measured_at"),
        ("API URL", "api_url"),
        ("모델 ID", "model_id"),
        ("GPU 종류", "gpu_type"),
        ("GPU 수", "gpu_count"),
        ("런타임/vLLM 버전", "runtime_version"),
        ("Tensor parallel", "tensor_parallel"),
        ("Max model length", "max_model_length"),
        ("Max sequences", "max_sequences"),
        ("Max batched tokens", "max_batched_tokens"),
        ("KV cache dtype", "kv_cache_dtype"),
        ("Quantization", "quantization"),
        ("Speculative decoding", "speculative_decoding"),
    ]
    return [f"- {label}: {metadata.get(key, UNKNOWN)}" for label, key in labels]


def build_report(
    preset: str,
    metadata: dict[str, Any],
    summaries: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    external_load: dict[str, Any],
) -> str:
    success = bool(samples) and all(not sample.get("error") for sample in samples)
    lines = [
        f"# Streaming benchmark: {preset}",
        "",
        *metadata_report_lines(metadata),
        f"- 프리셋 성공: {'성공' if success else '실패'}",
        f"- 외부 부하: {external_load['status']}",
        "",
        "## 결과",
        "",
        "| Group | C | Input target | Output requested | Requests | TTFT p50 (s) | TTFT p95 (s) | Decode mean tok/s | Decode p50 tok/s | Aggregate decode tok/s | E2E p50 (s) | E2E p95 (s) | Aggregate output tok/s |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summaries:
        lines.append(
            "| {group} | {concurrency} | {target_input_tokens} | {requested_output_tokens} | {requests} | {ttft_p50_s} | {ttft_p95_s} | {decode_tps_mean} | {decode_tps_p50} | {aggregate_decode_tps} | {e2e_p50_s} | {e2e_p95_s} | {aggregate_output_tps} |".format(
                **{key: format_number(value) for key, value in row.items()}
            )
        )
    errors = [sample for sample in samples if sample.get("error")]
    lines.extend(["", "## 오류", ""])
    if not errors:
        lines.append("- 없음")
    else:
        for sample in errors:
            lines.append(
                f"- {sample['group']} C{sample['concurrency']} {sample['target_input_tokens']}/{sample['requested_output_tokens']} "
                f"repeat={sample['repeat']} request={sample['request_index']}: {sample['error']}"
            )
    lines.extend(["", "## 외부 부하 판정", "", f"- {external_load['details']}", ""])
    return "\n".join(lines)


def write_artifacts(
    output_dir: Path,
    preset: str,
    metadata: dict[str, Any],
    samples: list[dict[str, Any]],
    waves: list[dict[str, Any]],
    external_load: dict[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    clean_samples = [clean_sample(sample) for sample in samples]
    summaries = summarize(samples, waves) if samples else []
    errors = [sample["error"] for sample in clean_samples if sample.get("error")]
    summary_payload = {
        "preset": preset,
        "success": bool(samples) and not errors,
        "metadata": metadata,
        "external_load": external_load,
        "errors": errors,
        "conditions": summaries,
        "waves": waves,
    }
    (output_dir / "samples.json").write_text(
        json.dumps(clean_samples, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    with (output_dir / "samples.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SAMPLE_FIELDS)
        writer.writeheader()
        writer.writerows(clean_samples)
    (output_dir / "summary.json").write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(
        build_report(preset, metadata, summaries, samples, external_load), encoding="utf-8"
    )


def external_load_assessment(
    before: dict[str, float | None] | None,
    after: dict[str, float | None] | None,
    pre_wave_loads: list[dict[str, float | None] | None],
    own_requests: int,
) -> dict[str, Any]:
    if before is None or after is None or any(item is None for item in pre_wave_loads):
        return {"status": UNKNOWN, "details": "메트릭을 완전하게 읽을 수 없어 외부 부하를 판정할 수 없음"}
    busy = [
        item
        for item in pre_wave_loads
        if (item.get("running") or 0) > 0 or (item.get("waiting") or 0) > 0
    ]
    success_before = before.get("success_total")
    success_after = after.get("success_total")
    extra = None
    if success_before is not None and success_after is not None:
        extra = (success_after - success_before) - own_requests
    observed = bool(busy) or (extra is not None and extra > 0.5)
    success_delta = UNKNOWN if success_before is None or success_after is None else f"{success_after - success_before:.0f}"
    details = (
        f"wave 시작 전 busy 관측={len(busy)}회; request_success_total 증가분={success_delta}; "
        f"자체 시도 요청={own_requests}; 추정 외부 완료 요청={UNKNOWN if extra is None else max(0, round(extra))}"
    )
    return {"status": "관측됨" if observed else "관측되지 않음", "details": details}


def collect_metadata(config: Config, model_info: dict[str, Any]) -> dict[str, Any]:
    version = http_text(config, f"{config.server_root}/version")
    runtime_version = UNKNOWN
    if version:
        try:
            runtime_version = json.loads(version).get("version", UNKNOWN)
        except json.JSONDecodeError:
            runtime_version = version.strip() or UNKNOWN
    metrics = http_text(config, f"{config.server_root}/metrics")
    speculative = UNKNOWN
    drafts = metric_value(metrics, "vllm:spec_decode_num_draft_tokens_total") if metrics else None
    if drafts is not None:
        speculative = "활성" if drafts > 0 else "비활성 또는 미사용"
    return {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "api_url": config.api_base_url,
        "model_id": config.model_id,
        "gpu_type": UNKNOWN,
        "gpu_count": UNKNOWN,
        "runtime_version": runtime_version,
        "tensor_parallel": UNKNOWN,
        "max_model_length": model_info.get("max_model_len", UNKNOWN),
        "max_sequences": UNKNOWN,
        "max_batched_tokens": UNKNOWN,
        "kv_cache_dtype": UNKNOWN,
        "quantization": UNKNOWN,
        "speculative_decoding": speculative,
    }


def run_preset(
    config: Config,
    preset: str,
    metadata: dict[str, Any],
    conditions: list[tuple[str, int, int, int]],
    repeats: int,
) -> tuple[bool, int]:
    output_dir = config.output_root / preset
    samples: list[dict[str, Any]] = []
    waves: list[dict[str, Any]] = []
    pre_wave_loads: list[dict[str, float | None] | None] = []
    before = metrics_snapshot(config)
    external_load = {"status": UNKNOWN, "details": "실행 중"}
    write_artifacts(output_dir, preset, metadata, samples, waves, external_load)

    total_waves = len(conditions) * repeats
    wave_number = 0
    for group, concurrency, input_tokens, output_tokens in conditions:
        for repeat in range(1, repeats + 1):
            wave_number += 1
            print(
                f"[{preset}] wave {wave_number}/{total_waves}: {group} C{concurrency} input={input_tokens} output={output_tokens} repeat={repeat}",
                flush=True,
            )
            try:
                wave_samples, wave, load_before = run_wave(
                    config, group, concurrency, input_tokens, output_tokens, repeat
                )
                samples.extend(wave_samples)
                waves.append(wave)
                pre_wave_loads.append(load_before)
                failed = [sample for sample in wave_samples if sample["error"]]
                print(
                    f"[{preset}] wave {wave_number}: success={len(wave_samples) - len(failed)}/{len(wave_samples)} "
                    f"aggregate_decode_tps={format_number(wave['aggregate_decode_tps'])}",
                    flush=True,
                )
            except Exception as exc:
                samples.append(
                    {
                        "group": group,
                        "concurrency": concurrency,
                        "target_input_tokens": input_tokens,
                        "actual_input_tokens": None,
                        "requested_output_tokens": output_tokens,
                        "actual_output_tokens": None,
                        "repeat": repeat,
                        "request_index": -1,
                        "ttft_seconds": None,
                        "e2e_seconds": None,
                        "decode_tokens_per_second": None,
                        "finish_reason": None,
                        "wave_wall_seconds": None,
                        "wave_aggregate_output_tps": None,
                        "wave_aggregate_decode_tps": None,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                print(f"[{preset}] wave {wave_number}: FAILED: {type(exc).__name__}: {exc}", flush=True)
            write_artifacts(output_dir, preset, metadata, samples, waves, external_load)

    after = metrics_snapshot(config)
    own_attempts = sum(wave["requests"] for wave in waves)
    external_load = external_load_assessment(before, after, pre_wave_loads, own_attempts)
    write_artifacts(output_dir, preset, metadata, samples, waves, external_load)
    success = bool(samples) and all(not sample.get("error") for sample in samples)
    print(f"[{preset}] {'SUCCESS' if success else 'FAILED'}: requests={len(samples)} output={output_dir}", flush=True)
    return success, len(samples)


def warmup(config: Config) -> None:
    print("[warmup] C1 input=1024 output=32", flush=True)
    samples, _, _ = run_wave(config, "warmup", 1, 1024, 32, 1)
    failures = [sample["error"] for sample in samples if sample["error"]]
    if failures:
        raise BenchmarkError(f"warmup failed: {failures}")
    print("[warmup] SUCCESS", flush=True)


def main() -> int:
    args = parse_args()
    run_id = datetime.now(timezone.utc).strftime("head-streaming-%Y%m%dT%H%M%SZ")
    output_root = args.output_root.expanduser().resolve() / run_id
    config = Config(
        api_base_url=args.api_base_url.rstrip("/"),
        model_id=args.model_id,
        api_key=args.api_key,
        timeout=args.timeout,
        output_root=output_root,
    )
    print(f"[validate] API={config.api_base_url} model={config.model_id}", flush=True)
    try:
        model_info = validate_api(config)
        probe_messages, actual, _ = calibrate_messages(config, 1024)
        if abs(actual - 1024) > 2 or not probe_messages:
            raise BenchmarkError(f"tokenization probe failed: actual={actual}")
        metadata = collect_metadata(config, model_info)
        print(f"[validate] SUCCESS: tokenize={actual}, output_root={output_root}", flush=True)
        warmup(config)

        total_requests = 0
        quick_success = None
        balanced_success = None
        if args.preset in ("quick", "all"):
            quick_success, count = run_preset(config, "quick", metadata, QUICK_CONDITIONS, repeats=1)
            total_requests += count
        if args.preset == "all" and not quick_success:
            print("[balanced] SKIPPED because quick failed", flush=True)
        elif args.preset in ("balanced", "all"):
            balanced_success, count = run_preset(config, "balanced", metadata, BALANCED_CONDITIONS, repeats=3)
            total_requests += count

        overall = (quick_success is not False) and (balanced_success is not False)
        print(
            f"[done] success={overall} quick={quick_success} balanced={balanced_success} "
            f"benchmark_requests={total_requests} output_root={output_root}",
            flush=True,
        )
        return 0 if overall else 1
    except Exception as exc:
        output_root.mkdir(parents=True, exist_ok=True)
        failure = {
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
            "api_url": config.api_base_url,
            "model_id": config.model_id,
            "measured_at": datetime.now(timezone.utc).isoformat(),
        }
        (output_root / "failure.json").write_text(
            json.dumps(failure, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"[fatal] {failure['error']}; output_root={output_root}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
