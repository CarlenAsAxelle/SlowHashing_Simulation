"""Brute-force estimation helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


ESTIMATION_FIELDS = [
    "algorithm",
    "parameter",
    "password_scenario",
    "keyspace",
    "attacker_profile",
    "hash_per_sec",
    "avg_case_seconds",
    "worst_case_seconds",
    "avg_case_human",
    "worst_case_human",
    "source",
]


def calculate_keyspace(character_set_size: int, length: int) -> int:
    """Return the exhaustive-search keyspace size."""

    return character_set_size**length


def estimate_seconds(keyspace: int, hash_per_sec: float) -> tuple[float, float]:
    """Return average-case and worst-case brute-force seconds."""

    if hash_per_sec <= 0:
        raise ValueError("hash_per_sec must be positive")
    return keyspace / (2 * hash_per_sec), keyspace / hash_per_sec


def humanize_seconds(seconds: float) -> str:
    """Convert seconds to a compact human-readable duration."""

    if seconds < 1:
        return f"{seconds:.6f} seconds"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.2f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.2f} hours"
    days = hours / 24
    if days < 365.25:
        return f"{days:.2f} days"
    years = days / 365.25
    if years >= 1_000_000:
        return f"{years:.3e} years"
    return f"{years:,.2f} years"


def build_estimations(
    benchmark_rows: Iterable[dict[str, Any]],
    keyspace_scenarios: Iterable[dict[str, Any]],
    attacker_hash_rates: Mapping[tuple[str, str], Mapping[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Build brute-force estimation rows from benchmark and attacker rates."""

    rows = []
    scenarios = list(keyspace_scenarios)

    for benchmark in benchmark_rows:
        if benchmark.get("status") != "success":
            continue

        algorithm = benchmark["algorithm"]
        parameter = benchmark["parameter"]
        local_hash_per_sec = benchmark.get("local_hash_per_sec")
        if local_hash_per_sec and local_hash_per_sec > 0:
            rows.extend(
                _rows_for_profile(
                    algorithm=algorithm,
                    parameter=parameter,
                    profile_name="local_cpu",
                    hash_per_sec=float(local_hash_per_sec),
                    source="Eksperimen mandiri",
                    scenarios=scenarios,
                )
            )

        external_profiles = attacker_hash_rates.get((algorithm, parameter), {})
        for profile_name, profile in external_profiles.items():
            hash_per_sec = profile.get("hash_per_sec")
            if not hash_per_sec or hash_per_sec <= 0:
                continue
            rows.extend(
                _rows_for_profile(
                    algorithm=algorithm,
                    parameter=parameter,
                    profile_name=profile_name,
                    hash_per_sec=float(hash_per_sec),
                    source=profile.get("source", "Referensi eksternal"),
                    scenarios=scenarios,
                )
            )

    return rows


def _rows_for_profile(
    algorithm: str,
    parameter: str,
    profile_name: str,
    hash_per_sec: float,
    source: str,
    scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for scenario in scenarios:
        keyspace = calculate_keyspace(
            scenario["character_set_size"],
            scenario["length"],
        )
        avg_seconds, worst_seconds = estimate_seconds(keyspace, hash_per_sec)
        rows.append(
            {
                "algorithm": algorithm,
                "parameter": parameter,
                "password_scenario": scenario["name"],
                "keyspace": keyspace,
                "attacker_profile": profile_name,
                "hash_per_sec": hash_per_sec,
                "avg_case_seconds": avg_seconds,
                "worst_case_seconds": worst_seconds,
                "avg_case_human": humanize_seconds(avg_seconds),
                "worst_case_human": humanize_seconds(worst_seconds),
                "source": source,
            }
        )
    return rows
