"""Benchmark helpers for slow password hashing algorithms."""

from __future__ import annotations

import hashlib
import os
import statistics
import time
from collections.abc import Iterable
from typing import Any

try:
    import bcrypt
except ImportError:  # pragma: no cover - exercised only when dependency is absent
    bcrypt = None

try:
    from argon2.low_level import Type, hash_secret_raw
except ImportError:  # pragma: no cover - exercised only when dependency is absent
    Type = None
    hash_secret_raw = None


BENCHMARK_FIELDS = [
    "algorithm",
    "parameter",
    "status",
    "error",
    "avg_time_sec",
    "median_time_sec",
    "min_time_sec",
    "max_time_sec",
    "local_hash_per_sec",
]


def run_benchmarks(
    algorithm_configs: Iterable[dict[str, Any]],
    password: bytes,
    salt_size_bytes: int,
    repeats: int,
) -> list[dict[str, Any]]:
    """Run every configured benchmark and return CSV-ready rows."""

    rows = []
    for config in algorithm_configs:
        rows.append(run_single_benchmark(config, password, salt_size_bytes, repeats))
    return rows


def run_single_benchmark(
    config: dict[str, Any],
    password: bytes,
    salt_size_bytes: int,
    repeats: int,
) -> dict[str, Any]:
    """Run one algorithm configuration and capture timing statistics."""

    base_row = {
        "algorithm": config["algorithm"],
        "parameter": config["parameter"],
        "status": "failed",
        "error": "",
        "avg_time_sec": None,
        "median_time_sec": None,
        "min_time_sec": None,
        "max_time_sec": None,
        "local_hash_per_sec": None,
    }

    if repeats < 1:
        return {**base_row, "error": "repeats must be at least 1"}

    try:
        hasher = _build_hasher(config, password, salt_size_bytes)
        durations = []
        for _ in range(repeats):
            started_at = time.perf_counter()
            digest = hasher()
            elapsed = time.perf_counter() - started_at
            if not digest:
                raise ValueError("hash output is empty")
            durations.append(elapsed)
    except Exception as exc:  # Keep later configurations running.
        return {**base_row, "error": f"{type(exc).__name__}: {exc}"}

    avg_time = statistics.fmean(durations)
    return {
        **base_row,
        "status": "success",
        "error": "",
        "avg_time_sec": avg_time,
        "median_time_sec": statistics.median(durations),
        "min_time_sec": min(durations),
        "max_time_sec": max(durations),
        "local_hash_per_sec": 1 / avg_time if avg_time > 0 else None,
    }


def _build_hasher(
    config: dict[str, Any],
    password: bytes,
    salt_size_bytes: int,
):
    kind = config["kind"]

    if kind == "pbkdf2":
        salt = os.urandom(salt_size_bytes)

        def hash_pbkdf2() -> bytes:
            return hashlib.pbkdf2_hmac(
                "sha256",
                password,
                salt,
                config["iterations"],
                dklen=32,
            )

        return hash_pbkdf2

    if kind == "bcrypt":
        if bcrypt is None:
            raise ImportError("bcrypt is not installed")
        salt = bcrypt.gensalt(rounds=config["cost"])

        def hash_bcrypt() -> bytes:
            return bcrypt.hashpw(password, salt)

        return hash_bcrypt

    if kind == "scrypt":
        salt = os.urandom(salt_size_bytes)
        maxmem = _scrypt_maxmem(config["n"], config["r"], config["p"])

        def hash_scrypt() -> bytes:
            return hashlib.scrypt(
                password,
                salt=salt,
                n=config["n"],
                r=config["r"],
                p=config["p"],
                dklen=32,
                maxmem=maxmem,
            )

        return hash_scrypt

    if kind == "argon2id":
        if hash_secret_raw is None or Type is None:
            raise ImportError("argon2-cffi is not installed")
        salt = os.urandom(salt_size_bytes)

        def hash_argon2id() -> bytes:
            return hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=config["time_cost"],
                memory_cost=config["memory_cost"],
                parallelism=config["parallelism"],
                hash_len=32,
                type=Type.ID,
            )

        return hash_argon2id

    raise ValueError(f"unsupported algorithm kind: {kind}")


def _scrypt_maxmem(n: int, r: int, p: int) -> int:
    """Return a practical maxmem value for hashlib.scrypt in bytes."""

    estimated_bytes = 128 * n * r * p
    return max(64 * 1024 * 1024, estimated_bytes * 2)
