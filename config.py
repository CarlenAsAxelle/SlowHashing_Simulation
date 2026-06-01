"""Configuration for the slow password hashing simulation."""

from __future__ import annotations

import os


PASSWORD = os.environ.get("BENCHMARK_PASSWORD", "P@ssw0rd2026!").encode("utf-8")
SALT_SIZE_BYTES = 16
BENCHMARK_REPEATS = int(os.environ.get("BENCHMARK_REPEATS", "5"))

OUTPUT_DIR = "output"
BENCHMARK_CSV = "hasil_benchmark.csv"
ESTIMATION_CSV = "hasil_estimasi_bruteforce.csv"
HASHING_CHART = "grafik_waktu_hashing.png"
ESTIMATION_CHART = "grafik_estimasi_bruteforce.png"


ALGORITHM_CONFIGS = [
    {
        "algorithm": "PBKDF2",
        "parameter": "100000 iterations",
        "kind": "pbkdf2",
        "iterations": 100_000,
    },
    {
        "algorithm": "PBKDF2",
        "parameter": "300000 iterations",
        "kind": "pbkdf2",
        "iterations": 300_000,
    },
    {
        "algorithm": "PBKDF2",
        "parameter": "600000 iterations",
        "kind": "pbkdf2",
        "iterations": 600_000,
    },
    {
        "algorithm": "PBKDF2",
        "parameter": "1000000 iterations",
        "kind": "pbkdf2",
        "iterations": 1_000_000,
    },
    {
        "algorithm": "bcrypt",
        "parameter": "cost=10",
        "kind": "bcrypt",
        "cost": 10,
    },
    {
        "algorithm": "bcrypt",
        "parameter": "cost=12",
        "kind": "bcrypt",
        "cost": 12,
    },
    {
        "algorithm": "bcrypt",
        "parameter": "cost=14",
        "kind": "bcrypt",
        "cost": 14,
    },
    {
        "algorithm": "scrypt",
        "parameter": "N=16384 r=8 p=1",
        "kind": "scrypt",
        "n": 2**14,
        "r": 8,
        "p": 1,
    },
    {
        "algorithm": "scrypt",
        "parameter": "N=32768 r=8 p=1",
        "kind": "scrypt",
        "n": 2**15,
        "r": 8,
        "p": 1,
    },
    {
        "algorithm": "scrypt",
        "parameter": "N=65536 r=8 p=1",
        "kind": "scrypt",
        "n": 2**16,
        "r": 8,
        "p": 1,
    },
    {
        "algorithm": "Argon2id",
        "parameter": "m=65536 t=2 p=1",
        "kind": "argon2id",
        "memory_cost": 65_536,
        "time_cost": 2,
        "parallelism": 1,
    },
    {
        "algorithm": "Argon2id",
        "parameter": "m=131072 t=3 p=1",
        "kind": "argon2id",
        "memory_cost": 131_072,
        "time_cost": 3,
        "parallelism": 1,
    },
    {
        "algorithm": "Argon2id",
        "parameter": "m=262144 t=3 p=2",
        "kind": "argon2id",
        "memory_cost": 262_144,
        "time_cost": 3,
        "parallelism": 2,
    },
]


KEYSPACE_SCENARIOS = [
    {
        "name": "lowercase_8",
        "description": "Lowercase 8 karakter",
        "character_set_size": 26,
        "length": 8,
    },
    {
        "name": "alphanumeric_8",
        "description": "Alphanumeric 8 karakter",
        "character_set_size": 62,
        "length": 8,
    },
    {
        "name": "alphanumeric_10",
        "description": "Alphanumeric 10 karakter",
        "character_set_size": 62,
        "length": 10,
    },
    {
        "name": "printable_ascii_10",
        "description": "Printable ASCII 10 karakter",
        "character_set_size": 94,
        "length": 10,
    },
    {
        "name": "printable_ascii_12",
        "description": "Printable ASCII 12 karakter",
        "character_set_size": 94,
        "length": 12,
    },
]


# External attacker rates are intentionally empty until a cited source is added.
# Shape:
# {
#     ("bcrypt", "cost=12"): {
#         "estimated_gpu": {
#             "hash_per_sec": 12345.0,
#             "source": "Citation or URL",
#         }
#     }
# }
ATTACKER_HASH_RATES = {}
