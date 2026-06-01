"""Entry point for the slow password hashing simulation."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

import config
from benchmark import BENCHMARK_FIELDS, run_benchmarks
from estimasi import ESTIMATION_FIELDS, build_estimations


def main() -> None:
    output_dir = Path(config.OUTPUT_DIR)
    output_dir.mkdir(exist_ok=True)

    print("Menjalankan benchmark slow hashing...")
    print(f"Repetisi per konfigurasi: {config.BENCHMARK_REPEATS}")

    benchmark_rows = run_benchmarks(
        algorithm_configs=config.ALGORITHM_CONFIGS,
        password=config.PASSWORD,
        salt_size_bytes=config.SALT_SIZE_BYTES,
        repeats=config.BENCHMARK_REPEATS,
    )
    benchmark_path = output_dir / config.BENCHMARK_CSV
    _write_csv(benchmark_path, BENCHMARK_FIELDS, benchmark_rows)

    estimation_rows = build_estimations(
        benchmark_rows=benchmark_rows,
        keyspace_scenarios=config.KEYSPACE_SCENARIOS,
        attacker_hash_rates=config.ATTACKER_HASH_RATES,
    )
    estimation_path = output_dir / config.ESTIMATION_CSV
    _write_csv(estimation_path, ESTIMATION_FIELDS, estimation_rows)

    _plot_hashing_times(
        benchmark_rows,
        output_dir / config.HASHING_CHART,
    )
    _plot_bruteforce_estimates(
        estimation_rows,
        output_dir / config.ESTIMATION_CHART,
    )

    _print_summary(benchmark_rows, estimation_rows, output_dir)


def _write_csv(
    path: Path,
    fieldnames: list[str],
    rows: list[dict[str, Any]],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _plot_hashing_times(rows: list[dict[str, Any]], path: Path) -> None:
    successful_rows = [row for row in rows if row["status"] == "success"]
    if not successful_rows:
        _write_empty_chart(path, "Tidak ada benchmark yang berhasil")
        return

    labels = [f"{row['algorithm']}\n{row['parameter']}" for row in successful_rows]
    values = [row["avg_time_sec"] for row in successful_rows]

    width = max(10, len(labels) * 0.9)
    plt.figure(figsize=(width, 6))
    plt.bar(labels, values, color="#4477aa")
    plt.ylabel("Rata-rata waktu hashing (detik)")
    plt.title("Benchmark Waktu Hashing")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def _plot_bruteforce_estimates(rows: list[dict[str, Any]], path: Path) -> None:
    selected_rows = [
        row
        for row in rows
        if row["attacker_profile"] == "local_cpu"
        and row["password_scenario"] == "alphanumeric_10"
    ]
    if not selected_rows:
        _write_empty_chart(path, "Tidak ada estimasi brute-force yang tersedia")
        return

    labels = [f"{row['algorithm']}\n{row['parameter']}" for row in selected_rows]
    values = [row["avg_case_seconds"] for row in selected_rows]

    width = max(10, len(labels) * 0.9)
    plt.figure(figsize=(width, 6))
    plt.bar(labels, values, color="#66aa55")
    plt.yscale("log")
    plt.ylabel("Average-case brute-force (detik, log scale)")
    plt.title("Estimasi Brute-Force: Alphanumeric 10")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def _write_empty_chart(path: Path, message: str) -> None:
    plt.figure(figsize=(8, 4))
    plt.text(0.5, 0.5, message, ha="center", va="center")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def _print_summary(
    benchmark_rows: list[dict[str, Any]],
    estimation_rows: list[dict[str, Any]],
    output_dir: Path,
) -> None:
    success_count = sum(1 for row in benchmark_rows if row["status"] == "success")
    failed_rows = [row for row in benchmark_rows if row["status"] == "failed"]

    print()
    print("Ringkasan eksperimen")
    print(f"- Benchmark berhasil: {success_count}/{len(benchmark_rows)} konfigurasi")
    print(f"- Baris estimasi brute-force: {len(estimation_rows)}")
    print(f"- Output disimpan di: {output_dir.resolve()}")

    if failed_rows:
        print("- Konfigurasi gagal:")
        for row in failed_rows:
            print(f"  - {row['algorithm']} {row['parameter']}: {row['error']}")


if __name__ == "__main__":
    main()
