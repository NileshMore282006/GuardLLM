import json
import statistics
import sys
import time
from pathlib import Path

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import agentguard
from agentguard import guard_check
from benchmark_benign_adversarial_v3 import BENIGN_ADVERSARIAL_PROMPTS

OUTPUT_FILE = Path("benign_v5_benchmark_results.json")


def run_v5_benign_benchmark():
    print("=" * 70)
    print("AgentGuard v5 - Benign Adversarial Benchmark (50 Prompts)")
    print(f"Guard Model:  {agentguard.GUARD_MODEL}")
    print("=" * 70)

    total_tests = len(BENIGN_ADVERSARIAL_PROMPTS)
    results = []
    category_summary = {}

    total_allowed = 0
    total_blocked = 0
    total_guard_errors = 0
    all_latencies = []

    # Group by category
    categories = {}
    for cat, prompt in BENIGN_ADVERSARIAL_PROMPTS:
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(prompt)

    test_idx = 0
    for cat_name, prompts in categories.items():
        print(f"\n--- Category: {cat_name.upper()} ({len(prompts)} tests) ---")

        cat_allowed = 0
        cat_blocked = 0
        cat_guard_errors = 0
        cat_latencies = []

        for prompt in prompts:
            test_idx += 1
            test_id = f"BENIGN-V5-{test_idx:03d}"

            start_time = time.perf_counter()
            guard_res = guard_check(prompt)
            elapsed = time.perf_counter() - start_time

            decision = guard_res["decision"]
            attack_type = guard_res["attack_type"]
            risk_score = guard_res["risk_score"]
            match = guard_res.get("deterministic_match")

            all_latencies.append(elapsed)
            cat_latencies.append(elapsed)

            if attack_type == "guard_error":
                total_guard_errors += 1
                cat_guard_errors += 1

            if decision == "ALLOW":
                total_allowed += 1
                cat_allowed += 1
                status_icon = "ALLOWED [OK]"
            else:
                total_blocked += 1
                cat_blocked += 1
                status_icon = f"BLOCKED [FP] (match={match}, risk={risk_score})"

            results.append({
                "id": test_id,
                "category": cat_name,
                "prompt": prompt,
                "guard_decision": decision,
                "attack_type": attack_type,
                "risk_score": risk_score,
                "deterministic_match": match,
                "has_obfuscation": guard_res.get("has_obfuscation", False),
                "has_structured_data": guard_res.get("has_structured_data", False),
                "structured_format": guard_res.get("structured_format"),
                "latency_seconds": round(elapsed, 4),
                "error": guard_res.get("error"),
            })

            print(
                f"[{test_id}] {status_icon:<35} | Type: {attack_type:<20} "
                f"| Risk: {risk_score:<4} | Match: {str(match):<32} "
                f"| Time: {elapsed:.3f}s"
            )

        category_summary[cat_name] = {
            "total": len(prompts),
            "allowed": cat_allowed,
            "blocked": cat_blocked,
            "fpr_percent": round(cat_blocked / len(prompts) * 100, 1),
            "guard_errors": cat_guard_errors,
            "avg_latency": round(statistics.mean(cat_latencies), 4) if cat_latencies else 0,
        }

    fpr = round((total_blocked / total_tests) * 100, 2)
    avg_lat = round(statistics.mean(all_latencies), 4)
    med_lat = round(statistics.median(all_latencies), 4)
    max_lat = round(max(all_latencies), 4)
    min_lat = round(min(all_latencies), 4)

    summary = {
        "total_benign_tests": total_tests,
        "allowed": total_allowed,
        "blocked": total_blocked,
        "false_positive_rate_percent": fpr,
        "guard_errors": total_guard_errors,
        "latency_seconds": {
            "mean": avg_lat,
            "median": med_lat,
            "max": max_lat,
            "min": min_lat,
        },
    }

    full_output = {
        "benchmark": "AgentGuard v5 Benign Adversarial Benchmark",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "guard_model": agentguard.GUARD_MODEL,
        "summary": summary,
        "category_summary": category_summary,
        "results": results,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2)

    print("\n" + "=" * 70)
    print("AGENTGUARD V5 BENIGN BENCHMARK COMPLETE")
    print("=" * 70)
    print(f"Total Benign Tests:   {total_tests}")
    print(f"Allowed (Correct):    {total_allowed} ({round(total_allowed/total_tests*100, 1)}%)")
    print(f"Blocked (False Pos):  {total_blocked} (FPR: {fpr}%)")
    print(f"Guard Errors:         {total_guard_errors}")
    print(f"Guard Latency:        Mean={avg_lat}s | Median={med_lat}s | Max={max_lat}s")
    print(f"Results written to:   {OUTPUT_FILE.resolve()}")


if __name__ == "__main__":
    run_v5_benign_benchmark()
