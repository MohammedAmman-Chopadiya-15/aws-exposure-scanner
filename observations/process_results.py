# process_results.py
import json
import os
import csv
import statistics

# 1. LATENCY BENCHMARK ANALYSIS
csv_file = "latency_benchmark_30_runs.csv"
if os.path.exists(csv_file):
    with open(csv_file, mode='r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    latencies = [float(r["LatencyMs"]) for r in rows]
    cold_start = latencies[0]
    warm_starts = latencies[1:]

    mean_warm = statistics.mean(warm_starts)
    std_warm = statistics.stdev(warm_starts) if len(warm_starts) > 1 else 0.0
    median_warm = statistics.median(warm_starts)
    min_warm = min(warm_starts)
    max_warm = max(warm_starts)

    print("=" * 60)
    print("LATENCY & CONCURRENCY BENCHMARK RESULTS (N=30)")
    print("=" * 60)
    print(f"Cold Start Latency (Iteration 1) : {cold_start:.2f} ms")
    print(f"Warm Start Mean Latency (Runs 2-30): {mean_warm:.2f} ms")
    print(f"Warm Start Std Deviation         : {std_warm:.2f} ms")
    print(f"Warm Start Median Latency        : {median_warm:.2f} ms")
    print(f"Warm Start Min / Max             : {min_warm:.2f} ms / {max_warm:.2f} ms")
    print("=" * 60)

# 2. GROUND TRUTH CONFUSION MATRIX EVALUATION
obs_file = "full_account_observation.json"
if os.path.exists(obs_file):
    with open(obs_file, "r") as f:
        payload = json.load(f)
        findings = payload.get("findings", []) if isinstance(payload, dict) else payload

    # Ground truth expectations (28 Vulnerable, 7 Hardened)
    total_assets = len(findings)
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for item in findings:
        name = (item.get("resource_name") or item.get("resource_id", "")).lower()
        score = item.get("final_risk_score", 0.0)
        sev = (item.get("highest_severity_level") or item.get("severity_level", "ADVISORY")).upper()

        is_hardened = "perfect" in name or "compliant" in name or "readonly" in name or "audit_logs" in name

        if is_hardened:
            if score == 0.0 or sev in ["ADVISORY", "CLEAN"]:
                tn += 1
            else:
                fp += 1
        else:
            if score > 0.0 and sev != "ADVISORY":
                tp += 1
            else:
                fn += 1

    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = ((tp + tn) / total_assets) * 100 if total_assets > 0 else 0

    print("\n" + "=" * 60)
    print("ACCURACY & CLASSIFICATION METRICS (CONFUSION MATRIX)")
    print("=" * 60)
    print(f"Total Evaluated Assets : {total_assets}")
    print(f"True Positives (TP)    : {tp} (Correctly detected vulnerabilities)")
    print(f"True Negatives (TN)    : {tn} (Correctly verified compliant baselines)")
    print(f"False Positives (FP)   : {fp} (False alarms on hardened assets)")
    print(f"False Negatives (FN)   : {fn} (Missed security exposures)")
    print("-" * 60)
    print(f"Accuracy               : {accuracy:.2f}%")
    print(f"Precision              : {precision:.2f}%")
    print(f"Recall (Sensitivity)   : {recall:.2f}%")
    print(f"F1-Score               : {f1:.2f}%")
    print("=" * 60)