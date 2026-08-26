# process_all_services.py
import json
import os

service_files = {
    "Amazon S3": "observation_s3.json",
    "Amazon EC2 / VPC": "observation_ec2.json",
    "AWS IAM": "observation_iam.json",
    "Amazon RDS": "observation_rds.json",
    "AWS Lambda": "observation_lambda.json",
    "Edge (APIGW & CloudFront)": "observation_edge.json",
    "Full Account (All 35 Assets)": "full_account_observation.json"
}

def evaluate_findings(findings):
    tp, tn, fp, fn = 0, 0, 0, 0
    
    for item in findings:
        name = (item.get("resource_name") or item.get("resource_id", "")).lower()
        score = item.get("final_risk_score", 0.0)
        sev = (item.get("highest_severity_level") or item.get("severity_level", "ADVISORY")).upper()

        is_hardened = any(term in name for term in ["perfect", "compliant", "readonly", "audit_logs"])

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

    total = tp + tn + fp + fn
    prec = (tp / (tp + fp) * 100) if (tp + fp) > 0 else (100.0 if total > 0 else 0.0)
    rec = (tp / (tp + fn) * 100) if (tp + fn) > 0 else (100.0 if total > 0 else 0.0)
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else (100.0 if total > 0 else 0.0)
    acc = ((tp + tn) / total * 100) if total > 0 else 0.0

    return {
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1
    }

print("=" * 100)
print(f"{'Service Domain':<26} | {'Assets':<6} | {'TP':<3} | {'TN':<3} | {'FP':<3} | {'FN':<3} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<7} | {'F1-Score':<8}")
print("=" * 100)

for service_name, filename in service_files.items():
    if os.path.exists(filename):
        with open(filename, "r") as f:
            payload = json.load(f)
            findings = payload.get("findings", []) if isinstance(payload, dict) else payload
            res = evaluate_findings(findings)
            print(f"{service_name:<26} | {res['total']:<6} | {res['tp']:<3} | {res['tn']:<3} | {res['fp']:<3} | {res['fn']:<3} | {res['accuracy']:>6.1f}% | {res['precision']:>8.1f}% | {res['recall']:>6.1f}% | {res['f1']:>7.1f}%")
    else:
        print(f"{service_name:<26} | FILE NOT FOUND ({filename})")

print("=" * 100)