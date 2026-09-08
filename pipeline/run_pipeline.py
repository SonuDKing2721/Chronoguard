"""
Chronoguard — End-to-End Integration Pipeline
Runs all models in sequence and produces a unified demo_results.csv,
then automatically generates dashboard/data.js for the interactive dashboard.

Usage:
    python pipeline/run_pipeline.py

Prerequisite: All models must be trained first:
    python notebooks/train_classifier.py
    python notebooks/train_anomaly.py
    python notebooks/explainability.py

Or use the one-click runner:
    run_all.bat  (Windows)
    bash run_all.sh  (Linux/Mac)
"""

import os
import sys
import warnings
import subprocess
import pandas as pd
import numpy as np
import joblib

warnings.filterwarnings("ignore")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

FEATURES = ["packet_rate", "byte_rate", "connection_count", "avg_syn_flags", "avg_duration"]
LAG_FEATURES = [
    "packet_rate_lag1", "byte_rate_lag1",
    "packet_rate_lag2", "byte_rate_lag2",
    "packet_rate_lag3", "byte_rate_lag3",
]
LABEL_NAMES = {0: "BENIGN", 1: "DDoS", 2: "DoS", 3: "Brute Force"}

MITRE_LOOKUP = {
    "BENIGN":      {"id": "N/A",   "technique": "Normal Traffic",               "tactic": "N/A"},
    "DDoS":        {"id": "T1498", "technique": "Network Denial of Service",    "tactic": "Impact"},
    "DoS":         {"id": "T1499", "technique": "Endpoint Denial of Service",   "tactic": "Impact"},
    "Brute Force": {"id": "T1110", "technique": "Brute Force",                  "tactic": "Credential Access"},
}

def risk_level(score):
    if score < 25: return "Low"
    if score < 50: return "Medium"
    if score < 75: return "High"
    return "Critical"


def main():
    print("=" * 65)
    print("  CHRONOGUARD - End-to-End Integration Pipeline")
    print("=" * 65)

    # ---- Validate data ----
    test_path = os.path.join(DATA_DIR, "test.csv")
    if not os.path.exists(test_path):
        print(f"[ERROR] test.csv not found at {test_path}")
        sys.exit(1)

    test_df = pd.read_csv(test_path)

    # Validate columns
    required = ["window"] + FEATURES + ["Label_num"]
    missing = [c for c in required if c not in test_df.columns]
    if missing:
        print(f"[ERROR] Missing columns in test.csv: {missing}")
        print(f"Available columns: {list(test_df.columns)}")
        sys.exit(1)

    print(f"[OK] Loaded test.csv: {len(test_df)} windows, columns OK")

    X_test = test_df[FEATURES]

    # ---- Load classifier ----
    clf_path = os.path.join(MODEL_DIR, "classifier_model.joblib")
    if not os.path.exists(clf_path):
        print(f"[ERROR] Classifier model not found: {clf_path}")
        print("  -> Run: python notebooks/train_classifier.py")
        sys.exit(1)

    classifier = joblib.load(clf_path)
    print("[OK] Loaded classifier model")

    class_preds = classifier.predict(X_test)
    class_proba = classifier.predict_proba(X_test)
    attack_prob = 1 - class_proba[:, 0]

    # ---- Load anomaly model (optional) ----
    anomaly_component = np.zeros(len(X_test))
    anom_path = os.path.join(MODEL_DIR, "anomaly_model.joblib")
    scaler_path = os.path.join(MODEL_DIR, "anomaly_scaler.joblib")

    if os.path.exists(anom_path) and os.path.exists(scaler_path):
        anomaly_model = joblib.load(anom_path)
        scaler = joblib.load(scaler_path)
        X_scaled = scaler.transform(X_test)
        anomaly_raw = anomaly_model.decision_function(X_scaled)
        # Normalize to [0, 1] using min-max (more robust than raw clip)
        neg_scores = -anomaly_raw
        s_min, s_max = neg_scores.min(), neg_scores.max()
        if s_max > s_min:
            anomaly_component = (neg_scores - s_min) / (s_max - s_min)
        print("[OK] Loaded anomaly model")
    else:
        print("[WARN] Anomaly model not found — using zero. Run train_anomaly.py first.")

    # ---- Load forecasting model (optional) ----
    trend_component = np.zeros(len(X_test))
    fc_path = os.path.join(MODEL_DIR, "forecasting_model.joblib")

    if os.path.exists(fc_path) and all(c in test_df.columns for c in LAG_FEATURES):
        forecaster = joblib.load(fc_path)
        X_fc = test_df[FEATURES + LAG_FEATURES].fillna(0)
        trend_component = np.clip(forecaster.predict(X_fc), 0, 1)
        print("[OK] Loaded forecasting model")
    else:
        print("[WARN] Forecasting model not found or lag columns missing.")

    # ---- Compute risk scores ----
    severity = np.array([
        {"BENIGN": 0.0, "DDoS": 0.95, "DoS": 0.85, "Brute Force": 0.75}[LABEL_NAMES[p]]
        for p in class_preds
    ])

    composite = (
        0.35 * attack_prob +
        0.25 * anomaly_component +
        0.15 * trend_component +
        0.25 * severity
    )
    risk_scores = np.clip(composite * 100, 0, 100)

    # ---- Build results table ----
    results = pd.DataFrame({
        "window":            test_df["window"],
        "packet_rate":       test_df["packet_rate"].round(2),
        "byte_rate":         test_df["byte_rate"].round(2),
        "connection_count":  test_df["connection_count"],
        "avg_syn_flags":     test_df["avg_syn_flags"].round(4),
        "avg_duration":      test_df["avg_duration"].round(2),
        "true_label":        [LABEL_NAMES[l] for l in test_df["Label_num"]],
        "predicted_label":   [LABEL_NAMES[p] for p in class_preds],
        "confidence":        class_proba.max(axis=1).round(4),
        "attack_probability": attack_prob.round(4),
        "anomaly_score":     anomaly_component.round(4),
        "trend_score":       trend_component.round(4),
        "risk_score":        risk_scores.round(1),
        "risk_level":        [risk_level(s) for s in risk_scores],
        "mitre_id":          [MITRE_LOOKUP[LABEL_NAMES[p]]["id"] for p in class_preds],
        "mitre_technique":   [MITRE_LOOKUP[LABEL_NAMES[p]]["technique"] for p in class_preds],
    })

    # ---- Save demo_results.csv ----
    output_path = os.path.join(OUTPUT_DIR, "demo_results.csv")
    results.to_csv(output_path, index=False)
    print(f"\n[OK] Saved {output_path} ({len(results)} rows)")

    # ---- Pipeline Summary ----
    print("\n--- Pipeline Summary ---")
    print(f"Total test windows:  {len(results)}")
    print("Risk level distribution:")
    for level in ["Low", "Medium", "High", "Critical"]:
        count = (results["risk_level"] == level).sum()
        bar = "=" * int(count / len(results) * 30)
        print(f"  {level:10s}: {count:4d}  [{bar}]")
    print(f"\nPrediction accuracy: {(results['true_label'] == results['predicted_label']).mean():.1%}")
    print(f"Mean risk score:     {risk_scores.mean():.1f}")
    print(f"Max risk score:      {risk_scores.max():.1f}")

    # Show risky windows
    print("\n--- Sample Risky Windows ---")
    risky = results[results["risk_level"].isin(["High", "Critical"])].head(5)
    if len(risky) > 0:
        print(risky[["window", "predicted_label", "risk_score", "risk_level", "mitre_id"]].to_string(index=False))
    else:
        print("No high-risk windows found.")

    # ---- Auto-generate dashboard data ----
    print("\n--- Generating Dashboard Data ---")
    gen_script = os.path.join(SCRIPT_DIR, "generate_dashboard_data.py")
    if os.path.exists(gen_script):
        result = subprocess.run(
            [sys.executable, gen_script],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[OK] Dashboard data generated successfully")
            # Print relevant lines from sub-script output
            for line in result.stdout.splitlines():
                if line.strip():
                    print(f"     {line}")
        else:
            print(f"[WARN] Dashboard data generation failed:")
            print(result.stderr[:500])
    else:
        print(f"[WARN] generate_dashboard_data.py not found at {gen_script}")

    print("\n" + "=" * 65)
    print("  Pipeline complete. Open dashboard/index.html to view results.")
    print("=" * 65)


if __name__ == "__main__":
    main()
