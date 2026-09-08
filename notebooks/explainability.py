"""
Chronoguard — Person 4: Explainability & Risk Scoring
  1. Runs SHAP on the classifier to explain feature contributions
  2. Builds MITRE ATT&CK lookup table (4 classes, no PortScan)
  3. Computes composite 0-100 risk score combining:
     - Attack probability (classifier)
     - Anomaly score (Isolation Forest)
     - Trend signal (forecasting model)
     - SHAP-weighted feature contribution
  4. Maps to Low / Medium / High / Critical

Saves: outputs/risk_table.csv, outputs/shap_summary.csv
"""

import os
import sys
import warnings
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
LABEL_NAMES = {0: "BENIGN", 1: "DDoS", 2: "DoS", 3: "Brute Force"}

# ════════════════════════════════════════════════════════════
# MITRE ATT&CK Lookup (only 4 categories — no PortScan)
# ════════════════════════════════════════════════════════════

MITRE_LOOKUP = {
    "BENIGN": {
        "mitre_id": "N/A",
        "technique": "Normal Traffic",
        "tactic": "N/A",
        "severity_weight": 0.0,
    },
    "DDoS": {
        "mitre_id": "T1498",
        "technique": "Network Denial of Service",
        "tactic": "Impact",
        "severity_weight": 0.95,
    },
    "DoS": {
        "mitre_id": "T1499",
        "technique": "Endpoint Denial of Service",
        "tactic": "Impact",
        "severity_weight": 0.85,
    },
    "Brute Force": {
        "mitre_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "severity_weight": 0.75,
    },
}

print("=" * 60)
print("CHRONOGUARD - Explainability & Risk Scoring")
print("=" * 60)

# ---- Load models ----
classifier_path = os.path.join(MODEL_DIR, "classifier_model.joblib")
anomaly_path = os.path.join(MODEL_DIR, "anomaly_model.joblib")
scaler_path = os.path.join(MODEL_DIR, "anomaly_scaler.joblib")
forecaster_path = os.path.join(MODEL_DIR, "forecasting_model.joblib")

if not os.path.exists(classifier_path):
    print(f"ERROR: Classifier not found at {classifier_path}")
    print("Run: python notebooks/train_classifier.py")
    sys.exit(1)

classifier = joblib.load(classifier_path)
print(f"[OK] Loaded classifier from {classifier_path}")

has_anomaly = os.path.exists(anomaly_path) and os.path.exists(scaler_path)
has_forecaster = os.path.exists(forecaster_path)

anomaly_model = None
anomaly_scaler = None
forecaster = None

if has_anomaly:
    anomaly_model = joblib.load(anomaly_path)
    anomaly_scaler = joblib.load(scaler_path)
    print("[OK] Loaded anomaly model + scaler")
else:
    print("[WARN] Anomaly model not found - run train_anomaly.py first. Using partial scoring.")

if has_forecaster:
    forecaster = joblib.load(forecaster_path)
    print("[OK] Loaded forecasting model")
else:
    print("[WARN] Forecasting model not found. Using partial scoring.")

# ---- Load data ----
test_df = pd.read_csv(os.path.join(DATA_DIR, "test.csv"))
X_test = test_df[FEATURES]

# ════════════════════════════════════════════════════════════
# 1. SHAP Explainability
# ════════════════════════════════════════════════════════════

print("\n--- SHAP Feature Importance ---")

has_shap = False
shap_importance = None

try:
    import shap
    explainer = shap.Explainer(classifier, X_test)
    shap_values = explainer(X_test)

    # FIX: shap_values.values can be 2D (binary) or 3D (multi-class).
    # For multi-class HistGradientBoosting, shape is (n_samples, n_features, n_classes).
    # We take mean over samples (axis=0) and classes (axis=-1) if 3D.
    raw = shap_values.values
    if raw.ndim == 3:
        # Multi-class: shape (n_samples, n_features, n_classes)
        mean_abs_shap = np.abs(raw).mean(axis=(0, 2))
    elif raw.ndim == 2:
        # Binary or single-output: shape (n_samples, n_features)
        mean_abs_shap = np.abs(raw).mean(axis=0)
    else:
        raise ValueError(f"Unexpected SHAP values shape: {raw.shape}")

    shap_importance = pd.DataFrame({
        "feature": FEATURES,
        "mean_abs_shap": mean_abs_shap
    }).sort_values("mean_abs_shap", ascending=False)

    print(shap_importance.to_string(index=False))
    shap_importance.to_csv(os.path.join(OUTPUT_DIR, "shap_summary.csv"), index=False)
    print("[OK] Saved shap_summary.csv")
    has_shap = True

except ImportError:
    print("[WARN] SHAP package not installed. Using permutation importance fallback.")
except Exception as e:
    print(f"[WARN] SHAP failed ({e}). Using permutation importance fallback.")

if not has_shap:
    # Fallback: permutation importance (works without shap package)
    try:
        from sklearn.inspection import permutation_importance
        perm_result = permutation_importance(
            classifier, X_test, test_df["Label_num"],
            n_repeats=10, random_state=42, n_jobs=-1
        )
        shap_importance = pd.DataFrame({
            "feature": FEATURES,
            "mean_abs_shap": perm_result.importances_mean
        }).sort_values("mean_abs_shap", ascending=False)
        print(shap_importance.to_string(index=False))
        shap_importance.to_csv(os.path.join(OUTPUT_DIR, "shap_summary.csv"), index=False)
        print("[OK] Saved shap_summary.csv (permutation importance fallback)")
    except Exception as e:
        print(f"[WARN] Permutation importance also failed ({e}). Using uniform weights.")
        shap_importance = pd.DataFrame({
            "feature": FEATURES,
            "mean_abs_shap": [1.0 / len(FEATURES)] * len(FEATURES)
        })

# ════════════════════════════════════════════════════════════
# 2. Composite Risk Scoring
# ════════════════════════════════════════════════════════════

print("\n--- Composite Risk Scoring ---")

# Component 1: Classification probability (attack probability)
class_proba = classifier.predict_proba(X_test)
class_preds = classifier.predict(X_test)
attack_prob = 1 - class_proba[:, 0]   # 1 - P(BENIGN) = P(attack)

# Component 2: Anomaly score — normalized to [0, 1]
if has_anomaly:
    X_scaled = anomaly_scaler.transform(X_test)
    anomaly_scores_raw = anomaly_model.decision_function(X_scaled)
    # decision_function: more negative = more anomalous.
    # FIX: normalize properly to [0, 1] using min-max instead of naive clip(-raw, 0, 1)
    # which can silently produce zeros for all normal samples.
    neg_scores = -anomaly_scores_raw  # higher = more anomalous
    score_min, score_max = neg_scores.min(), neg_scores.max()
    if score_max > score_min:
        anomaly_component = (neg_scores - score_min) / (score_max - score_min)
    else:
        anomaly_component = np.zeros(len(X_test))
else:
    anomaly_component = np.zeros(len(X_test))

# Component 3: Forecasting trend
LAG_FEATURES = [
    "packet_rate_lag1", "byte_rate_lag1",
    "packet_rate_lag2", "byte_rate_lag2",
    "packet_rate_lag3", "byte_rate_lag3",
]
if has_forecaster and all(c in test_df.columns for c in LAG_FEATURES):
    forecast_features = FEATURES + LAG_FEATURES
    X_fc = test_df[forecast_features].fillna(0)
    trend_component = np.clip(forecaster.predict(X_fc), 0, 1)
else:
    trend_component = np.zeros(len(X_test))

# Component 4: MITRE severity weight
severity_weights = np.array([
    MITRE_LOOKUP[LABEL_NAMES[p]]["severity_weight"] for p in class_preds
])

# Composite score (weighted average, scaled 0-100)
WEIGHTS = {
    "attack_prob": 0.35,
    "anomaly":     0.25,
    "trend":       0.15,
    "severity":    0.25,
}

composite = (
    WEIGHTS["attack_prob"] * attack_prob +
    WEIGHTS["anomaly"]     * anomaly_component +
    WEIGHTS["trend"]       * trend_component +
    WEIGHTS["severity"]    * severity_weights
)

# Scale to 0-100
risk_scores = np.clip(composite * 100, 0, 100)

# Risk level mapping
def risk_level(score):
    if score < 25: return "Low"
    if score < 50: return "Medium"
    if score < 75: return "High"
    return "Critical"

risk_levels = [risk_level(s) for s in risk_scores]

# ════════════════════════════════════════════════════════════
# 3. Build Risk Table
# ════════════════════════════════════════════════════════════

risk_table = pd.DataFrame({
    "window":             test_df["window"],
    "true_label":         [LABEL_NAMES[l] for l in test_df["Label_num"]],
    "predicted_label":    [LABEL_NAMES[p] for p in class_preds],
    "confidence":         class_proba.max(axis=1).round(4),
    "attack_probability": attack_prob.round(4),
    "anomaly_score":      anomaly_component.round(4),
    "trend_score":        trend_component.round(4),
    "mitre_id":           [MITRE_LOOKUP[LABEL_NAMES[p]]["mitre_id"] for p in class_preds],
    "mitre_technique":    [MITRE_LOOKUP[LABEL_NAMES[p]]["technique"] for p in class_preds],
    "risk_score":         risk_scores.round(1),
    "risk_level":         risk_levels,
})

risk_table_path = os.path.join(OUTPUT_DIR, "risk_table_full.csv")
risk_table.to_csv(risk_table_path, index=False)
print(f"\n[OK] Saved {risk_table_path}")

# Print summary
print("\nRisk Level Distribution:")
print(risk_table["risk_level"].value_counts().to_string())
print(f"\nMean Risk Score: {risk_scores.mean():.1f}")
print(f"Max Risk Score:  {risk_scores.max():.1f}")
print(f"Min Risk Score:  {risk_scores.min():.1f}")

print("\nSample rows (first 10):")
print(risk_table[["window","predicted_label","risk_score","risk_level","mitre_id"]].head(10).to_string(index=False))

print("\n" + "=" * 60)
print("Explainability & Risk Scoring complete.")
print("=" * 60)
