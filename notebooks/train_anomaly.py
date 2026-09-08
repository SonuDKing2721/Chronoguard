"""
Chronoguard — Person 3: Anomaly Detection & Forecasting
Trains:
  1. Isolation Forest on normal-only traffic (Label_num == 0)
  2. Gradient Boosting Regressor for next-window risk forecasting
     using lagged features (packet_rate_lag1/2/3, byte_rate_lag1/2/3)

Saves both models to models/ folder.
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest, HistGradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, classification_report
from sklearn.preprocessing import StandardScaler

# ---- Paths ----
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

FEATURES = ["packet_rate", "byte_rate", "connection_count", "avg_syn_flags", "avg_duration"]
LAG_FEATURES = [
    "packet_rate_lag1", "byte_rate_lag1",
    "packet_rate_lag2", "byte_rate_lag2",
    "packet_rate_lag3", "byte_rate_lag3",
]

# ---- Load data ----
train_df = pd.read_csv(os.path.join(DATA_DIR, "train.csv"))
test_df = pd.read_csv(os.path.join(DATA_DIR, "test.csv"))

print("=" * 60)
print("CHRONOGUARD - Anomaly Detection & Forecasting Training")
print("=" * 60)

# ════════════════════════════════════════════════════════════
# 1. ISOLATION FOREST — trained on normal traffic only
# ════════════════════════════════════════════════════════════

print("\n--- Isolation Forest (Anomaly Detection) ---")

normal_train = train_df[train_df["Label_num"] == 0]
print(f"Normal-only training rows: {len(normal_train)}")

scaler = StandardScaler()
X_normal = scaler.fit_transform(normal_train[FEATURES])

# Auto-tune contamination based on actual class imbalance in training data
attack_ratio = (train_df["Label_num"] != 0).mean()
contamination = float(np.clip(attack_ratio, 0.01, 0.49))
print(f"Auto-tuned contamination: {contamination:.3f} (based on {attack_ratio:.1%} attack rate in train)")

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=contamination,
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
)
iso_forest.fit(X_normal)

# Evaluate on test set
X_test_scaled = scaler.transform(test_df[FEATURES])
anomaly_preds = iso_forest.predict(X_test_scaled)      # +1 = normal, -1 = anomaly
anomaly_scores = iso_forest.decision_function(X_test_scaled)

# Map predictions: ISO returns +1 (inlier) / -1 (outlier)
# We want: 0 = normal, 1 = anomaly
is_anomaly_pred = (anomaly_preds == -1).astype(int)
is_anomaly_true = (test_df["Label_num"] != 0).astype(int)

print("\nAnomaly Detection (binary: normal vs. anomalous):")
print(classification_report(is_anomaly_true, is_anomaly_pred,
                             target_names=["Normal", "Anomaly"], zero_division=0))

# Save model + scaler
joblib.dump(iso_forest, os.path.join(MODEL_DIR, "anomaly_model.joblib"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "anomaly_scaler.joblib"))
print("[OK] Saved anomaly_model.joblib + anomaly_scaler.joblib")

# ════════════════════════════════════════════════════════════
# 2. FORECASTING MODEL — predict next-window risk from lags
# ════════════════════════════════════════════════════════════

print("\n--- Forecasting Model (Lagged Features) ---")

# FIX: Changed sys.exit(0) to a soft warning + skip.
# This allows pipeline/run_pipeline.py to call this script without crashing
# when lag columns are absent — the forecaster is optional.
missing = [c for c in LAG_FEATURES if c not in train_df.columns]
if missing:
    print(f"[WARN] Missing lag columns: {missing}")
    print("[WARN] Skipping forecasting model. Add lag columns to data for trend analysis.")
    print("[INFO] The pipeline will run without the forecasting component.")
    # Write a sentinel file so other scripts know the forecaster wasn't trained
    sentinel_path = os.path.join(MODEL_DIR, "forecasting_skipped.txt")
    with open(sentinel_path, "w") as f:
        f.write(f"Forecasting model skipped — missing columns: {missing}\n")
else:
    # Target: binary "is next window risky" using Label_num as a proxy
    forecast_features = FEATURES + LAG_FEATURES

    X_train_fc = train_df[forecast_features].dropna()
    y_train_fc = train_df.loc[X_train_fc.index, "Label_num"].apply(lambda x: 0 if x == 0 else 1)

    X_test_fc = test_df[forecast_features].dropna()
    y_test_fc = test_df.loc[X_test_fc.index, "Label_num"].apply(lambda x: 0 if x == 0 else 1)

    print(f"Forecast training rows: {len(X_train_fc)}")
    print(f"Forecast test rows: {len(X_test_fc)}")

    if len(X_train_fc) == 0:
        print("[WARN] No training rows available after dropna — skipping forecaster.")
    else:
        forecaster = HistGradientBoostingRegressor(
            max_iter=200,
            learning_rate=0.05,
            max_depth=3,
            random_state=42,
        )
        forecaster.fit(X_train_fc, y_train_fc)

        y_pred_fc = forecaster.predict(X_test_fc)
        y_pred_binary = (y_pred_fc >= 0.5).astype(int)

        print("\nForecasting Model (binary: safe vs. risky):")
        print(classification_report(y_test_fc, y_pred_binary,
                                     target_names=["Safe", "Risky"], zero_division=0))

        mae = mean_absolute_error(y_test_fc, y_pred_fc)
        print(f"MAE: {mae:.4f}")

        joblib.dump(forecaster, os.path.join(MODEL_DIR, "forecasting_model.joblib"))
        print("[OK] Saved forecasting_model.joblib")

# ════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("Models saved:")
print(f"  - {os.path.join(MODEL_DIR, 'anomaly_model.joblib')}")
print(f"  - {os.path.join(MODEL_DIR, 'anomaly_scaler.joblib')}")
if not missing:
    print(f"  - {os.path.join(MODEL_DIR, 'forecasting_model.joblib')}")
else:
    print("  - forecasting_model.joblib  [SKIPPED — lag columns missing]")
print("=" * 60)
