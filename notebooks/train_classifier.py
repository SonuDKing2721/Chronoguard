"""
Chronoguard - Person 2: ML Classification Lead
Trains a multi-class traffic classifier (BENIGN / DDoS / DoS / Brute Force).

Uses sklearn's HistGradientBoostingClassifier — histogram-based gradient
boosting, equivalent to XGBoost in algorithm family. Natively handles
missing values and supports class_weight='balanced' for imbalanced data.

If your environment has xgboost installed, you can swap in:
    from xgboost import XGBClassifier
    model = XGBClassifier(n_estimators=300, learning_rate=0.08, max_depth=4,
                          scale_pos_weight=..., random_state=42, eval_metric='mlogloss')
with the same .fit() / .predict() / .predict_proba() calls.

Usage:
    python notebooks/train_classifier.py           # train and save model
    python notebooks/train_classifier.py --force   # retrain even if model exists
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, accuracy_score
)

# ---- Argument parsing ----
parser = argparse.ArgumentParser(description="Train Chronoguard classifier")
parser.add_argument(
    "--force", action="store_true",
    help="Retrain even if classifier_model.joblib already exists"
)
args = parser.parse_args()

# ---- Paths ----
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "classifier_model.joblib")

# ---- Skip if already trained ----
if os.path.exists(MODEL_PATH) and not args.force:
    print(f"[INFO] Classifier model already exists at {MODEL_PATH}")
    print("[INFO] Use --force to retrain. Skipping training.")
    sys.exit(0)

FEATURES = ["packet_rate", "byte_rate", "connection_count", "avg_syn_flags", "avg_duration"]
TARGET = "Label_num"
LABEL_NAMES = {0: "BENIGN", 1: "DDoS", 2: "DoS", 3: "Brute Force"}

print("=" * 60)
print("CHRONOGUARD - ML Classifier Training")
print("=" * 60)

# ---- Load data ----
train_path = os.path.join(DATA_DIR, "train.csv")
test_path = os.path.join(DATA_DIR, "test.csv")

if not os.path.exists(train_path):
    print(f"[ERROR] train.csv not found at {train_path}")
    sys.exit(1)
if not os.path.exists(test_path):
    print(f"[ERROR] test.csv not found at {test_path}")
    sys.exit(1)

train_df = pd.read_csv(train_path)
test_df = pd.read_csv(test_path)

# Validate columns
required_cols = FEATURES + [TARGET]
missing_cols = [c for c in required_cols if c not in train_df.columns]
if missing_cols:
    print(f"[ERROR] Missing columns in train.csv: {missing_cols}")
    sys.exit(1)

X_train, y_train = train_df[FEATURES], train_df[TARGET]
X_test, y_test = test_df[FEATURES], test_df[TARGET]

print(f"\nTraining set:  {len(X_train)} windows")
print(f"Test set:      {len(X_test)} windows")
print("\nTrain class counts:")
print(y_train.value_counts().sort_index().rename(index=LABEL_NAMES).to_string())
print("\nTest class counts:")
print(y_test.value_counts().sort_index().rename(index=LABEL_NAMES).to_string())

# ---- Train ----
print("\n--- Training HistGradientBoostingClassifier ---")
model = HistGradientBoostingClassifier(
    max_iter=500,           # Increased from 300 for better convergence on DoS
    learning_rate=0.08,
    max_depth=4,
    min_samples_leaf=5,
    l2_regularization=0.1,
    class_weight="balanced",  # Critical for sparse DDoS class
    random_state=42,
)
model.fit(X_train, y_train)
print("[OK] Training complete.")

# ---- Evaluate ----
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\n=== Overall Accuracy: {accuracy:.1%} ===")

print("\n=== Classification Report (per-class precision/recall/F1) ===")
report = classification_report(
    y_test, y_pred,
    target_names=[LABEL_NAMES[i] for i in sorted(LABEL_NAMES)],
    zero_division=0,
)
print(report)

print("=== Confusion Matrix (rows=true, cols=pred) ===")
labels_sorted = sorted(LABEL_NAMES)
cm = confusion_matrix(y_test, y_pred, labels=labels_sorted)
cm_df = pd.DataFrame(
    cm,
    index=[LABEL_NAMES[i] for i in labels_sorted],
    columns=[LABEL_NAMES[i] for i in labels_sorted]
)
print(cm_df)

per_class_f1 = f1_score(y_test, y_pred, average=None, labels=labels_sorted, zero_division=0)
print("\nPer-class F1:")
for i, f1 in zip(labels_sorted, per_class_f1):
    flag = "  [LOW]" if f1 < 0.5 else ""
    print(f"  {LABEL_NAMES[i]:12s}: {f1:.3f}{flag}")

macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
print(f"\nMacro F1:    {macro_f1:.3f}")
print(f"Weighted F1: {weighted_f1:.3f}")

# DDoS specific note — documented data limitation
ddos_test_count = (y_test == 1).sum()
print(f"\n[NOTE] DDoS has only {ddos_test_count} test examples (16 train). "
      f"Its F1 score is expected to be noisy — this is a known data limitation.")

# ---- Save model ----
joblib.dump(model, MODEL_PATH)
print(f"\n[OK] Saved model to {MODEL_PATH}")

# Save metrics report
report_path = os.path.join(OUTPUT_DIR, "classifier_report.txt")
with open(report_path, "w") as f:
    f.write("Chronoguard - ML Classification Report\n")
    f.write("=" * 60 + "\n")
    f.write("Model: sklearn HistGradientBoostingClassifier\n")
    f.write(f"Features: {FEATURES}\n")
    f.write(f"Overall Accuracy: {accuracy:.1%}\n\n")
    f.write(report)
    f.write("\nConfusion Matrix:\n")
    f.write(cm_df.to_string())
    f.write(f"\n\nMacro F1:    {macro_f1:.3f}\n")
    f.write(f"Weighted F1: {weighted_f1:.3f}\n")
    f.write(f"\nNote: DDoS class has only {ddos_test_count} test / 16 train examples — "
            f"expect noisy F1 for this class specifically.\n")

print(f"[OK] Saved report to {report_path}")
print("\n" + "=" * 60)
print("Training complete. Run next: python notebooks/train_anomaly.py")
print("=" * 60)
