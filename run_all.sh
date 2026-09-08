#!/bin/bash
# ╔══════════════════════════════════════════════════════╗
# ║   Chronoguard — One-Click Runner (Linux / Mac)      ║
# ║   Runs the full pipeline from training to dashboard  ║
# ╚══════════════════════════════════════════════════════╝

set -e  # Exit immediately on any error

echo ""
echo "================================================"
echo "  CHRONOGUARD - Full Pipeline Runner"
echo "================================================"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Please install Python 3.10+."
    exit 1
fi

PYTHON=python3

# Install dependencies
echo "[1/6] Installing dependencies..."
$PYTHON -m pip install -r requirements.txt --quiet
echo "[OK] Dependencies ready."
echo ""

# Step 1: Train classifier
echo "[2/6] Training ML Classifier..."
$PYTHON notebooks/train_classifier.py
echo ""

# Step 2: Train anomaly model
echo "[3/6] Training Anomaly Detection Model..."
$PYTHON notebooks/train_anomaly.py
echo ""

# Step 3: Explainability + risk scoring
echo "[4/6] Running Explainability & Risk Scoring..."
$PYTHON notebooks/explainability.py
echo ""

# Step 4: End-to-end pipeline (also generates dashboard data)
echo "[5/6] Running Integration Pipeline + Dashboard Data..."
$PYTHON pipeline/run_pipeline.py
echo ""

# Step 5: Demo scenarios
echo "[6/6] Selecting Demo Scenarios..."
$PYTHON pipeline/demo_scenarios.py
echo ""

echo "================================================"
echo "  ALL DONE! Open dashboard/index.html in your browser."
echo "================================================"
echo ""
