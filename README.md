# Chronoguard

> **AI-Powered Network Threat Intelligence System**
> Real-time traffic classification, anomaly detection, and risk scoring for enterprise network security.

[![Dataset](https://img.shields.io/badge/Dataset-CICIDS2017-blue)](https://www.unb.ca/cic/datasets/ids-2017.html)
[![Python](https://img.shields.io/badge/Python-3.10+-green)]()
[![sklearn](https://img.shields.io/badge/scikit--learn-1.2+-orange)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

---

## Overview

Chronoguard is an end-to-end machine learning pipeline that monitors network traffic in **per-minute windows**, classifies attack types, detects anomalies, and produces a composite risk score — all visualized in a real-time interactive dashboard.

Built for **Smart India Hackathon (SIH)**, it demonstrates how ML can augment Security Operations Centers (SOCs) with automated threat detection and explainable risk assessment.

## Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │              CICIDS2017 Dataset                  │
                    │    Tuesday + Wednesday + Friday-DDoS CSVs        │
                    └────────────────────┬────────────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────────────┐
                    │            Data Pipeline (Person 1)              │
                    │  Clean → Label Map → Per-Minute Windowing        │
                    │  → Lag Features → Stratified Train/Test Split    │
                    └────────────────────┬────────────────────────────┘
                                         │
                         ┌───────────────┼───────────────┐
                         ▼               ▼               ▼
               ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
               │ HistGradient │ │  Isolation   │ │  Forecasting     │
               │ Boosting     │ │  Forest      │ │  Model (Lagged)  │
               │ Classifier   │ │  (Normal     │ │  (Risk Trend)    │
               │  (4 classes) │ │   only)      │ │                  │
               └──────┬───────┘ └──────┬───────┘ └────────┬─────────┘
                      │                │                   │
                      └────────────────┼───────────────────┘
                                       ▼
               ┌─────────────────────────────────────────────────────┐
               │          Explainability & Risk Engine                │
               │  SHAP Feature Importance + MITRE ATT&CK Mapping     │
               │  Composite Risk Score (0-100) → Low/Med/High/Crit   │
               └────────────────────────┬────────────────────────────┘
                                        ▼
               ┌─────────────────────────────────────────────────────┐
               │           Interactive Dashboard                      │
               │  Risk Gauge │ Classification │ Timeline │ Alerts     │
               │  Anomaly Detection │ SHAP Bars │ MITRE Cards         │
               └─────────────────────────────────────────────────────┘
```

## Dataset

**Source:** [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — `GeneratedLabelledFlows` variant

| Property | Value |
|----------|-------|
| CSVs Used | Tuesday, Wednesday, Friday-Afternoon-DDoS |
| Window Size | **1 minute** (timestamp precision) |
| Train Windows | 869 |
| Test Windows | 220 |
| Split Strategy | Stratified 80/20 per class, re-sorted by time |

### Attack Categories

| Label | Class | MITRE ATT&CK | Train Count | Test Count |
|-------|-------|---------------|-------------|------------|
| 0 | BENIGN | N/A | 691 | 173 |
| 1 | DDoS | T1498 | 16 | 5 |
| 2 | DoS (Hulk, GoldenEye, Slowloris, Slowhttptest) | T1499 | 60 | 15 |
| 3 | Brute Force (FTP-Patator, SSH-Patator) | T1110 | 101 | 26 |

> **Note:** PortScan is not included in this dataset. DDoS has very few examples (21 total) — expect noisy scores for this class.

### Features (Per-Minute Aggregates)

| Column | Description |
|--------|-------------|
| `window` | Timestamp (per-minute) |
| `packet_rate` | Mean Flow Packets/s |
| `byte_rate` | Mean Flow Bytes/s |
| `connection_count` | Number of flows |
| `avg_syn_flags` | Mean SYN Flag Count |
| `avg_duration` | Mean Flow Duration |
| `packet_rate_lag1/2/3` | Lagged packet rate (1-3 windows back) |
| `byte_rate_lag1/2/3` | Lagged byte rate (1-3 windows back) |
| `Label_num` | Attack class (0-3) |

## Model Performance

### Classifier (HistGradientBoostingClassifier)

> **Note:** Using sklearn's `HistGradientBoostingClassifier` — same algorithm family as XGBoost (histogram-based gradient boosting), fully compatible drop-in. See `notebooks/train_classifier.py` for XGBoost swap instructions.

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------| 
| BENIGN | 0.91 | 0.96 | 0.94 | 173 |
| DDoS | 0.71 | 1.00 | 0.83 | 5 |
| DoS | 0.50 | 0.33 | 0.40 | 15 |
| Brute Force | 0.75 | 0.58 | 0.65 | 26 |

- **Weighted F1:** 0.863
- **Macro F1:** 0.705
- **Overall Accuracy:** 87%

### Risk Scoring Formula

```
Risk Score = 0.35 × P(attack) + 0.25 × anomaly_score + 0.15 × trend_score + 0.25 × severity_weight
```

| Risk Level | Score Range | Action |
|------------|-------------|--------|
| Low | 0–24 | Monitor |
| Medium | 25–49 | Investigate |
| High | 50–74 | Respond |
| Critical | 75–100 | Immediate escalation |

## Project Structure

```
Chronoguard/
├── data/
│   ├── train.csv              # Training data (869 windows)
│   └── test.csv               # Test data (220 windows)
├── models/
│   ├── classifier_model.joblib    # Multi-class traffic classifier
│   ├── anomaly_model.joblib       # Isolation Forest
│   ├── anomaly_scaler.joblib      # StandardScaler for anomaly model
│   └── forecasting_model.joblib   # Risk trend forecaster (optional)
├── notebooks/
│   ├── train_classifier.py    # HistGradientBoosting classifier training
│   ├── train_anomaly.py       # Isolation Forest + forecasting
│   └── explainability.py      # SHAP + composite risk scoring
├── pipeline/
│   ├── run_pipeline.py        # End-to-end integration pipeline
│   ├── demo_scenarios.py      # Demo scenario selector
│   └── generate_dashboard_data.py  # Dashboard JSON generator
├── dashboard/
│   ├── index.html             # Interactive dashboard
│   ├── style.css              # Premium dark-mode styles
│   ├── app.js                 # Dashboard logic
│   └── data.js                # Pre-computed data (auto-generated)
├── outputs/
│   ├── classifier_report.txt  # Classification metrics
│   ├── risk_table_full.csv    # Detailed risk scores (all test windows)
│   ├── risk_table.csv         # Summary risk table
│   ├── shap_summary.csv       # SHAP feature importance
│   └── demo_results.csv       # Full pipeline results
├── docs/
│   └── demo_script.md         # Presentation narration guide
├── requirements.txt           # Python dependencies
├── run_all.bat                # One-click runner (Windows)
├── run_all.sh                 # One-click runner (Linux/Mac)
├── .env.example               # Environment variables template
└── README.md
```

## Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
```

### Option A — One-Click Runner (Recommended)

**Windows:**
```cmd
run_all.bat
```

**Linux / Mac:**
```bash
bash run_all.sh
```

This runs all steps automatically and opens the dashboard when done.

### Option B — Step-by-Step

#### 1. Train Models

```bash
# Classifier (HistGradientBoosting — XGBoost-equivalent)
python notebooks/train_classifier.py

# Anomaly detection + forecasting
python notebooks/train_anomaly.py

# Explainability + risk scoring
python notebooks/explainability.py
```

#### 2. Run Integration Pipeline

```bash
python pipeline/run_pipeline.py
```

This also auto-generates `dashboard/data.js`.

#### 3. Open Dashboard

Open `dashboard/index.html` in any modern browser. **No server required** — works completely offline.

**Dashboard Controls:**
- **Arrow keys** or click ◀/▶ to step through windows
- **Spacebar** to auto-play
- **Click timeline** to jump to any window
- **Speed slider** to adjust playback speed

## Security

- **Never commit tokens or credentials** — use `.env` (see `.env.example`)
- The `.gitignore` is configured to exclude `.env` files

## Known Limitations

1. **Per-minute windows (not 10-second):** CICIDS2017 timestamps have minute-level precision only
2. **DDoS is sparse:** Only 21 total windows (16 train / 5 test) — expect noisy F1 scores
3. **No PortScan category:** Only 3 CSVs were used; PortScan data was not included
4. **Stratified split:** Not purely chronological — each class was split 80/20 independently, then merged and time-sorted
5. **Simulated dashboard data:** Dashboard uses calibrated simulations of model outputs for offline demo capability

## Team

| Role | Responsibility |
|------|---------------|
| Person 1 — Data Lead | Dataset preparation, windowing, feature engineering |
| Person 2 — ML Classification | HistGradientBoosting classifier training & evaluation |
| Person 3 — Forecasting/Anomaly | Isolation Forest, lagged-feature forecasting |
| Person 4 — Explainability/Risk | SHAP analysis, MITRE mapping, risk scoring |
| Person 5 — Dashboard | Interactive visualization |
| Person 6 — Integration & Presentation | End-to-end pipeline, demo prep, documentation |

## License

MIT License — built for Smart India Hackathon (SIH).
