"""
Chronoguard — Synthetic Attack & Triage Scenario Simulator
Injects 3 realistic security scenarios into a test dataset split (data/attack_sim.csv):
  1. Confirmed Threat: Volumetric DoS / SYN Flood (Score > 90, Critical, Confirmed)
  2. Downgrade: Scheduled Off-Hours Backup (High byte volume, Benign, Downgraded to Warning)
  3. False Positive: Internal Dev Subnet Probe (Anomalous pattern, Audited & Dismissed as False Positive)

Usage:
    python pipeline/simulate_attack.py
"""

import os
import sys
import subprocess
import pandas as pd
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
BASE_TEST_CSV = os.path.join(DATA_DIR, "test.csv")
OUTPUT_SIM_CSV = os.path.join(DATA_DIR, "attack_sim.csv")

FEATURES = ["packet_rate", "byte_rate", "connection_count", "avg_syn_flags", "avg_duration"]
LAG_FEATURES = [
    "packet_rate_lag1", "byte_rate_lag1",
    "packet_rate_lag2", "byte_rate_lag2",
    "packet_rate_lag3", "byte_rate_lag3",
]


def generate_attack_simulation():
    if not os.path.exists(BASE_TEST_CSV):
        print(f"[ERROR] Baseline test dataset not found at {BASE_TEST_CSV}")
        sys.exit(1)

    print("=" * 68)
    print("  CHRONOGUARD — Generating Attack & Triage Simulation Dataset")
    print("=" * 68)

    df = pd.read_csv(BASE_TEST_CSV)
    sim_df = df.copy()

    # We will inject 3 specific demonstration scenarios at deterministic indices:
    # 1. Index 10: Confirmed Threat (Severe DoS SYN Flood)
    # 2. Index 25: Downgrade (Volumetric Backup Sync)
    # 3. Index 40: False Positive (Internal Dev Probe)

    # Scenario 1: DoS SYN Flood Attack (Confirmed Threat)
    idx1 = min(10, len(sim_df) - 1)
    sim_df.at[idx1, "packet_rate"] = 92450.00
    sim_df.at[idx1, "byte_rate"] = 4850000.00
    sim_df.at[idx1, "connection_count"] = 3120
    sim_df.at[idx1, "avg_syn_flags"] = 0.2850
    sim_df.at[idx1, "avg_duration"] = 2850000.00
    sim_df.at[idx1, "Label_num"] = 2  # DoS

    # Scenario 2: Off-Hours Large Backup Burst (Downgrade)
    idx2 = min(25, len(sim_df) - 1)
    sim_df.at[idx2, "packet_rate"] = 24500.00
    sim_df.at[idx2, "byte_rate"] = 8950000.00   # Extreme byte throughput
    sim_df.at[idx2, "connection_count"] = 180    # Few long-running backup flows
    sim_df.at[idx2, "avg_syn_flags"] = 0.0090   # Very clean TCP handshake
    sim_df.at[idx2, "avg_duration"] = 58200000.00
    sim_df.at[idx2, "Label_num"] = 0  # Benign

    # Scenario 3: Internal Staging Probe / Rapid API Benchmark (False Positive)
    idx3 = min(40, len(sim_df) - 1)
    sim_df.at[idx3, "packet_rate"] = 48500.00
    sim_df.at[idx3, "byte_rate"] = 980000.00
    sim_df.at[idx3, "connection_count"] = 2240   # Short burst of connections
    sim_df.at[idx3, "avg_syn_flags"] = 0.0540   # Slightly elevated
    sim_df.at[idx3, "avg_duration"] = 450000.00
    sim_df.at[idx3, "Label_num"] = 0  # Benign, but flags anomaly

    # Recompute lag features to keep time series integrity
    for lag in [1, 2, 3]:
        sim_df[f"packet_rate_lag{lag}"] = sim_df["packet_rate"].shift(lag).fillna(sim_df["packet_rate"])
        sim_df[f"byte_rate_lag{lag}"] = sim_df["byte_rate"].shift(lag).fillna(sim_df["byte_rate"])

    # Save to data/attack_sim.csv
    sim_df.to_csv(OUTPUT_SIM_CSV, index=False)
    print(f"[OK] Generated {OUTPUT_SIM_CSV} with {len(sim_df)} windows.")
    print(f"     [1] Index {idx1} -> Confirmed Threat (DoS SYN Flood)")
    print(f"     [2] Index {idx2} -> Downgrade (Backup Burst)")
    print(f"     [3] Index {idx3} -> False Positive (Dev Probe)")

    # Run dashboard generator to rebuild data.js
    gen_script = os.path.join(SCRIPT_DIR, "generate_dashboard_data.py")
    if os.path.exists(gen_script):
        print("\n[+] Updating dashboard data.js...")
        res = subprocess.run([sys.executable, gen_script], capture_output=True, text=True)
        if res.returncode == 0:
            print("[OK] Dashboard data updated successfully.")
            for line in res.stdout.splitlines():
                if line.strip():
                    print(f"    {line}")
        else:
            print("[ERROR] Failed to update dashboard data:")
            print(res.stderr)
    else:
        print(f"[WARN] {gen_script} not found.")


if __name__ == "__main__":
    generate_attack_simulation()
