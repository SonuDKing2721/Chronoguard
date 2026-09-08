"""
Chronoguard — Demo Scenario Selector
Picks 3 representative windows from test data for the live demo:
  1. BENIGN   -> should show Low risk
  2. DoS      -> should show High/Critical risk
  3. Brute Force -> should show High risk

Skips DDoS (only 5 test examples - too sparse for reliable live demo).

Usage:
    python pipeline/demo_scenarios.py
"""

import os
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")

LABEL_NAMES = {0: "BENIGN", 1: "DDoS", 2: "DoS", 3: "Brute Force"}


def main():
    # Try to load pipeline results first; fall back to raw test data
    results_path = os.path.join(OUTPUT_DIR, "demo_results.csv")
    test_path = os.path.join(PROJECT_ROOT, "data", "test.csv")

    if os.path.exists(results_path):
        df = pd.read_csv(results_path)
        has_risk = "risk_score" in df.columns
        label_col = "true_label"
    else:
        df = pd.read_csv(test_path)
        has_risk = False
        label_col = "Label_num"
        df["true_label"] = df["Label_num"].map(LABEL_NAMES)
        label_col = "true_label"

    print("=" * 70)
    print("  CHRONOGUARD - Demo Scenario Selector")
    print("  Recommended windows for live presentation")
    print("=" * 70)

    scenarios = [
        ("BENIGN",      "Normal traffic - should show LOW risk",        0),
        ("DoS",         "Denial of Service - should show HIGH/CRITICAL", 2),
        ("Brute Force", "Credential attack - should show HIGH risk",     3),
    ]

    selected = []

    for label, description, label_num in scenarios:
        subset = df[df["true_label"] == label]

        if len(subset) == 0:
            print(f"\n[SKIP] No {label} windows found in test data.")
            continue

        # Pick a representative row (median by connection count for variety)
        if has_risk:
            # Pick row closest to median risk for that class
            median_risk = subset["risk_score"].median()
            idx = (subset["risk_score"] - median_risk).abs().idxmin()
        else:
            idx = subset.index[len(subset) // 2]

        row = df.loc[idx]
        selected.append(row)

        print(f"\n{'_' * 70}")
        print(f"  SCENARIO: {label}")
        print(f"  {description}")
        print(f"{'_' * 70}")
        print(f"  Window:          {row['window']}")
        print(f"  Packet Rate:     {row.get('packet_rate', 'N/A'):,.2f} pkts/s")
        print(f"  Byte Rate:       {row.get('byte_rate', 'N/A'):,.2f} bytes/s")
        print(f"  Connections:     {int(row.get('connection_count', 0))}")
        print(f"  SYN Flag Rate:   {row.get('avg_syn_flags', 'N/A'):.4f}")
        if has_risk:
            print(f"  Predicted Label: {row.get('predicted_label', 'N/A')}")
            print(f"  Confidence:      {row.get('confidence', 'N/A'):.1%}")
            print(f"  Risk Score:      {row.get('risk_score', 'N/A'):.1f} / 100")
            print(f"  Risk Level:      {row.get('risk_level', 'N/A')}")
            print(f"  MITRE Technique: {row.get('mitre_id', 'N/A')} - {row.get('mitre_technique', 'N/A')}")

    # Save selected scenarios
    if selected:
        selected_df = pd.DataFrame(selected)
        out_path = os.path.join(OUTPUT_DIR, "demo_scenarios.csv")
        selected_df.to_csv(out_path, index=False)
        print(f"\n\n[OK] Saved selected scenarios to {out_path}")

    print("\n" + "=" * 70)
    print("  TIP: DDoS is omitted (only 5 test examples).")
    print("  Show BENIGN -> DoS -> Brute Force for the clearest demo.")
    print("=" * 70)


if __name__ == "__main__":
    main()
