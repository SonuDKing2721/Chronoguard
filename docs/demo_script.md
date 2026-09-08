# Chronoguard — Demo Presentation Script

> Use this as your narration guide during the live demo.
> Estimated time: 5–7 minutes.

---

## Opening (30 seconds)

> "Chronoguard is an AI-powered network threat intelligence system. It monitors enterprise traffic in **per-minute windows**, classifies attacks using machine learning, detects anomalies with Isolation Forest, and combines everything into a single risk score that tells SOC analysts exactly how worried they should be — and why."

**Action:** Show the dashboard with a BENIGN window loaded (Window 1).

---

## Part 1: Normal Traffic (1 minute)

> "Here we're looking at normal traffic from the CICIDS2017 dataset. The risk gauge shows a score of [read score] — **Low**. The classifier correctly identifies this as BENIGN traffic with [read confidence]% confidence. Notice the anomaly ring shows NORMAL, and no MITRE ATT&CK techniques are mapped."

**Action:** Point to:
- Risk gauge (green, low score)
- Classification panel (BENIGN badge)
- Anomaly ring (green, NORMAL)
- Empty MITRE section

---

## Part 2: Step Into an Attack (2 minutes)

> "Now let's advance to a window where our models detect a Denial of Service attack."

**Action:** Navigate to a DoS window (use arrow keys or click timeline).

> "Immediately you can see the dashboard transform. The risk score jumps to [read score] — **High/Critical**. The classifier identifies this as a **DoS** attack. Look at the SHAP explanation panel on the right — it tells us *why*: the primary drivers are byte_rate and packet_rate, which are abnormally high. This is consistent with a volumetric denial-of-service attack."

**Point out:**
- Risk gauge (orange/red)
- Classification confidence bars
- SHAP feature importance bars
- MITRE ATT&CK mapping: **T1499 — Endpoint Denial of Service**

---

## Part 3: Brute Force Attack (1.5 minutes)

> "Let's look at a different type of attack."

**Action:** Navigate to a Brute Force window.

> "This time it's a **Brute Force** attack — someone trying to guess credentials. Notice the SHAP explanation is completely different: now the top features are connection_count and avg_syn_flags, not byte_rate. The system doesn't just detect that something is wrong — it explains the *mechanism* of the attack. MITRE maps this to **T1110 — Brute Force** under the Credential Access tactic."

---

## Part 4: Timeline & Trends (1 minute)

> "The timeline at the bottom shows risk scores across all [220] test windows. You can see clusters of high-risk activity here [point], and the system transitions smoothly between normal and attack periods."

**Action:** Click on the timeline to jump between high and low risk areas.

> "Security analysts can click anywhere on this timeline to investigate specific windows. Or they can press play and watch the system step through windows automatically."

**Action:** Press spacebar to auto-play for 5–10 seconds, then stop.

---

## Part 5: Technical Architecture (1 minute)

> "Under the hood, Chronoguard uses three ML models working together:
> 1. A **gradient-boosted classifier** that categorizes traffic into 4 types
> 2. An **Isolation Forest** trained only on normal traffic that detects anything unusual
> 3. A **forecasting model** using lagged features to predict trend direction
>
> These feed into a composite risk formula that also incorporates MITRE ATT&CK severity weights. The result is a single 0–100 score with explainable components."

---

## Closing (30 seconds)

> "Chronoguard demonstrates that modern ML can provide actionable, explainable threat intelligence — not just 'this looks bad,' but 'this is a DoS attack because byte_rate spiked, and here's the MITRE technique.' This is the future of automated SOC augmentation."

---

## Backup Plan

If WiFi or projector fails on demo day:

1. **Screen recording:** Pre-record a 3-minute walkthrough of the dashboard
   - Open `dashboard/index.html` in Chrome
   - Use Windows built-in screen recording (Win+G → Record)
   - Walk through BENIGN → DoS → Brute Force scenarios
   - Save the recording

2. **Static screenshots:** Take 3 screenshots showing:
   - BENIGN window (low risk, green gauge)
   - DoS window (high risk, red gauge, SHAP bars)
   - Timeline view with attack clusters

3. **Terminal fallback:** Run `python pipeline/demo_scenarios.py` — it prints formatted results to the terminal, no GUI needed.

---

## Key Numbers to Remember

| Metric | Value |
|--------|-------|
| Dataset | CICIDS2017 |
| Window size | **1 minute** (not 10-second) |
| Attack classes | 4 (BENIGN, DDoS, DoS, Brute Force) |
| Overall accuracy | 87% |
| Weighted F1 | 0.863 |
| Risk score range | 0–100 |
| Test windows | 220 |

> **Do NOT say "10-second windows"** — the data only supports minute-level precision.
> **Do NOT demo DDoS** — only 5 test examples, scores will be unreliable.
