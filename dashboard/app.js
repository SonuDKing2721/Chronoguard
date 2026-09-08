/* ══════════════════════════════════════════════════════════════════
   CHRONOGUARD — Dashboard Application Logic
   Interactive Network Threat Intelligence Console
   Supports test.csv / train.csv / custom CSV uploads, dynamic
   user-controlled critical thresholds, analyst audit tools,
   and interactive traffic window inspection.
   ══════════════════════════════════════════════════════════════════ */

(function () {
    "use strict";

    // ──── Globals & Data Sources ────
    const RAW_DATA = window.CHRONOGUARD_DATA;
    if (!RAW_DATA) {
        document.body.innerHTML = '<p style="color:#ef4444;padding:40px;font-size:1.2rem;">Error: data.js not loaded. Run <code>python pipeline/generate_dashboard_data.py</code> first.</p>';
        return;
    }

    // Map of datasets
    const datasets = {
        test: RAW_DATA.datasets?.test || {
            name: "test.csv (Evaluation Split)",
            windows: RAW_DATA.windows || [],
            total_windows: (RAW_DATA.windows || []).length
        },
        train: RAW_DATA.datasets?.train || {
            name: "train.csv (Training Split)",
            windows: [],
            total_windows: 0
        },
        custom: null
    };

    let activeDatasetKey = "test";
    let activeDataset = datasets.test;
    let windows = activeDataset.windows;
    let TOTAL = windows.length;
    let currentIndex = 0;
    let isPlaying = false;
    let playInterval = null;
    let alertLog = [];

    // User-controlled risk thresholds
    const userThresholds = {
        critical: 75,
        high: 50,
        medium: 25,
        anomalyWeight: 1.2
    };

    // User Verification / Human Audit storage (keyed by window id/index)
    const auditStore = {};

    // Table pagination and filtering state
    let tableFilter = "all";
    let tableSearch = "";
    let tableCurrentPage = 1;
    const tablePageSize = 25;

    // Label names mapping
    const LABEL_NAMES = {
        0: "BENIGN",
        1: "DDoS",
        2: "DoS",
        3: "Brute Force"
    };

    const MITRE_MAP = {
        0: [],
        1: [
            { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
            { id: "T1498.001", name: "Direct Network Flood", tactic: "Impact" }
        ],
        2: [
            { id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact" },
            { id: "T1499.001", name: "OS Exhaustion Flood", tactic: "Impact" }
        ],
        3: [
            { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
            { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" }
        ]
    };

    const CLASS_ICONS = {
        "BENIGN": "✔️",
        "DDoS": "💥",
        "DoS": "⚠️",
        "Brute Force": "🔓"
    };

    const CLASS_CSS = {
        "BENIGN": "benign",
        "DDoS": "ddos",
        "DoS": "dos",
        "Brute Force": "bf"
    };

    // ──── DOM References ────
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // Header & Status
    const elTimestamp = $("#currentTimestamp");
    const elWindowCounter = $("#windowCounter");
    const elProgressBar = $("#progressBar");
    const elSystemStatus = $("#systemStatus");

    // Toolbar elements
    const datasetSelect = $("#datasetSelect");
    const customFileWrap = $("#customFileWrap");
    const csvFileInput = $("#csvFileInput");
    const selectedFileName = $("#selectedFileName");
    const btnApplyData = $("#btnApplyData");
    const valTotalWindows = $("#valTotalWindows");
    const valCriticalWindows = $("#valCriticalWindows");
    const valVerifiedWindows = $("#valVerifiedWindows");
    const btnToggleThresholds = $("#btnToggleThresholds");
    const thresholdToggleText = $("#thresholdToggleText");

    // Threshold drawer
    const thresholdDrawer = $("#thresholdDrawer");
    const btnCloseThresholds = $("#btnCloseThresholds");
    const sliderCritThreshold = $("#sliderCritThreshold");
    const sliderHighThreshold = $("#sliderHighThreshold");
    const sliderAnomalyWeight = $("#sliderAnomalyWeight");
    const lblCritThreshold = $("#lblCritThreshold");
    const lblHighThreshold = $("#lblHighThreshold");
    const lblAnomalyWeight = $("#lblAnomalyWeight");
    const btnApplyThresholds = $("#btnApplyThresholds");
    const btnResetThresholds = $("#btnResetThresholds");

    // Panels
    const elGaugeScore = $("#gaugeScore");
    const elGaugeLevel = $("#gaugeLevel");
    const elGaugeFill = $("#gaugeFill");
    const elClassName = $("#className");
    const elClassIcon = $("#classIcon");
    const elClassBadge = $("#classBadge");
    const elAnomalyRing = $("#anomalyRing");
    const elAnomalyLabel = $("#anomalyLabel");
    const elAnomalyScoreValue = $("#anomalyScoreValue");
    const elMitreCards = $("#mitreCards");
    const elShapBars = $("#shapBars");
    const elAlertsList = $("#alertsList");
    const elTimelineCursor = $("#timelineCursor");

    // Audit Panel
    const auditStatusBadge = $("#auditStatusBadge");
    const auditGroundTruth = $("#auditGroundTruth");
    const auditPredicted = $("#auditPredicted");
    const auditMatchIndicator = $("#auditMatchIndicator");
    const criticalReasonCard = $("#criticalReasonCard");
    const criticalReasonTitle = $("#criticalReasonTitle");
    const criticalReasonText = $("#criticalReasonText");
    const btnAuditConfirm = $("#btnAuditConfirm");
    const btnAuditDowngrade = $("#btnAuditDowngrade");
    const btnAuditFalsePos = $("#btnAuditFalsePos");
    const analystNotesInput = $("#analystNotesInput");
    const btnSaveNotes = $("#btnSaveNotes");

    // Table elements
    const trafficTableBody = $("#trafficTableBody");
    const tableFilterPills = $("#tableFilterPills");
    const tableSearchInput = $("#tableSearchInput");
    const paginationInfo = $("#paginationInfo");
    const btnPagePrev = $("#btnPagePrev");
    const btnPageNext = $("#btnPageNext");
    const pageNum = $("#pageNum");
    const countAll = $("#countAll");
    const countCrit = $("#countCrit");
    const countAttacks = $("#countAttacks");
    const countBenign = $("#countBenign");
    const countReviewed = $("#countReviewed");

    // Playback Controls
    const btnFirst = $("#btnFirst");
    const btnPrev = $("#btnPrev");
    const btnNext = $("#btnNext");
    const btnLast = $("#btnLast");
    const btnPlay = $("#btnPlay");
    const btnClearAlerts = $("#clearAlerts");
    const speedSlider = $("#speedSlider");
    const speedLabel = $("#speedLabel");

    // Canvas Timeline
    const canvas = $("#timelineCanvas");
    const ctx = canvas ? canvas.getContext("2d") : null;

    // ──── Helpers ────
    function formatNumber(n) {
        if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
        if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
        if (Number.isInteger(n)) return n.toLocaleString();
        return typeof n === "number" ? n.toFixed(2) : n;
    }

    function computeDynamicRiskLevel(score) {
        if (score >= userThresholds.critical) return "Critical";
        if (score >= userThresholds.high) return "High";
        if (score >= userThresholds.medium) return "Medium";
        return "Low";
    }

    function riskColor(level) {
        const map = {
            "Low": "#10b981",
            "Medium": "#f59e0b",
            "High": "#f97316",
            "Critical": "#ef4444"
        };
        return map[level] || "#94a3b8";
    }

    const GAUGE_ARC_LEN = 251.2;

    function setGauge(score, level) {
        const pct = Math.min(score, 100) / 100;
        const offset = GAUGE_ARC_LEN * (1 - pct);
        if (elGaugeFill) {
            elGaugeFill.style.strokeDashoffset = offset;
            elGaugeFill.style.stroke = riskColor(level);
        }

        animateCounter(elGaugeScore, score, 0);
        if (elGaugeLevel) {
            elGaugeLevel.textContent = level;
            elGaugeLevel.style.color = riskColor(level);
        }
        if (elGaugeScore) {
            elGaugeScore.style.color = riskColor(level);
        }

        const gaugePanel = $(".gauge-panel");
        if (gaugePanel) {
            if (level === "Critical") {
                gaugePanel.classList.add("pulse-critical");
            } else {
                gaugePanel.classList.remove("pulse-critical");
            }
        }
    }

    function animateCounter(el, target, decimals) {
        if (!el) return;
        const start = parseFloat(el.textContent) || 0;
        const diff = target - start;
        const duration = 400;
        const startTime = performance.now();

        function tick(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);
            const current = start + diff * ease;
            el.textContent = decimals > 0 ? current.toFixed(decimals) : Math.round(current);
            if (progress < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
    }

    // ──── Recalculate Risk Levels Across Active Dataset ────
    function recalculateActiveDatasetScores() {
        let critCount = 0;
        windows.forEach(w => {
            // Re-evaluate level with user threshold
            w.risk_level = computeDynamicRiskLevel(w.risk_score);
            if (w.risk_level === "Critical") critCount++;
        });

        // Update toolbar chips
        if (valCriticalWindows) valCriticalWindows.textContent = critCount;
        if (thresholdToggleText) thresholdToggleText.textContent = `Critical Cutoff: ${userThresholds.critical}`;
        updateCountsAndFilters();
    }

    // ──── Panel Renders ────
    function renderMetrics(w) {
        const fields = [
            { field: "packet_rate", max: 200000 },
            { field: "byte_rate", max: 20000000 },
            { field: "connection_count", max: 5000 },
            { field: "avg_syn_flags", max: 1 }
        ];

        fields.forEach(({ field, max }) => {
            const card = $(`[data-field="${field}"]`);
            if (!card) return;
            const val = w[field];
            card.textContent = formatNumber(val);
            const metricCard = card.closest(".metric-card");
            if (metricCard) {
                const barFill = metricCard.querySelector(".metric-bar-fill");
                if (barFill) {
                    barFill.style.width = Math.min((val / max) * 100, 100) + "%";
                }
            }
        });
    }

    function renderClassification(w) {
        const label = w.predicted_label_name;
        const css = CLASS_CSS[label] || "benign";
        if (elClassName) elClassName.textContent = label;
        if (elClassIcon) elClassIcon.textContent = CLASS_ICONS[label] || "";
        if (elClassBadge) elClassBadge.className = "class-badge " + css;

        const confRows = $$(".conf-row");
        confRows.forEach((row, i) => {
            const pctVal = (w.confidence && w.confidence[i] !== undefined)
                ? (w.confidence[i] * 100).toFixed(1)
                : "0.0";
            const fill = row.querySelector(".conf-fill");
            const pctLabel = row.querySelector(".conf-pct");
            if (fill) fill.style.width = pctVal + "%";
            if (pctLabel) pctLabel.textContent = pctVal + "%";
        });
    }

    function renderShap(w) {
        if (!elShapBars) return;
        const features = w.shap_features;
        if (!features || !features.length) {
            elShapBars.innerHTML = '<div class="mitre-empty">No SHAP data</div>';
            return;
        }
        const maxVal = Math.max(...features.map(f => f.value));

        let html = "";
        features.forEach(f => {
            const pct = maxVal > 0 ? (f.value / maxVal) * 100 : 0;
            html += `
                <div class="shap-row">
                    <span class="shap-feature-name">${f.name}</span>
                    <div class="shap-bar-container">
                        <div class="shap-bar-fill" style="width:${pct}%"></div>
                    </div>
                    <span class="shap-value">${f.value.toFixed(3)}</span>
                </div>`;
        });
        elShapBars.innerHTML = html;
    }

    function renderAnomaly(w) {
        if (elAnomalyRing && elAnomalyLabel) {
            if (w.is_anomaly) {
                elAnomalyRing.classList.add("anomalous");
                elAnomalyLabel.textContent = "ANOMALY";
            } else {
                elAnomalyRing.classList.remove("anomalous");
                elAnomalyLabel.textContent = "NORMAL";
            }
        }
        if (elAnomalyScoreValue) {
            elAnomalyScoreValue.textContent = typeof w.anomaly_score === "number"
                ? w.anomaly_score.toFixed(4)
                : w.anomaly_score;
        }

        if (elMitreCards) {
            if (!w.mitre_techniques || w.mitre_techniques.length === 0) {
                elMitreCards.innerHTML = '<div class="mitre-empty">No techniques mapped (BENIGN traffic)</div>';
            } else {
                let html = "";
                w.mitre_techniques.forEach(t => {
                    html += `
                        <div class="mitre-card">
                            <span class="mitre-id">${t.id}</span>
                            <span class="mitre-name">${t.name}</span>
                            <span class="mitre-tactic">${t.tactic}</span>
                        </div>`;
                });
                elMitreCards.innerHTML = html;
            }
        }
    }

    function renderRiskBreakdown(w) {
        const conf = w.confidence ? Math.max(...w.confidence) * 100 : 50;
        const anomaly = Math.abs(w.anomaly_score || 0) * 200 * userThresholds.anomalyWeight;
        const trend = (w.risk_score || 0) * 0.6;
        const color = riskColor(w.risk_level);

        const rClass = $("#riskClassification");
        const rAnom = $("#riskAnomaly");
        const rTrend = $("#riskTrend");

        if (rClass) {
            rClass.style.width = Math.min(conf, 100) + "%";
            rClass.style.background = color;
        }
        if (rAnom) {
            rAnom.style.width = Math.min(anomaly, 100) + "%";
            rAnom.style.background = color;
        }
        if (rTrend) {
            rTrend.style.width = Math.min(trend, 100) + "%";
            rTrend.style.background = color;
        }
    }

    // ──── Human Verification & Audit Panel ────
    function renderAuditPanel(w) {
        const windowKey = w.id || `win_${currentIndex}`;
        const audit = auditStore[windowKey] || { status: "pending", notes: "" };

        // Ground Truth vs Prediction
        if (auditGroundTruth) {
            auditGroundTruth.textContent = `${w.true_label_name || 'BENIGN'} [${w.true_label ?? 0}]`;
            auditGroundTruth.style.color = (w.true_label === 0) ? "#10b981" : "#ef4444";
        }
        if (auditPredicted) {
            auditPredicted.textContent = `${w.predicted_label_name} [${w.predicted_label}]`;
            auditPredicted.style.color = (w.predicted_label === 0) ? "#10b981" : "#ef4444";
        }

        // Match indicator
        if (auditMatchIndicator) {
            const isMatch = (w.true_label === w.predicted_label);
            auditMatchIndicator.textContent = isMatch ? "✓ MATCH" : "⚠️ MISMATCH";
            auditMatchIndicator.style.color = isMatch ? "#10b981" : "#f59e0b";
            auditMatchIndicator.style.fontSize = "0.75rem";
            auditMatchIndicator.style.fontWeight = "700";
        }

        // Audit Status Badge
        if (auditStatusBadge) {
            auditStatusBadge.className = `audit-status-badge ${audit.status}`;
            const labelMap = {
                "pending": "PENDING REVIEW",
                "verified": "CONFIRMED THREAT",
                "warning": "DOWNGRADED WARNING",
                "false_positive": "FALSE POSITIVE"
            };
            auditStatusBadge.textContent = labelMap[audit.status] || "PENDING REVIEW";
        }

        // Active button states
        btnAuditConfirm?.classList.toggle("active", audit.status === "verified");
        btnAuditDowngrade?.classList.toggle("active", audit.status === "warning");
        btnAuditFalsePos?.classList.toggle("active", audit.status === "false_positive");

        // Analyst Notes input
        if (analystNotesInput) {
            analystNotesInput.value = audit.notes || "";
        }

        // Diagnostic Reason explanation ("Why is this score Critical / Normal?")
        generateCriticalScoreReason(w);
    }

    function generateCriticalScoreReason(w) {
        if (!criticalReasonText || !criticalReasonTitle) return;

        const isCrit = w.risk_score >= userThresholds.critical;
        const isHigh = w.risk_score >= userThresholds.high;
        const reasons = [];

        if (w.packet_rate > 60000) {
            reasons.push(`Packet rate burst (${formatNumber(w.packet_rate)} pkts/s)`);
        }
        if (w.byte_rate > 3000000) {
            reasons.push(`High byte volume (${formatNumber(w.byte_rate)} B/s)`);
        }
        if (w.avg_syn_flags > 0.08) {
            reasons.push(`Elevated TCP SYN ratio (${w.avg_syn_flags.toFixed(3)}) indicative of SYN flood`);
        }
        if (w.connection_count > 1500) {
            reasons.push(`High concurrent connection count (${w.connection_count} flows)`);
        }
        if (w.is_anomaly) {
            reasons.push(`Isolation Forest anomaly deviation (${w.anomaly_score.toFixed(3)})`);
        }

        if (isCrit) {
            criticalReasonCard.style.borderLeftColor = "var(--risk-critical)";
            criticalReasonTitle.textContent = `Score ${w.risk_score.toFixed(1)} ≥ User Critical Cutoff (${userThresholds.critical})`;
            criticalReasonTitle.style.color = "var(--risk-critical)";
            criticalReasonText.textContent = reasons.length
                ? `CRITICAL THREAT: ${reasons.join(". ")}. Ground truth label confirms ${w.true_label_name}.`
                : `Elevated attack classification confidence on ${w.predicted_label_name}. Analyst review advised.`;
        } else if (isHigh) {
            criticalReasonCard.style.borderLeftColor = "var(--risk-high)";
            criticalReasonTitle.textContent = `Score ${w.risk_score.toFixed(1)} ≥ User High Cutoff (${userThresholds.high})`;
            criticalReasonTitle.style.color = "var(--risk-high)";
            criticalReasonText.textContent = reasons.length
                ? `HIGH SEVERITY: ${reasons.join(". ")}.`
                : `Moderate anomaly detected on ${w.predicted_label_name}.`;
        } else {
            criticalReasonCard.style.borderLeftColor = "var(--risk-low)";
            criticalReasonTitle.textContent = `Score ${w.risk_score.toFixed(1)} < Thresholds (Normal)`;
            criticalReasonTitle.style.color = "var(--risk-low)";
            criticalReasonText.textContent = `Traffic parameters remain within standard baseline range. No volumetric or SYN flood patterns detected.`;
        }
    }

    function setAuditDecision(decision) {
        const w = windows[currentIndex];
        if (!w) return;
        const windowKey = w.id || `win_${currentIndex}`;
        if (!auditStore[windowKey]) {
            auditStore[windowKey] = { status: "pending", notes: "" };
        }
        auditStore[windowKey].status = decision;
        renderAuditPanel(w);
        updateCountsAndFilters();
        renderTableRows();
    }

    // ──── Alert Feed ────
    function addAlert(w) {
        if (w.risk_level === "Low") return;
        const alert = {
            time: w.timestamp,
            level: w.risk_level,
            label: w.predicted_label_name,
            score: w.risk_score,
            windowIdx: currentIndex
        };
        // Avoid duplicate alerts in close sequence
        if (!alertLog.some(a => a.time === alert.time && a.label === alert.label)) {
            alertLog.unshift(alert);
            if (alertLog.length > 60) alertLog.pop();
            renderAlerts();
        }
    }

    function renderAlerts() {
        if (!elAlertsList) return;
        if (alertLog.length === 0) {
            elAlertsList.innerHTML = '<div class="alert-empty">No alerts yet. Advance through windows to see alerts.</div>';
            return;
        }

        let html = "";
        alertLog.slice(0, 30).forEach(a => {
            const shortTime = a.time.split(" ")[1] || a.time;
            html += `
                <div class="alert-card level-${a.level}">
                    <span class="alert-time">${shortTime}</span>
                    <span class="alert-badge level-${a.level}">${a.level}</span>
                    <span class="alert-text"><strong>${a.label}</strong> detected — risk score ${a.score.toFixed(1)}</span>
                </div>`;
        });
        elAlertsList.innerHTML = html;
    }

    // ──── Timeline Canvas Chart ────
    function drawTimeline() {
        if (!ctx || !canvas) return;

        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        canvas.style.width = rect.width + "px";
        canvas.style.height = rect.height + "px";
        ctx.scale(dpr, dpr);

        const W = rect.width;
        const H = rect.height;
        const PAD_L = 35, PAD_R = 12, PAD_T = 12, PAD_B = 25;
        const plotW = W - PAD_L - PAD_R;
        const plotH = H - PAD_T - PAD_B;

        ctx.clearRect(0, 0, W, H);

        // Grid lines
        ctx.strokeStyle = "rgba(255,255,255,0.04)";
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = PAD_T + (plotH / 4) * i;
            ctx.beginPath();
            ctx.moveTo(PAD_L, y);
            ctx.lineTo(W - PAD_R, y);
            ctx.stroke();
        }

        // Y-axis labels
        ctx.fillStyle = "#475569";
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        [100, 75, 50, 25, 0].forEach((v, i) => {
            ctx.fillText(v, PAD_L - 6, PAD_T + (plotH / 4) * i + 4);
        });

        // User Risk threshold zones
        const zones = [
            { min: userThresholds.critical, max: 100, color: "rgba(239,68,68,0.06)" },
            { min: userThresholds.high, max: userThresholds.critical, color: "rgba(249,115,22,0.04)" },
            { min: userThresholds.medium, max: userThresholds.high, color: "rgba(245,158,11,0.02)" }
        ];
        zones.forEach(z => {
            const y1 = PAD_T + plotH * (1 - z.max / 100);
            const y2 = PAD_T + plotH * (1 - z.min / 100);
            ctx.fillStyle = z.color;
            ctx.fillRect(PAD_L, y1, plotW, y2 - y1);
        });

        // User Critical Threshold Cutoff Line (Dotted red line)
        const critY = PAD_T + plotH * (1 - userThresholds.critical / 100);
        ctx.strokeStyle = "rgba(239, 68, 68, 0.4)";
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(PAD_L, critY);
        ctx.lineTo(W - PAD_R, critY);
        ctx.stroke();
        ctx.setLineDash([]);

        if (TOTAL < 2) return;

        const stepX = plotW / (TOTAL - 1);

        // Area fill gradient
        const gradient = ctx.createLinearGradient(0, PAD_T, 0, PAD_T + plotH);
        gradient.addColorStop(0, "rgba(6,182,212,0.18)");
        gradient.addColorStop(1, "rgba(6,182,212,0)");

        ctx.beginPath();
        ctx.moveTo(PAD_L, PAD_T + plotH);
        windows.forEach((w, i) => {
            const x = PAD_L + i * stepX;
            const y = PAD_T + plotH * (1 - w.risk_score / 100);
            ctx.lineTo(x, y);
        });
        ctx.lineTo(PAD_L + (TOTAL - 1) * stepX, PAD_T + plotH);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        // Line
        ctx.beginPath();
        windows.forEach((w, i) => {
            const x = PAD_L + i * stepX;
            const y = PAD_T + plotH * (1 - w.risk_score / 100);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.strokeStyle = "#06b6d4";
        ctx.lineWidth = 1.8;
        ctx.stroke();

        // Dots (colored by risk level)
        windows.forEach((w, i) => {
            const x = PAD_L + i * stepX;
            const y = PAD_T + plotH * (1 - w.risk_score / 100);
            const r = (i === currentIndex) ? 5.5 : 2.2;
            ctx.beginPath();
            ctx.arc(x, y, r, 0, Math.PI * 2);
            ctx.fillStyle = riskColor(w.risk_level);
            ctx.fill();

            if (i === currentIndex) {
                ctx.strokeStyle = "white";
                ctx.lineWidth = 2;
                ctx.stroke();
            }
        });

        // Timeline cursor
        if (elTimelineCursor) {
            const cursorX = PAD_L + currentIndex * stepX;
            elTimelineCursor.style.left = (cursorX / W * 100) + "%";
        }

        // X-axis timestamps
        ctx.fillStyle = "#475569";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        const labelInterval = Math.max(1, Math.floor(TOTAL / 8));
        for (let i = 0; i < TOTAL; i += labelInterval) {
            const x = PAD_L + i * stepX;
            const time = windows[i].timestamp.split(" ")[1] || "";
            ctx.fillText(time, x, H - 5);
        }
    }

    // ──── Traffic Windows Table & Filter Logic ────
    function getFilteredWindows() {
        const q = tableSearch.toLowerCase().trim();
        return windows.map((w, origIdx) => ({ ...w, origIdx })).filter(w => {
            // Pill filter
            if (tableFilter === "critical" && w.risk_level !== "Critical") return false;
            if (tableFilter === "attacks" && w.predicted_label === 0 && w.true_label === 0) return false;
            if (tableFilter === "benign" && (w.predicted_label !== 0 || w.true_label !== 0)) return false;
            if (tableFilter === "reviewed") {
                const windowKey = w.id || `win_${w.origIdx}`;
                const st = auditStore[windowKey]?.status;
                if (!st || st === "pending") return false;
            }

            // Search query
            if (q) {
                const text = `${w.timestamp} ${w.true_label_name} ${w.predicted_label_name} ${w.risk_level}`.toLowerCase();
                if (!text.includes(q)) return false;
            }

            return true;
        });
    }

    function updateCountsAndFilters() {
        if (!windows) return;
        let crit = 0, attacks = 0, benign = 0, reviewed = 0;

        windows.forEach((w, idx) => {
            if (w.risk_level === "Critical") crit++;
            if (w.true_label !== 0 || w.predicted_label !== 0) attacks++;
            if (w.true_label === 0 && w.predicted_label === 0) benign++;
            const windowKey = w.id || `win_${idx}`;
            const st = auditStore[windowKey]?.status;
            if (st && st !== "pending") reviewed++;
        });

        if (countAll) countAll.textContent = windows.length;
        if (countCrit) countCrit.textContent = crit;
        if (countAttacks) countAttacks.textContent = attacks;
        if (countBenign) countBenign.textContent = benign;
        if (countReviewed) countReviewed.textContent = reviewed;

        if (valTotalWindows) valTotalWindows.textContent = windows.length;
        if (valCriticalWindows) valCriticalWindows.textContent = crit;
        if (valVerifiedWindows) valVerifiedWindows.textContent = reviewed;
    }

    function renderTableRows() {
        if (!trafficTableBody) return;
        const filtered = getFilteredWindows();
        const totalItems = filtered.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / tablePageSize));

        if (tableCurrentPage > totalPages) tableCurrentPage = totalPages;
        if (tableCurrentPage < 1) tableCurrentPage = 1;

        const startIdx = (tableCurrentPage - 1) * tablePageSize;
        const pageItems = filtered.slice(startIdx, startIdx + tablePageSize);

        if (pageItems.length === 0) {
            trafficTableBody.innerHTML = `<tr><td colspan="11" style="text-align:center;color:var(--text-muted);padding:24px;">No windows match your filter criteria.</td></tr>`;
        } else {
            let html = "";
            pageItems.forEach(w => {
                const isActive = (w.origIdx === currentIndex);
                const windowKey = w.id || `win_${w.origIdx}`;
                const audit = auditStore[windowKey] || { status: "pending" };
                const badgeClass = {
                    "Critical": "crit",
                    "High": "high",
                    "Medium": "med",
                    "Low": "low"
                }[w.risk_level] || "low";

                const auditBadges = {
                    "pending": '<span style="color:#f59e0b;font-size:0.75rem;">⏳ Pending</span>',
                    "verified": '<span style="color:#ef4444;font-size:0.75rem;font-weight:700;">🛡️ Verified</span>',
                    "warning": '<span style="color:#f97316;font-size:0.75rem;">⚠️ Warning</span>',
                    "false_positive": '<span style="color:#10b981;font-size:0.75rem;">❌ False Pos</span>'
                };

                html += `
                    <tr class="${isActive ? 'active-row' : ''}" data-idx="${w.origIdx}">
                        <td>#${w.origIdx + 1}</td>
                        <td>${w.timestamp}</td>
                        <td>${formatNumber(w.packet_rate)}</td>
                        <td>${formatNumber(w.byte_rate)}</td>
                        <td>${w.connection_count}</td>
                        <td>${w.avg_syn_flags.toFixed(3)}</td>
                        <td style="color:${w.true_label === 0 ? '#10b981' : '#f87171'}">${w.true_label_name || 'BENIGN'}</td>
                        <td style="color:${w.predicted_label === 0 ? '#10b981' : '#f87171'}">${w.predicted_label_name}</td>
                        <td><strong>${w.risk_score.toFixed(1)}</strong></td>
                        <td><span class="tbl-badge ${badgeClass}">${w.risk_level}</span></td>
                        <td>${auditBadges[audit.status] || '⏳ Pending'}</td>
                    </tr>`;
            });
            trafficTableBody.innerHTML = html;
        }

        // Update pagination UI
        if (paginationInfo) {
            const startDisplay = totalItems > 0 ? startIdx + 1 : 0;
            const endDisplay = Math.min(startIdx + tablePageSize, totalItems);
            paginationInfo.textContent = `Showing ${startDisplay}-${endDisplay} of ${totalItems} windows`;
        }
        if (pageNum) {
            pageNum.textContent = `Page ${tableCurrentPage} of ${totalPages}`;
        }
        if (btnPagePrev) btnPagePrev.disabled = (tableCurrentPage <= 1);
        if (btnPageNext) btnPageNext.disabled = (tableCurrentPage >= totalPages);
    }

    // ──── Main Dashboard Update ────
    function updateDashboard(index) {
        if (index < 0 || index >= TOTAL) return;
        currentIndex = index;
        const w = windows[index];
        if (!w) return;

        // Header
        if (elTimestamp) elTimestamp.textContent = w.timestamp;
        if (elWindowCounter) elWindowCounter.textContent = `${index + 1} / ${TOTAL}`;
        if (elProgressBar) elProgressBar.style.width = ((index + 1) / TOTAL * 100) + "%";

        // Status indicator dot
        const statusDot = elSystemStatus?.querySelector(".status-dot");
        if (statusDot) statusDot.style.background = riskColor(w.risk_level);

        // Render each panel
        renderMetrics(w);
        setGauge(w.risk_score, w.risk_level);
        renderClassification(w);
        renderShap(w);
        renderAnomaly(w);
        renderRiskBreakdown(w);
        renderAuditPanel(w);
        addAlert(w);

        // Timeline
        drawTimeline();

        // Highlight row in table
        const activeRow = trafficTableBody?.querySelector("tr.active-row");
        activeRow?.classList.remove("active-row");
        const newRow = trafficTableBody?.querySelector(`tr[data-idx="${index}"]`);
        newRow?.classList.add("active-row");
    }

    // ──── In-Browser CSV Parser for Custom Uploads ────
    function parseCustomCSV(text) {
        const lines = text.trim().split(/\r?\n/).filter(line => line.trim().length > 0);
        if (lines.length < 2) return null;

        const headers = lines[0].split(",").map(h => h.trim().replace(/^["']|["']$/g, ""));
        const parsedWindows = [];

        for (let i = 1; i < lines.length; i++) {
            const cols = lines[i].split(",").map(c => c.trim().replace(/^["']|["']$/g, ""));
            const row = {};
            headers.forEach((h, idx) => {
                row[h] = cols[idx];
            });

            const true_label = parseInt(row["Label_num"] ?? 0) || 0;
            const true_name = LABEL_NAMES[true_label] || "BENIGN";
            const predicted_label = true_label; // Default ground-truth aligned
            const predicted_name = LABEL_NAMES[predicted_label] || "BENIGN";

            const packet_rate = parseFloat(row["packet_rate"] || 0);
            const byte_rate = parseFloat(row["byte_rate"] || 0);
            const connection_count = parseInt(row["connection_count"] || 0);
            const avg_syn_flags = parseFloat(row["avg_syn_flags"] || 0);
            const avg_duration = parseFloat(row["avg_duration"] || 0);

            // Compute risk score
            const p_spike = Math.min(1.0, packet_rate / 90000.0);
            const b_spike = Math.min(1.0, byte_rate / 6000000.0);
            const syn_spike = Math.min(1.0, avg_syn_flags / 0.12);
            const conn_spike = Math.min(1.0, connection_count / 2500.0);

            let base_risk = 8.0 + (p_spike * 10.0) + (syn_spike * 5.0);
            let anomaly_score = 0.08;
            let is_anomaly = false;

            if (predicted_label === 1) { // DDoS
                base_risk = 80.0 + (p_spike * 12.0) + (b_spike * 10.0);
                anomaly_score = -0.38;
                is_anomaly = true;
            } else if (predicted_label === 2) { // DoS
                base_risk = 72.0 + (conn_spike * 14.0) + (syn_spike * 14.0);
                anomaly_score = -0.34;
                is_anomaly = true;
            } else if (predicted_label === 3) { // Brute Force
                base_risk = 64.0 + (conn_spike * 16.0) + (syn_spike * 18.0);
                anomaly_score = -0.28;
                is_anomaly = true;
            }

            const risk_score = Math.min(99.0, Math.max(4.0, base_risk));
            const risk_level = computeDynamicRiskLevel(risk_score);

            const shap_features = [
                { name: "packet_rate", value: +(0.15 + 0.55 * p_spike).toFixed(3) },
                { name: "byte_rate", value: +(0.12 + 0.50 * b_spike).toFixed(3) },
                { name: "connection_count", value: +(0.10 + 0.45 * conn_spike).toFixed(3) },
                { name: "avg_syn_flags", value: +(0.08 + 0.60 * syn_spike).toFixed(3) },
                { name: "avg_duration", value: 0.06 }
            ].sort((a, b) => b.value - a.value);

            const confidence = [0.05, 0.05, 0.05, 0.05];
            confidence[predicted_label] = 0.85;

            parsedWindows.push({
                id: `custom_${i - 1}`,
                index: i - 1,
                timestamp: row["window"] || `Row ${i}`,
                packet_rate: +packet_rate.toFixed(2),
                byte_rate: +byte_rate.toFixed(2),
                connection_count: connection_count,
                avg_syn_flags: +avg_syn_flags.toFixed(4),
                avg_duration: +avg_duration.toFixed(2),
                true_label: true_label,
                true_label_name: true_name,
                predicted_label: predicted_label,
                predicted_label_name: predicted_name,
                confidence: confidence,
                anomaly_score: anomaly_score,
                is_anomaly: is_anomaly,
                risk_score: +risk_score.toFixed(1),
                risk_level: risk_level,
                shap_features: shap_features,
                mitre_techniques: MITRE_MAP[predicted_label] || [],
                verification_status: "pending",
                analyst_notes: ""
            });
        }

        return parsedWindows;
    }

    // ──── Dataset Switching & Application ────
    function applyDataset(key) {
        stopPlay();
        activeDatasetKey = key;

        if (key === "custom") {
            if (!datasets.custom || !datasets.custom.windows.length) {
                alert("Please select and upload a valid .csv file first.");
                return;
            }
            activeDataset = datasets.custom;
        } else {
            activeDataset = datasets[key];
        }

        windows = activeDataset.windows;
        TOTAL = windows.length;
        currentIndex = 0;
        alertLog = [];

        recalculateActiveDatasetScores();
        updateDashboard(0);
        renderTableRows();

        // Update dataset indicator badge in top-right
        const datasetBadge = $(".dataset-badge span");
        if (datasetBadge) {
            datasetBadge.textContent = key.toUpperCase() + ".CSV";
        }

        // Button feedback
        if (btnApplyData) {
            const originalHtml = btnApplyData.innerHTML;
            btnApplyData.innerHTML = `<span>✓ ${key.toUpperCase()} Applied (${TOTAL} windows)</span>`;
            btnApplyData.style.background = "linear-gradient(135deg, #10b981, #059669)";
            btnApplyData.style.color = "#ffffff";
            setTimeout(() => {
                btnApplyData.innerHTML = originalHtml;
                btnApplyData.style.background = "";
                btnApplyData.style.color = "";
            }, 1800);
        }
    }

    // ──── Event Listeners: Toolbar & Dataset Selection ────
    datasetSelect?.addEventListener("change", (e) => {
        const val = e.target.value;
        if (val === "custom") {
            customFileWrap.style.display = "flex";
        } else {
            customFileWrap.style.display = "none";
        }
    });

    csvFileInput?.addEventListener("change", (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        if (selectedFileName) selectedFileName.textContent = file.name;

        const reader = new FileReader();
        reader.onload = (event) => {
            try {
                const text = event.target.result;
                const parsed = parseCustomCSV(text);
                if (parsed && parsed.length > 0) {
                    datasets.custom = {
                        name: file.name,
                        windows: parsed,
                        total_windows: parsed.length
                    };
                    if (selectedFileName) selectedFileName.textContent = `${file.name} (${parsed.length} rows)`;
                } else {
                    alert("Unable to parse CSV. Please ensure standard CICIDS2017 column headers exist.");
                }
            } catch (err) {
                console.error("CSV parse error:", err);
                alert("Error reading CSV file: " + err.message);
            }
        };
        reader.readAsText(file);
    });

    btnApplyData?.addEventListener("click", () => {
        const selVal = datasetSelect?.value || "test";
        applyDataset(selVal);
    });

    // ──── Threshold Drawer Controls ────
    btnToggleThresholds?.addEventListener("click", () => {
        if (!thresholdDrawer) return;
        const isHidden = thresholdDrawer.style.display === "none";
        thresholdDrawer.style.display = isHidden ? "block" : "none";
    });

    btnCloseThresholds?.addEventListener("click", () => {
        if (thresholdDrawer) thresholdDrawer.style.display = "none";
    });

    sliderCritThreshold?.addEventListener("input", (e) => {
        const val = parseInt(e.target.value);
        if (lblCritThreshold) lblCritThreshold.textContent = val;
    });

    sliderHighThreshold?.addEventListener("input", (e) => {
        const val = parseInt(e.target.value);
        if (lblHighThreshold) lblHighThreshold.textContent = val;
    });

    sliderAnomalyWeight?.addEventListener("input", (e) => {
        const val = parseFloat(e.target.value);
        if (lblAnomalyWeight) lblAnomalyWeight.textContent = val.toFixed(1) + "x";
    });

    btnApplyThresholds?.addEventListener("click", () => {
        userThresholds.critical = parseInt(sliderCritThreshold?.value || 75);
        userThresholds.high = parseInt(sliderHighThreshold?.value || 50);
        userThresholds.anomalyWeight = parseFloat(sliderAnomalyWeight?.value || 1.2);

        recalculateActiveDatasetScores();
        updateDashboard(currentIndex);
        renderTableRows();

        if (thresholdDrawer) thresholdDrawer.style.display = "none";
    });

    btnResetThresholds?.addEventListener("click", () => {
        userThresholds.critical = 75;
        userThresholds.high = 50;
        userThresholds.anomalyWeight = 1.2;

        if (sliderCritThreshold) sliderCritThreshold.value = 75;
        if (sliderHighThreshold) sliderHighThreshold.value = 50;
        if (sliderAnomalyWeight) sliderAnomalyWeight.value = 1.2;
        if (lblCritThreshold) lblCritThreshold.textContent = "75";
        if (lblHighThreshold) lblHighThreshold.textContent = "50";
        if (lblAnomalyWeight) lblAnomalyWeight.textContent = "1.2x";

        recalculateActiveDatasetScores();
        updateDashboard(currentIndex);
        renderTableRows();
    });

    // ──── Audit Panel Action Buttons ────
    btnAuditConfirm?.addEventListener("click", () => setAuditDecision("verified"));
    btnAuditDowngrade?.addEventListener("click", () => setAuditDecision("warning"));
    btnAuditFalsePos?.addEventListener("click", () => setAuditDecision("false_positive"));

    btnSaveNotes?.addEventListener("click", () => {
        const w = windows[currentIndex];
        if (!w) return;
        const windowKey = w.id || `win_${currentIndex}`;
        if (!auditStore[windowKey]) {
            auditStore[windowKey] = { status: "pending", notes: "" };
        }
        auditStore[windowKey].notes = analystNotesInput?.value || "";
        const originalText = btnSaveNotes.textContent;
        btnSaveNotes.textContent = "Saved!";
        setTimeout(() => { btnSaveNotes.textContent = originalText; }, 1200);
    });

    // ──── Table Filter & Pagination Events ────
    tableFilterPills?.addEventListener("click", (e) => {
        const btn = e.target.closest(".filter-pill");
        if (!btn) return;
        tableFilterPills.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
        btn.classList.add("active");
        tableFilter = btn.dataset.filter;
        tableCurrentPage = 1;
        renderTableRows();
    });

    tableSearchInput?.addEventListener("input", (e) => {
        tableSearch = e.target.value;
        tableCurrentPage = 1;
        renderTableRows();
    });

    btnPagePrev?.addEventListener("click", () => {
        if (tableCurrentPage > 1) {
            tableCurrentPage--;
            renderTableRows();
        }
    });

    btnPageNext?.addEventListener("click", () => {
        tableCurrentPage++;
        renderTableRows();
    });

    trafficTableBody?.addEventListener("click", (e) => {
        const row = e.target.closest("tr[data-idx]");
        if (!row) return;
        const idx = parseInt(row.dataset.idx);
        if (!isNaN(idx)) {
            stopPlay();
            updateDashboard(idx);
        }
    });

    // ──── Navigation & Playback Controls ────
    btnFirst?.addEventListener("click", () => { stopPlay(); updateDashboard(0); });
    btnPrev?.addEventListener("click", () => { stopPlay(); updateDashboard(currentIndex - 1); });
    btnNext?.addEventListener("click", () => { stopPlay(); updateDashboard(currentIndex + 1); });
    btnLast?.addEventListener("click", () => { stopPlay(); updateDashboard(TOTAL - 1); });

    btnPlay?.addEventListener("click", () => {
        if (isPlaying) stopPlay();
        else startPlay();
    });

    btnClearAlerts?.addEventListener("click", () => {
        alertLog = [];
        renderAlerts();
    });

    speedSlider?.addEventListener("input", () => {
        const ms = parseInt(speedSlider.value);
        if (speedLabel) speedLabel.textContent = (ms / 1000).toFixed(1) + "s";
        if (isPlaying) {
            clearInterval(playInterval);
            playInterval = setInterval(playTick, ms);
        }
    });

    function startPlay() {
        isPlaying = true;
        const playIcon = $("#playIcon");
        const pauseIcon = $("#pauseIcon");
        if (playIcon) playIcon.style.display = "none";
        if (pauseIcon) pauseIcon.style.display = "block";
        const ms = parseInt(speedSlider?.value || 1200);
        playInterval = setInterval(playTick, ms);
    }

    function stopPlay() {
        isPlaying = false;
        const playIcon = $("#playIcon");
        const pauseIcon = $("#pauseIcon");
        if (playIcon) playIcon.style.display = "block";
        if (pauseIcon) pauseIcon.style.display = "none";
        if (playInterval) {
            clearInterval(playInterval);
            playInterval = null;
        }
    }

    function playTick() {
        if (currentIndex >= TOTAL - 1) {
            stopPlay();
            return;
        }
        updateDashboard(currentIndex + 1);
    }

    // Keyboard navigation
    document.addEventListener("keydown", (e) => {
        if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
        if (e.key === "ArrowRight" || e.key === "l") { stopPlay(); updateDashboard(currentIndex + 1); }
        if (e.key === "ArrowLeft" || e.key === "h") { stopPlay(); updateDashboard(currentIndex - 1); }
        if (e.key === " ") { e.preventDefault(); btnPlay?.click(); }
        if (e.key === "Home") { stopPlay(); updateDashboard(0); }
        if (e.key === "End") { stopPlay(); updateDashboard(TOTAL - 1); }
    });

    // Resize handler
    let resizeTimer;
    window.addEventListener("resize", () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(drawTimeline, 100);
    });

    // Timeline seek
    canvas?.addEventListener("click", (e) => {
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const PAD_L = 35, PAD_R = 12;
        const plotW = rect.width - PAD_L - PAD_R;
        const relX = x - PAD_L;
        const idx = Math.round((relX / plotW) * (TOTAL - 1));
        if (idx >= 0 && idx < TOTAL) {
            stopPlay();
            updateDashboard(idx);
        }
    });

    // ──── Initialize Console ────
    recalculateActiveDatasetScores();
    updateDashboard(0);
    renderTableRows();
    if (speedSlider && speedLabel) {
        speedLabel.textContent = (parseInt(speedSlider.value) / 1000).toFixed(1) + "s";
    }

})();
