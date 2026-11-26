/**
 * Cybersecurity Risk Scoring and Decision Support Framework
 * Frontend interactive logic, live calculation preview, and Chart.js visualizations.
 */

document.addEventListener("DOMContentLoaded", () => {
    initRiskCalculatorPreview();
    initCharts();
    initAlertAutoDismiss();
    initSearchFilterHelpers();
});

// --------------------------------------------------------------------------
// 1. LIVE RISK CALCULATOR PREVIEW
// --------------------------------------------------------------------------
function initRiskCalculatorPreview() {
    const vInput = document.getElementById("input-vuln-severity");
    const aInput = document.getElementById("input-asset-criticality");
    const eInput = document.getElementById("input-exposure");
    const sInput = document.getElementById("input-event-severity");

    const vRange = document.getElementById("range-vuln-severity");
    const aRange = document.getElementById("range-asset-criticality");
    const eRange = document.getElementById("range-exposure");
    const sRange = document.getElementById("range-event-severity");

    const scoreMeter = document.getElementById("preview-score-meter");
    const scoreVal = document.getElementById("preview-score-val");
    const scoreTier = document.getElementById("preview-score-tier");
    const formulaMath = document.getElementById("preview-formula-math");

    if (!vInput || !aInput || !eInput || !sInput) return;

    // Sync input <-> range
    function sync(input, range) {
        if (!input || !range) return;
        input.addEventListener("input", () => {
            range.value = input.value;
            calculateLivePreview();
        });
        range.addEventListener("input", () => {
            input.value = range.value;
            calculateLivePreview();
        });
    }

    sync(vInput, vRange);
    sync(aInput, aRange);
    sync(eInput, eRange);
    sync(sInput, sRange);

    function calculateLivePreview() {
        const v = Math.min(100, Math.max(0, parseFloat(vInput.value) || 0));
        const a = Math.min(100, Math.max(0, parseFloat(aInput.value) || 0));
        const e = Math.min(100, Math.max(0, parseFloat(eInput.value) || 0));
        const s = Math.min(100, Math.max(0, parseFloat(sInput.value) || 0));

        // R = 0.40V + 0.25A + 0.20E + 0.15S
        const vW = 0.40 * v;
        const aW = 0.25 * a;
        const eW = 0.20 * e;
        const sW = 0.15 * s;
        const rawScore = vW + aW + eW + sW;
        const score = Math.min(100, Math.max(0, rawScore)).toFixed(1);

        // Classification: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical
        let tier = "Low";
        let tierClass = "low";
        let tierTextClass = "text-success";

        if (score >= 75) {
            tier = "Critical Risk";
            tierClass = "critical";
            tierTextClass = "text-danger";
        } else if (score >= 50) {
            tier = "High Risk";
            tierClass = "high";
            tierTextClass = "text-orange";
        } else if (score >= 25) {
            tier = "Medium Risk";
            tierClass = "medium";
            tierTextClass = "text-warning";
        } else {
            tier = "Low Risk";
            tierClass = "low";
            tierTextClass = "text-success";
        }

        if (scoreVal) scoreVal.textContent = score;
        if (scoreTier) {
            scoreTier.textContent = tier;
            scoreTier.className = `score-label ${tierTextClass}`;
        }
        if (scoreMeter) {
            scoreMeter.className = `score-meter-circle ${tierClass}`;
        }
        if (formulaMath) {
            formulaMath.textContent = `R = 0.40(${v}) + 0.25(${a}) + 0.20(${e}) + 0.15(${s}) = ${score}`;
        }
    }

    // Initial run
    calculateLivePreview();
}

// --------------------------------------------------------------------------
// 2. CHART.JS VISUALIZATIONS
// --------------------------------------------------------------------------
function initCharts() {
    // 2A. Risk Distribution Chart (Doughnut)
    const distCanvas = document.getElementById("riskDistributionChart");
    if (distCanvas && window.Chart) {
        const low = parseInt(distCanvas.dataset.low || "0");
        const med = parseInt(distCanvas.dataset.med || "0");
        const high = parseInt(distCanvas.dataset.high || "0");
        const crit = parseInt(distCanvas.dataset.crit || "0");

        new Chart(distCanvas, {
            type: "doughnut",
            data: {
                labels: ["Low Risk (0-24)", "Medium Risk (25-49)", "High Risk (50-74)", "Critical Risk (75-100)"],
                datasets: [{
                    data: [low, med, high, crit],
                    backgroundColor: ["#10b981", "#f59e0b", "#f97316", "#ef4444"],
                    borderColor: "#1c2541",
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: "#94a3b8",
                            font: { size: 11, family: "'Segoe UI', sans-serif" },
                            padding: 12
                        }
                    },
                    tooltip: {
                        backgroundColor: "#0b132b",
                        titleColor: "#00f5d4",
                        bodyColor: "#ffffff",
                        borderColor: "#2a3a5f",
                        borderWidth: 1
                    }
                },
                cutout: "68%"
            }
        });
    }

    // 2B. Vulnerability Status Chart (Bar / Polar)
    const vulnCanvas = document.getElementById("vulnStatusChart");
    if (vulnCanvas && window.Chart) {
        const openCnt = parseInt(vulnCanvas.dataset.open || "0");
        const pendingCnt = parseInt(vulnCanvas.dataset.pending || "0");
        const resolvedCnt = parseInt(vulnCanvas.dataset.resolved || "0");

        new Chart(vulnCanvas, {
            type: "bar",
            data: {
                labels: ["Open", "Pending", "Resolved"],
                datasets: [{
                    label: "Vulnerabilities",
                    data: [openCnt, pendingCnt, resolvedCnt],
                    backgroundColor: ["#ef4444", "#f59e0b", "#10b981"],
                    borderColor: ["#f87171", "#fbbf24", "#34d399"],
                    borderWidth: 1,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#0b132b",
                        borderColor: "#2a3a5f",
                        borderWidth: 1
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#94a3b8", stepSize: 1 },
                        grid: { color: "#1e293b" }
                    },
                    x: {
                        ticks: { color: "#94a3b8" },
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // 2C. Historical Risk Trend Chart (Line Chart)
    const trendCanvas = document.getElementById("historicalTrendChart");
    if (trendCanvas && window.Chart) {
        fetch("/api/chart-data")
            .then(res => res.json())
            .then(data => {
                const trends = data.trends;
                if (!trends || !trends.labels || trends.labels.length === 0) return;

                new Chart(trendCanvas, {
                    type: "line",
                    data: {
                        labels: trends.labels,
                        datasets: [{
                            label: "Risk Score (0-100)",
                            data: trends.scores,
                            borderColor: "#38bdf8",
                            backgroundColor: "rgba(56, 189, 248, 0.1)",
                            pointBackgroundColor: trends.colors,
                            pointBorderColor: "#ffffff",
                            pointRadius: 6,
                            pointHoverRadius: 8,
                            tension: 0.3,
                            fill: true,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                labels: { color: "#94a3b8", font: { size: 11 } }
                            },
                            tooltip: {
                                backgroundColor: "#0b132b",
                                borderColor: "#2a3a5f",
                                borderWidth: 1,
                                callbacks: {
                                    label: function(context) {
                                        const score = context.parsed.y;
                                        let tier = "Low";
                                        if (score >= 75) tier = "CRITICAL";
                                        else if (score >= 50) tier = "HIGH";
                                        else if (score >= 25) tier = "MEDIUM";
                                        return `Risk Score: ${score} [${tier}]`;
                                    }
                                }
                            }
                        },
                        scales: {
                            y: {
                                min: 0,
                                max: 100,
                                ticks: { color: "#94a3b8" },
                                grid: { color: "#1e293b" }
                            },
                            x: {
                                ticks: {
                                    color: "#94a3b8",
                                    maxRotation: 45,
                                    minRotation: 20,
                                    font: { size: 10 }
                                },
                                grid: { display: false }
                            }
                        }
                    }
                });
            })
            .catch(err => console.error("Could not load chart data:", err));
    }
}

// --------------------------------------------------------------------------
// 3. AUTO DISMISS ALERTS
// --------------------------------------------------------------------------
function initAlertAutoDismiss() {
    const alerts = document.querySelectorAll(".alert.alert-dismissible");
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 6000);
    });
}

// --------------------------------------------------------------------------
// 4. CLIENT TABLE QUICK SEARCH FILTER
// --------------------------------------------------------------------------
function initSearchFilterHelpers() {
    const quickInputs = document.querySelectorAll("[data-table-filter]");
    quickInputs.forEach(input => {
        const tableId = input.dataset.tableFilter;
        const table = document.getElementById(tableId);
        if (!table) return;

        input.addEventListener("input", () => {
            const query = input.value.toLowerCase().trim();
            const rows = table.querySelectorAll("tbody tr");

            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(query)) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            });
        });
    });
}
