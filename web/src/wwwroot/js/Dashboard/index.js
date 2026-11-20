// Overview page — score sparkline + open-issues trend chart with range toggle.
// Server data arrives via the CSP-safe #chart-data JSON block (no inline script).

const SEVERITIES = [
    { key: 'low', label: 'Low', token: '--severity-low-solid' },
    { key: 'medium', label: 'Medium', token: '--severity-medium-solid' },
    { key: 'high', label: 'High', token: '--severity-high-solid' },
    { key: 'critical', label: 'Critical', token: '--severity-critical-solid' }
];

function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
}

document.addEventListener('DOMContentLoaded', () => {
    const el = document.getElementById('chart-data');
    if (!el) return;

    let chartData;
    try {
        chartData = JSON.parse(el.textContent);
    } catch {
        return;
    }
    if (!chartData || !chartData.ranges) return;

    const defaultRange = chartData.defaultRange ?? '90d';

    initSparkline(chartData, defaultRange);

    const chart = initTimelineChart(chartData, defaultRange);
    if (chart) initPeriodToggle(chart, chartData);
});

// ── Score sparkline (navy panel) ────────────────────────────────
function initSparkline(chartData, range) {
    const canvas = document.getElementById('scoreSparkline');
    if (!canvas) return;

    const series = chartData.ranges[range]?.securityScore ?? [];
    if (series.length < 2) return;

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = rect.width || canvas.clientWidth || 200;
    const h = rect.height || 46;
    canvas.width = w * dpr;
    canvas.height = h * dpr;

    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const padY = 6;
    const min = Math.min(...series);
    const max = Math.max(...series);
    const span = (max - min) || 1;
    const plotH = h - padY * 2;

    const x = (i) => (series.length === 1 ? 0 : (w * i) / (series.length - 1));
    const y = (v) => padY + plotH * (1 - (v - min) / span);

    const stroke = '#6EE7A8';

    // Gradient fill under the line
    ctx.beginPath();
    ctx.moveTo(x(0), y(series[0]));
    series.forEach((v, i) => ctx.lineTo(x(i), y(v)));
    ctx.lineTo(x(series.length - 1), h);
    ctx.lineTo(x(0), h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(110, 231, 168, 0.35)');
    grad.addColorStop(1, 'rgba(110, 231, 168, 0)');
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    ctx.moveTo(x(0), y(series[0]));
    series.forEach((v, i) => ctx.lineTo(x(i), y(v)));
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 2.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();

    // End dot
    ctx.beginPath();
    ctx.arc(x(series.length - 1), y(series[series.length - 1]), 3, 0, Math.PI * 2);
    ctx.fillStyle = '#fff';
    ctx.fill();
}

// ── Open-issues stacked area chart ──────────────────────────────
function initTimelineChart(chartData, range) {
    const canvas = document.getElementById('securityTimelineChart');
    if (!canvas || typeof Chart === 'undefined') return null;

    const range0 = chartData.ranges[range];
    if (!range0) return null;

    // SEVERITIES is ordered low → critical so the stack builds bottom-up.
    // fill 'origin' anchors the first band to the axis; '-1' fills each later
    // band down to the previous series line, giving true stacked bands.
    const datasets = SEVERITIES.map((sev, i) => {
        const color = cssVar(sev.token, '#888');
        return {
            label: sev.label,
            data: range0[sev.key] ?? [],
            borderColor: color,
            backgroundColor: hexToRgba(color, 0.82),
            borderWidth: 1,
            fill: i === 0 ? 'origin' : '-1',
            tension: 0.3,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: color,
            maxBarThickness: 48
        };
    });
    shapeForScanCount(datasets, (range0.labels ?? []).length);

    const gridColor = cssVar('--vw-gray-200', 'rgba(0,0,0,0.06)');
    const tickColor = cssVar('--vw-gray-500', '#94a3b8');

    return new Chart(canvas, {
        type: 'line',
        data: { labels: range0.labels ?? [], datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(16, 24, 40, 0.92)',
                    padding: 12,
                    boxWidth: 8,
                    boxHeight: 8,
                    boxPadding: 6,
                    usePointStyle: true,
                    itemSort: (a, b) => b.datasetIndex - a.datasetIndex,
                    callbacks: {
                        label: (ctx) => `${ctx.dataset.label}: ${ctx.parsed.y}`,
                        labelColor: (ctx) => ({
                            borderColor: ctx.dataset.borderColor,
                            backgroundColor: ctx.dataset.borderColor,
                            borderRadius: 3
                        }),
                        footer: (items) => {
                            const total = items.reduce((sum, it) => sum + (it.parsed.y || 0), 0);
                            return `Total open: ${total}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    stacked: true,
                    grid: { display: false },
                    ticks: { color: tickColor, font: { size: 11 }, maxRotation: 0, autoSkipPadding: 16 }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    grid: { color: gridColor },
                    ticks: {
                        color: tickColor,
                        font: { size: 11 },
                        precision: 0
                    }
                }
            }
        }
    });
}

// ── 30d / 90d / 6m toggle ───────────────────────────────────────
function initPeriodToggle(chart, chartData) {
    const buttons = document.querySelectorAll('.chart-period-btn[data-period]');
    if (!buttons.length) return;

    buttons.forEach((btn) => {
        btn.addEventListener('click', () => {
            const range = btn.dataset.period;
            if (!chartData.ranges[range]) return;

            buttons.forEach((b) => b.removeAttribute('data-active'));
            btn.setAttribute('data-active', '');

            updateChart(chart, chartData.ranges[range]);
            // Keep the score sparkline in sync — its label reads "Trend, this period".
            // initSparkline resets the canvas dimensions each call, so re-drawing is safe.
            initSparkline(chartData, range);
        });
    });
}

function updateChart(chart, range) {
    chart.data.labels = range.labels ?? [];
    SEVERITIES.forEach((sev, i) => {
        chart.data.datasets[i].data = range[sev.key] ?? [];
    });
    shapeForScanCount(chart.data.datasets, chart.data.labels.length);
    chart.update();
}

// A stacked area needs two scans: with one, its bands have no width and the chart looks
// empty. A single scan is drawn as one stacked bar instead.
function shapeForScanCount(datasets, scanCount) {
    datasets.forEach((ds) => {
        ds.type = scanCount === 1 ? 'bar' : 'line';
        ds.backgroundColor = scanCount === 1 ? ds.borderColor : hexToRgba(ds.borderColor, 0.82);
    });
}

// Expand a #RRGGBB color to rgba() with the given alpha. Non-hex inputs pass through.
function hexToRgba(hex, alpha) {
    const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    if (!m) return hex;
    const r = parseInt(m[1], 16);
    const g = parseInt(m[2], 16);
    const b = parseInt(m[3], 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}
