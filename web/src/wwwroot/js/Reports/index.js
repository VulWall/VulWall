// Reports Page - Main Entry Point
// Initializes all modules for the Reports page

import { initializeTypeCards, initializeTypeActions } from './template-cards.js';

// Score ring radius (must match the SVG markup in Index.cshtml: r="26").
const RING_RADIUS = 26;

function parseScanData() {
    try {
        return JSON.parse(document.getElementById('reports-scan-data')?.textContent || '[]');
    } catch {
        return [];
    }
}

function updateContextStrip(scan) {
    if (!scan) return;

    const circumference = 2 * Math.PI * RING_RADIUS;
    const fill = document.getElementById('rptScoreRingFill');
    if (fill) {
        const offset = circumference - (scan.score / 100) * circumference;
        fill.style.strokeDasharray = `${circumference}`;
        fill.style.strokeDashoffset = `${offset}`;
        // Color by score band — mirrors the server-rendered initial color (>=70 green, >=50 amber).
        const color = scan.score >= 70 ? 'var(--vw-success)'
            : scan.score >= 50 ? 'var(--severity-medium)'
            : 'var(--severity-high)';
        fill.style.stroke = color;
    }

    // Keep the SVG's accessible label in sync with the selected scan.
    const svg = document.querySelector('.rpt-score-ring-svg');
    if (svg) svg.setAttribute('aria-label', `Security score ${scan.score} out of 100`);

    const scoreVal = document.getElementById('rptScoreValue');
    if (scoreVal) scoreVal.textContent = scan.score;

    const band = document.getElementById('rptScoreBand');
    if (band) band.textContent = scan.band;

    const sevMap = {
        rptSevCritical: scan.critical,
        rptSevHigh: scan.high,
        rptSevMedium: scan.medium,
        rptSevLow: scan.low,
        rptSevInfo: scan.info
    };
    for (const [id, val] of Object.entries(sevMap)) {
        const el = document.getElementById(id);
        if (el) el.textContent = val ?? 0;
    }
}

function initializeScopeDropdown(scans) {
    const btn = document.getElementById('rptScopeBtn');
    const menu = document.getElementById('rptScopeMenu');
    const hiddenId = document.getElementById('rptSelectedScanId');
    if (!btn || !menu) return;

    // Toggle menu open/close
    btn.addEventListener('click', e => {
        e.stopPropagation();
        menu.hidden = !menu.hidden;
        btn.setAttribute('aria-expanded', String(!menu.hidden));
    });

    // Close on outside click
    document.addEventListener('click', () => {
        if (!menu.hidden) {
            menu.hidden = true;
            btn.setAttribute('aria-expanded', 'false');
        }
    });

    // Option click handler — update strip + cards
    menu.addEventListener('click', e => {
        const opt = e.target.closest('[data-scan-id]');
        if (!opt) return;
        menu.hidden = true;
        btn.setAttribute('aria-expanded', 'false');

        const scanId = opt.dataset.scanId;
        const scan = scans.find(s => s.id === scanId);
        if (!scan) return;

        if (hiddenId) hiddenId.value = scanId;

        // Update scope button label
        const label = document.getElementById('rptScopeBtnLabel');
        if (label) {
            label.innerHTML =
                `<span class="rpt-scope-name">${opt.dataset.scanLabel}</span>` +
                `<span class="rpt-scope-meta">${opt.dataset.findings} findings · ${opt.dataset.assets} assets</span>`;
        }

        // Update context strip
        updateContextStrip(scan);

        // Update selected state in menu
        menu.querySelectorAll('[data-scan-id]').forEach(o => o.classList.remove('rpt-scope-opt--selected'));
        opt.classList.add('rpt-scope-opt--selected');
    });
}

// Lightweight visual selection for the report-type cards. The action buttons inside the
// cards stop propagation, so picking a card only changes the highlighted ring.
function initializeTypeCardSelection() {
    const cards = document.querySelectorAll('.rpt-type-card');
    cards.forEach(card => {
        card.addEventListener('click', () => {
            cards.forEach(c => c.classList.remove('active'));
            card.classList.add('active');
        });
    });
}

document.addEventListener('DOMContentLoaded', function () {
    const scans = parseScanData();

    // Initialize type cards
    initializeTypeCards();
    initializeTypeActions();
    initializeTypeCardSelection();

    // Initialize scan scope dropdown + context strip
    initializeScopeDropdown(scans);

    const selectedId = document.getElementById('rptSelectedScanId')?.value;
    const initialScan = scans.find(s => s.id === selectedId) || scans[0];
    updateContextStrip(initialScan);
});
