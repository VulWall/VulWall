// Recommendations index — CSP-compliant (no inline script).
// Handles severity filtering, sort (priority / quickest win), and the archive collapse.

document.addEventListener('DOMContentLoaded', () => {
    const stream = document.getElementById('findingsStream');
    const filterEl = document.getElementById('filterChips');
    const sortEl = document.getElementById('sortControl');
    const archToggle = document.getElementById('archiveToggle');
    const archBody = document.getElementById('archiveBody');
    const archPanel = archToggle?.closest('.archive-panel');

    let activeFilter = 'all';
    let sortMode = 'priority';

    const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const EFFORT_ORDER = { trivial: 0, small: 1, medium: 2, large: 3, unknown: 4 };
    const SEVERITY_GROUPS = ['critical', 'high', 'medium', 'low', 'info'];

    // ── Filter ──────────────────────────────────────────────────
    filterEl?.addEventListener('click', e => {
        const btn = e.target.closest('.filter-chip');
        if (!btn) return;
        activeFilter = btn.dataset.filter;
        filterEl.querySelectorAll('.filter-chip').forEach(c => {
            const active = c === btn;
            c.classList.toggle('is-active', active);
            c.setAttribute('aria-pressed', String(active));
        });
        applyState();
    });

    // ── Sort ────────────────────────────────────────────────────
    sortEl?.addEventListener('click', e => {
        const btn = e.target.closest('.sort-btn');
        if (!btn) return;
        sortMode = btn.dataset.sort;
        sortEl.querySelectorAll('.sort-btn').forEach(b => {
            const active = b === btn;
            b.classList.toggle('is-active', active);
            b.setAttribute('aria-pressed', String(active));
        });
        applyState();
    });

    // ── Archive collapse ────────────────────────────────────────
    archToggle?.addEventListener('click', () => {
        const open = archBody.style.display === 'none' || archBody.style.display === '';
        archBody.style.display = open ? 'block' : 'none';
        archToggle.setAttribute('aria-expanded', String(open));
        archPanel?.classList.toggle('is-open', open);
    });

    // ── Apply filter + sort ─────────────────────────────────────
    function applyState() {
        if (!stream) return;
        const cards = [...stream.querySelectorAll('.finding-card')];
        const headers = [...stream.querySelectorAll('.severity-section-header')];

        // Filter visibility
        cards.forEach(c => {
            const sev = c.dataset.severity;
            c.classList.toggle('is-hidden', activeFilter !== 'all' && sev !== activeFilter);
        });

        // Section headers only make sense when grouped by priority across all severities
        const showHeaders = sortMode === 'priority' && activeFilter === 'all';
        headers.forEach(h => h.classList.toggle('is-hidden', !showHeaders));

        const sorted = cards.slice().sort((a, b) => {
            if (sortMode === 'effort') {
                const ea = EFFORT_ORDER[a.dataset.effort] ?? 4;
                const eb = EFFORT_ORDER[b.dataset.effort] ?? 4;
                if (ea !== eb) return ea - eb;
            }
            // Tie-break (and default) by severity
            return (SEVERITY_ORDER[a.dataset.severity] ?? 9) - (SEVERITY_ORDER[b.dataset.severity] ?? 9);
        });

        if (sortMode === 'effort') {
            // Flat order: append every card in effort-then-severity order
            sorted.forEach(c => stream.appendChild(c));
        } else {
            // Priority: restore severity grouping, each section header followed by its cards
            SEVERITY_GROUPS.forEach(sev => {
                const header = stream.querySelector(`[data-sev-header="${sev}"]`);
                if (header) stream.appendChild(header);
                sorted.filter(c => c.dataset.severity === sev).forEach(c => stream.appendChild(c));
            });
        }
    }
});
